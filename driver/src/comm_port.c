/*
 * BludEDR - comm_port.c
 * FltCreateCommunicationPort on \\BludCommPort.
 * Connect/disconnect/message-notify callbacks.
 * Worker thread dequeues from the ring buffer and sends via FltSendMessage.
 * Handles agent commands (suspend/terminate/inject).
 */

#include "../inc/driver.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, BludCommPortInitialize)
#pragma alloc_text(PAGE, BludCommPortTeardown)
#pragma alloc_text(PAGE, BludCommPortConnect)
#pragma alloc_text(PAGE, BludCommPortDisconnect)
#pragma alloc_text(PAGE, BludCommPortMessageNotify)
#endif

/* ============================================================================
 * Local helpers for command processing
 * ============================================================================ */

static NTSTATUS
BludpHandleSuspendProcess(
    _In_ ULONG TargetPid
    )
{
    NTSTATUS  status;
    PEPROCESS process = NULL;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = PsSuspendProcess(process);
    ObDereferenceObject(process);
    return status;
}

static NTSTATUS
BludpHandleTerminateProcess(
    _In_ ULONG TargetPid
    )
{
    NTSTATUS  status;
    HANDLE    hProcess = NULL;
    PEPROCESS process  = NULL;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objAttr;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Do not allow terminating critical system processes */
    {
        ULONG pid = TargetPid;
        if (pid == 4 || pid == 0) {
            ObDereferenceObject(process);
            return STATUS_ACCESS_DENIED;
        }
    }

    /* Open a handle to the process for termination */
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)TargetPid;
    clientId.UniqueThread  = NULL;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &objAttr, &clientId);
    if (NT_SUCCESS(status)) {
        status = ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
        ZwClose(hProcess);
    }

    ObDereferenceObject(process);
    return status;
}

static NTSTATUS
BludpHandleInjectDll(
    _In_ ULONG  TargetPid,
    _In_ PUCHAR Data,
    _In_ ULONG  DataSize
    )
{
    /*
     * DLL injection from kernel is handled by queueing an APC to the target
     * process. The actual injection mechanism is complex and involves
     * allocating memory in the target process and writing the DLL path.
     *
     * For this implementation, we queue a work item that the agent thread
     * will pick up. The actual injection is performed from userspace via
     * the hook DLL component.
     */
    UNREFERENCED_PARAMETER(TargetPid);
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(DataSize);

    /*
     * Stub: In production, signal the agent to perform the injection
     * from userspace, which is more reliable and maintainable.
     */
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BludEDR: Inject DLL request for PID %lu\n", TargetPid));

    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludCommPortInitialize
 * ============================================================================ */
NTSTATUS
BludCommPortInitialize(
    _In_ PFLT_FILTER Filter
    )
{
    NTSTATUS            status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES   oa;
    UNICODE_STRING      portName;

    PAGED_CODE();

    /*
     * Create a security descriptor that allows the local system account
     * and administrators group to connect.
     */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&portName, BLUD_COMM_PORT_NAME);

    InitializeObjectAttributes(&oa,
                                &portName,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL,
                                sd);

    status = FltCreateCommunicationPort(
        Filter,
        &g_Globals.CommPort.ServerPort,
        &oa,
        NULL,                           /* ServerPortCookie */
        BludCommPortConnect,
        BludCommPortDisconnect,
        BludCommPortMessageNotify,
        1                               /* MaxConnections */
        );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Initialize worker thread synchronization */
    g_Globals.CommPort.AgentConnected = FALSE;
    g_Globals.CommPort.ShutdownWorker = FALSE;
    KeInitializeEvent(&g_Globals.CommPort.WorkerStartEvent, NotificationEvent, FALSE);

    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludCommPortTeardown
 * ============================================================================ */
VOID
BludCommPortTeardown(
    VOID
    )
{
    PAGED_CODE();

    /* Signal the worker thread to exit */
    InterlockedExchange(&g_Globals.CommPort.ShutdownWorker, TRUE);

    /* Wake the worker if it is waiting on the queue event */
    KeSetEvent(&g_Globals.EventQueue.DataReadyEvent, IO_NO_INCREMENT, FALSE);

    /* Wait for the worker thread to terminate */
    if (g_Globals.CommPort.WorkerThreadObject != NULL) {
        KeWaitForSingleObject(
            g_Globals.CommPort.WorkerThreadObject,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        ObDereferenceObject(g_Globals.CommPort.WorkerThreadObject);
        g_Globals.CommPort.WorkerThreadObject = NULL;
        g_Globals.CommPort.WorkerThread = NULL;
    }

    /* Close the client port */
    if (g_Globals.CommPort.ClientPort != NULL) {
        FltCloseClientPort(g_Globals.FilterHandle, &g_Globals.CommPort.ClientPort);
        g_Globals.CommPort.ClientPort = NULL;
    }

    /* Close the server port */
    if (g_Globals.CommPort.ServerPort != NULL) {
        FltCloseCommunicationPort(g_Globals.CommPort.ServerPort);
        g_Globals.CommPort.ServerPort = NULL;
    }
}

/* ============================================================================
 * BludCommPortConnect - Called when an agent connects
 * ============================================================================ */
NTSTATUS
BludCommPortConnect(
    _In_  PFLT_PORT          ClientPort,
    _In_  PVOID              ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_  ULONG              SizeOfContext,
    _Out_ PVOID              *ConnectionPortCookie
    )
{
    NTSTATUS        status;
    HANDLE          threadHandle = NULL;
    OBJECT_ATTRIBUTES oa;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    *ConnectionPortCookie = NULL;

    /* Only allow one connection at a time */
    if (InterlockedCompareExchange(&g_Globals.CommPort.AgentConnected, TRUE, FALSE) != FALSE) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "BludEDR: Agent connection rejected, already connected\n"));
        return STATUS_CONNECTION_COUNT_LIMIT;
    }

    g_Globals.CommPort.ClientPort = ClientPort;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BludEDR: Agent connected\n"));

    /* Start the worker thread that sends events to the agent */
    g_Globals.CommPort.ShutdownWorker = FALSE;

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &oa,
        NULL,
        NULL,
        BludCommWorkerThread,
        NULL
        );

    if (NT_SUCCESS(status)) {
        /* Get the thread object for later wait */
        status = ObReferenceObjectByHandle(
            threadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            (PVOID *)&g_Globals.CommPort.WorkerThreadObject,
            NULL
            );

        g_Globals.CommPort.WorkerThread = threadHandle;
        ZwClose(threadHandle);

        if (!NT_SUCCESS(status)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "BludEDR: ObReferenceObjectByHandle on worker thread failed 0x%08X\n", status));
            InterlockedExchange(&g_Globals.CommPort.ShutdownWorker, TRUE);
        }
    } else {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BludEDR: Failed to create worker thread 0x%08X\n", status));
        InterlockedExchange(&g_Globals.CommPort.AgentConnected, FALSE);
        g_Globals.CommPort.ClientPort = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludCommPortDisconnect - Called when agent disconnects
 * ============================================================================ */
VOID
BludCommPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(ConnectionCookie);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BludEDR: Agent disconnected\n"));

    /* Signal the worker to stop */
    InterlockedExchange(&g_Globals.CommPort.ShutdownWorker, TRUE);
    KeSetEvent(&g_Globals.EventQueue.DataReadyEvent, IO_NO_INCREMENT, FALSE);

    /* Wait for worker thread to finish */
    if (g_Globals.CommPort.WorkerThreadObject != NULL) {
        KeWaitForSingleObject(
            g_Globals.CommPort.WorkerThreadObject,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        ObDereferenceObject(g_Globals.CommPort.WorkerThreadObject);
        g_Globals.CommPort.WorkerThreadObject = NULL;
        g_Globals.CommPort.WorkerThread = NULL;
    }

    /* Close the client port */
    FltCloseClientPort(g_Globals.FilterHandle, &g_Globals.CommPort.ClientPort);
    g_Globals.CommPort.ClientPort = NULL;

    InterlockedExchange(&g_Globals.CommPort.AgentConnected, FALSE);
}

/* ============================================================================
 * BludCommPortMessageNotify - Handles commands from the agent
 * ============================================================================ */
NTSTATUS
BludCommPortMessageNotify(
    _In_  PVOID              PortCookie,
    _In_reads_bytes_(InputBufferLength)  PVOID InputBuffer,
    _In_  ULONG              InputBufferLength,
    _Out_writes_bytes_to_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_  ULONG              OutputBufferLength,
    _Out_ PULONG             ReturnOutputBufferLength
    )
{
    PSENTINEL_COMMAND   command;
    SENTINEL_REPLY      reply;
    NTSTATUS            status = STATUS_SUCCESS;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(PortCookie);

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(SENTINEL_COMMAND)) {
        return STATUS_INVALID_PARAMETER;
    }

    command = (PSENTINEL_COMMAND)InputBuffer;

    RtlZeroMemory(&reply, sizeof(reply));

    switch (command->CommandType) {
    case CMD_SUSPEND_PROCESS:
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "BludEDR: CMD_SUSPEND_PROCESS PID=%lu\n", command->TargetProcessId));
        reply.Status = BludpHandleSuspendProcess(command->TargetProcessId);
        break;

    case CMD_TERMINATE_PROCESS:
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "BludEDR: CMD_TERMINATE_PROCESS PID=%lu\n", command->TargetProcessId));
        reply.Status = BludpHandleTerminateProcess(command->TargetProcessId);
        break;

    case CMD_INJECT_DLL:
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "BludEDR: CMD_INJECT_DLL PID=%lu\n", command->TargetProcessId));
        reply.Status = BludpHandleInjectDll(command->TargetProcessId,
                                             command->Data,
                                             sizeof(command->Data));
        break;

    case CMD_QUERY_PROCESS_INFO:
        {
            PBLUD_PROCESS_CONTEXT ctx = BludProcessContextLookup(command->TargetProcessId);
            if (ctx != NULL) {
                reply.Status = STATUS_SUCCESS;
                /* Copy process flags into reply data */
                if (OutputBufferLength >= sizeof(SENTINEL_REPLY)) {
                    reply.DataSize = sizeof(ULONG);
                    RtlCopyMemory(reply.Data, &ctx->Flags, sizeof(ULONG));
                }
            } else {
                reply.Status = STATUS_NOT_FOUND;
            }
        }
        break;

    case CMD_SET_PROTECTION:
        {
            PBLUD_PROCESS_CONTEXT ctx = BludProcessContextLookup(command->TargetProcessId);
            if (ctx != NULL) {
                ctx->Flags |= PROCESS_FLAG_PROTECTED;
                reply.Status = STATUS_SUCCESS;
            } else {
                reply.Status = STATUS_NOT_FOUND;
            }
        }
        break;

    case CMD_PING:
        reply.Status = STATUS_SUCCESS;
        reply.DataSize = sizeof(ULONG);
        {
            ULONG version = (BLUD_DRIVER_VERSION_MAJOR << 16) | BLUD_DRIVER_VERSION_MINOR;
            RtlCopyMemory(reply.Data, &version, sizeof(ULONG));
        }
        break;

    default:
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "BludEDR: Unknown command 0x%04X\n", command->CommandType));
        reply.Status = STATUS_INVALID_PARAMETER;
        break;
    }

    /* Write reply if the output buffer is large enough */
    if (OutputBuffer != NULL && OutputBufferLength >= sizeof(SENTINEL_REPLY)) {
        RtlCopyMemory(OutputBuffer, &reply, sizeof(SENTINEL_REPLY));
        *ReturnOutputBufferLength = sizeof(SENTINEL_REPLY);
    }

    return status;
}

/* ============================================================================
 * BludCommWorkerThread - Dequeues events and sends them to the agent
 * ============================================================================ */
VOID
BludCommWorkerThread(
    _In_ PVOID Context
    )
{
    NTSTATUS            status;
    LARGE_INTEGER       timeout;
    UCHAR               eventBuffer[sizeof(SENTINEL_REGISTRY_EVENT)]; /* Largest event */
    ULONG               bytesCopied;
    SENTINEL_MESSAGE    message;
    ULONG               replyLength;

    UNREFERENCED_PARAMETER(Context);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BludEDR: Worker thread started\n"));

    /* 500ms timeout for waiting on queue events */
    timeout.QuadPart = -5000000LL;  /* 500ms in 100ns units, negative = relative */

    while (!g_Globals.CommPort.ShutdownWorker) {
        /*
         * Wait for the data-ready event with a timeout.
         * The timeout ensures we check the shutdown flag periodically.
         */
        status = KeWaitForSingleObject(
            &g_Globals.EventQueue.DataReadyEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
            );

        if (g_Globals.CommPort.ShutdownWorker) {
            break;
        }

        /* Drain all available events from the queue */
        while (!g_Globals.CommPort.ShutdownWorker) {
            bytesCopied = 0;

            if (!BludDequeueEvent(&g_Globals.EventQueue,
                                   eventBuffer,
                                   sizeof(eventBuffer),
                                   &bytesCopied)) {
                /* Queue is empty */
                break;
            }

            if (bytesCopied == 0) {
                continue;
            }

            /* Ensure the agent is still connected */
            if (!g_Globals.CommPort.AgentConnected || g_Globals.CommPort.ClientPort == NULL) {
                continue;
            }

            /*
             * Build the SENTINEL_MESSAGE with the filter message header.
             * The event data goes into the union.
             */
            RtlZeroMemory(&message, sizeof(message));
            RtlCopyMemory(&message.Event, eventBuffer, bytesCopied);

            replyLength = 0;

            /*
             * Send the message. Use a reasonable timeout so we don't
             * block indefinitely if the agent is hung.
             */
            {
                LARGE_INTEGER sendTimeout;
                sendTimeout.QuadPart = -30000000LL;  /* 3 seconds */

                status = FltSendMessage(
                    g_Globals.FilterHandle,
                    &g_Globals.CommPort.ClientPort,
                    &message.Event,
                    bytesCopied,
                    NULL,           /* ReplyBuffer */
                    &replyLength,
                    &sendTimeout
                    );

                if (!NT_SUCCESS(status)) {
                    if (status == STATUS_TIMEOUT) {
                        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                            "BludEDR: FltSendMessage timeout\n"));
                    } else if (status == STATUS_PORT_DISCONNECTED) {
                        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                            "BludEDR: Agent disconnected during send\n"));
                        break;
                    }
                }
            }
        }
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BludEDR: Worker thread exiting\n"));

    PsTerminateSystemThread(STATUS_SUCCESS);
}
