/*
 * BludEDR - driver_entry.c
 * DriverEntry, filter registration, callback registration, unload cleanup
 *
 * Made by @tarry
 */

#include "../inc/driver.h"

/* ============================================================================
 * Global driver state
 * ============================================================================ */
BLUD_GLOBALS g_Globals = { 0 };

/* ============================================================================
 * Minifilter operation callbacks
 * ============================================================================ */
static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        BludPreCreate,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

/* ============================================================================
 * Minifilter context registration
 * ============================================================================ */
static const FLT_CONTEXT_REGISTRATION g_ContextRegistration[] = {
    {
        FLT_STREAMHANDLE_CONTEXT,
        0,
        NULL,
        sizeof(BLUD_PROCESS_CONTEXT),
        BLUD_POOL_TAG
    },
    { FLT_CONTEXT_END }
};

/* ============================================================================
 * Minifilter registration structure
 * ============================================================================ */
static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),           /* Size */
    FLT_REGISTRATION_VERSION,           /* Version */
    0,                                  /* Flags */
    g_ContextRegistration,              /* Context */
    g_Callbacks,                        /* Operation callbacks */
    BludUnload,                         /* MiniFilterUnload */
    BludInstanceSetup,                  /* InstanceSetup */
    BludInstanceQueryTeardown,          /* InstanceQueryTeardown */
    NULL,                               /* InstanceTeardownStart */
    NULL,                               /* InstanceTeardownComplete */
    NULL,                               /* GenerateFileName */
    NULL,                               /* GenerateDestinationFileName */
    NULL                                /* NormalizeNameComponent */
};

/* ============================================================================
 * Object callback registration (for LSASS protection)
 * ============================================================================ */
static OB_OPERATION_REGISTRATION g_ObOperationRegistration[] = {
    {
        PsProcessType,
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        BludObPreOperationCallback,
        BludObPostOperationCallback
    }
};

static OB_CALLBACK_REGISTRATION g_ObCallbackRegistration = {
    OB_FLT_REGISTRATION_VERSION,
    1,
    RTL_CONSTANT_STRING(L"385200"),
    NULL,
    g_ObOperationRegistration
};

/* ============================================================================
 * Forward declarations for local helpers
 * ============================================================================ */
static VOID
BludpRegisterCallbacks(
    VOID
    );

static VOID
BludpUnregisterCallbacks(
    VOID
    );

static VOID
BludpResolveLsassPid(
    VOID
    );

/* ============================================================================
 * DriverEntry
 * ============================================================================ */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&g_Globals, sizeof(g_Globals));
    g_Globals.DriverObject = DriverObject;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BludEDR: DriverEntry v%d.%d\n",
        BLUD_DRIVER_VERSION_MAJOR, BLUD_DRIVER_VERSION_MINOR));

    /* --- 1. Initialize the event queue --- */
    status = BludEventQueueInitialize(&g_Globals.EventQueue, SENTINEL_EVENT_QUEUE_SIZE);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BludEDR: EventQueueInitialize failed 0x%08X\n", status));
        return status;
    }

    /* --- 2. Initialize process context tracking --- */
    status = BludProcessContextInitialize();
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BludEDR: ProcessContextInitialize failed 0x%08X\n", status));
        BludEventQueueDestroy(&g_Globals.EventQueue);
        return status;
    }

    /* --- 3. Register minifilter --- */
    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_Globals.FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BludEDR: FltRegisterFilter failed 0x%08X\n", status));
        goto Cleanup;
    }
    g_Globals.FilterRegistered = TRUE;

    /* --- 4. Create communication port --- */
    status = BludCommPortInitialize(g_Globals.FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BludEDR: CommPortInitialize failed 0x%08X\n", status));
        goto Cleanup;
    }
    g_Globals.CommPortCreated = TRUE;

    /* --- 5. Register kernel callbacks --- */
    BludpRegisterCallbacks();

    /* --- 6. Resolve LSASS PID for object callback fast path --- */
    BludpResolveLsassPid();

    /* --- 7. Start filtering --- */
    status = FltStartFiltering(g_Globals.FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "BludEDR: FltStartFiltering failed 0x%08X\n", status));
        goto Cleanup;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BludEDR: Driver loaded successfully\n"));

    return STATUS_SUCCESS;

Cleanup:
    BludpUnregisterCallbacks();

    if (g_Globals.CommPortCreated) {
        BludCommPortTeardown();
        g_Globals.CommPortCreated = FALSE;
    }

    if (g_Globals.FilterRegistered) {
        FltUnregisterFilter(g_Globals.FilterHandle);
        g_Globals.FilterRegistered = FALSE;
    }

    BludProcessContextCleanup();
    BludEventQueueDestroy(&g_Globals.EventQueue);

    return status;
}

/* ============================================================================
 * BludUnload - Minifilter unload callback
 * ============================================================================ */
NTSTATUS
BludUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BludEDR: Unloading driver\n"));

    /* Stop the worker thread first so it does not try to use the comm port */
    BludCommPortTeardown();
    g_Globals.CommPortCreated = FALSE;

    /* Unregister all kernel callbacks */
    BludpUnregisterCallbacks();

    /* Unregister the minifilter */
    if (g_Globals.FilterRegistered) {
        FltUnregisterFilter(g_Globals.FilterHandle);
        g_Globals.FilterRegistered = FALSE;
    }

    /* Cleanup subsystems */
    BludProcessContextCleanup();
    BludEventQueueDestroy(&g_Globals.EventQueue);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BludEDR: Driver unloaded, dropped %ld events\n",
        g_Globals.EventQueue.DroppedCount));

    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludInstanceSetup
 * ============================================================================ */
NTSTATUS
BludInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS    FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE              VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE      VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    /* Only attach to NTFS and ReFS volumes */
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS &&
        VolumeFilesystemType != FLT_FSTYPE_REFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludInstanceQueryTeardown
 * ============================================================================ */
NTSTATUS
BludInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS           FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludpRegisterCallbacks - Register all kernel notification callbacks
 * ============================================================================ */
static VOID
BludpRegisterCallbacks(
    VOID
    )
{
    NTSTATUS status;

    /* Process creation/termination (extended) */
    status = PsSetCreateProcessNotifyRoutineEx(BludProcessNotifyRoutineEx, FALSE);
    if (NT_SUCCESS(status)) {
        g_Globals.ProcessCallbackRegistered = TRUE;
    } else {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "BludEDR: PsSetCreateProcessNotifyRoutineEx failed 0x%08X\n", status));
    }

    /* Thread creation */
    status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem,
                                               (PVOID)BludThreadNotifyRoutine);
    if (NT_SUCCESS(status)) {
        g_Globals.ThreadCallbackRegistered = TRUE;
    } else {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "BludEDR: PsSetCreateThreadNotifyRoutineEx failed 0x%08X\n", status));
    }

    /* Image load */
    status = PsSetLoadImageNotifyRoutine(BludImageLoadNotifyRoutine);
    if (NT_SUCCESS(status)) {
        g_Globals.ImageCallbackRegistered = TRUE;
    } else {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "BludEDR: PsSetLoadImageNotifyRoutine failed 0x%08X\n", status));
    }

    /* Registry */
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(BLUD_ALTITUDE);
    status = CmRegisterCallbackEx(BludRegistryCallback,
                                   &altitude,
                                   g_Globals.DriverObject,
                                   NULL,
                                   &g_Globals.RegistryCookie,
                                   NULL);
    if (NT_SUCCESS(status)) {
        g_Globals.RegistryCallbackRegistered = TRUE;
    } else {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "BludEDR: CmRegisterCallbackEx failed 0x%08X\n", status));
    }

    /* Object callbacks (LSASS protection) */
    status = ObRegisterCallbacks(&g_ObCallbackRegistration, &g_Globals.ObCallbackHandle);
    if (NT_SUCCESS(status)) {
        g_Globals.ObCallbackRegistered = TRUE;
    } else {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "BludEDR: ObRegisterCallbacks failed 0x%08X\n", status));
    }
}

/* ============================================================================
 * BludpUnregisterCallbacks - Unregister all kernel notification callbacks
 * ============================================================================ */
static VOID
BludpUnregisterCallbacks(
    VOID
    )
{
    if (g_Globals.ObCallbackRegistered) {
        ObUnRegisterCallbacks(g_Globals.ObCallbackHandle);
        g_Globals.ObCallbackRegistered = FALSE;
    }

    if (g_Globals.RegistryCallbackRegistered) {
        CmUnRegisterCallback(g_Globals.RegistryCookie);
        g_Globals.RegistryCallbackRegistered = FALSE;
    }

    if (g_Globals.ImageCallbackRegistered) {
        PsRemoveLoadImageNotifyRoutine(BludImageLoadNotifyRoutine);
        g_Globals.ImageCallbackRegistered = FALSE;
    }

    if (g_Globals.ThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(BludThreadNotifyRoutine);
        g_Globals.ThreadCallbackRegistered = FALSE;
    }

    if (g_Globals.ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(BludProcessNotifyRoutineEx, TRUE);
        g_Globals.ProcessCallbackRegistered = FALSE;
    }
}

/* ============================================================================
 * BludpResolveLsassPid - Find lsass.exe PID for fast path in object callback
 * ============================================================================ */
static VOID
BludpResolveLsassPid(
    VOID
    )
{
    /*
     * We start with PID 0. The process callback will update this
     * field when it sees lsass.exe being created. On driver load,
     * lsass is already running, so we walk the process list once.
     */
    ULONG bufferSize = 0;
    NTSTATUS status;
    PVOID buffer = NULL;

    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH || bufferSize == 0) {
        return;
    }

    bufferSize += 4096;  /* Extra room for racing creates */
    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, BLUD_POOL_TAG);
    if (buffer == NULL) {
        return;
    }

    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, BLUD_POOL_TAG);
        return;
    }

    PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    UNICODE_STRING lsassName = RTL_CONSTANT_STRING(L"lsass.exe");

    for (;;) {
        if (procInfo->ImageName.Buffer != NULL &&
            RtlEqualUnicodeString(&procInfo->ImageName, &lsassName, TRUE)) {
            g_Globals.LsassPid = (ULONG)(ULONG_PTR)procInfo->UniqueProcessId;
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "BludEDR: LSASS PID = %lu\n", g_Globals.LsassPid));
            break;
        }
        if (procInfo->NextEntryOffset == 0) {
            break;
        }
        procInfo = (PSYSTEM_PROCESS_INFORMATION)
            ((ULONG_PTR)procInfo + procInfo->NextEntryOffset);
    }

    ExFreePoolWithTag(buffer, BLUD_POOL_TAG);
}
