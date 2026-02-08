/*
 * BludEDR - driver.h
 * Main driver header: globals, function prototypes, internal structures
 *
 * Made by @tarry
 */

#pragma once

#include <fltKernel.h>
#include <ntifs.h>
#include <ntstrsafe.h>

#include "..\..\shared\sentinel_shared.h"

/* ============================================================================
 * Kernel-mode constants not always available in WDK headers
 * These are the standard process access rights from winnt.h
 * ============================================================================ */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE           0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD       0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION        0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ             0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE            0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE          0x0040
#endif

/* ============================================================================
 * ZwQuerySystemInformation - not always declared in all WDK header combos
 * ============================================================================ */
#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_      ULONG  SystemInformationClass,
    _Out_opt_ PVOID  SystemInformation,
    _In_      ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/*
 * SYSTEM_PROCESS_INFORMATION - defined here if not already provided.
 * We only need the fields used in BludpResolveLsassPid.
 */
#ifndef _SYSTEM_PROCESS_INFORMATION_DEFINED
#define _SYSTEM_PROCESS_INFORMATION_DEFINED
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   WorkingSetPrivateSize;
    ULONG           HardFaultCount;
    ULONG           NumberOfThreadsHighWatermark;
    ULONGLONG       CycleTime;
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    LONG            BasePriority;
    HANDLE          UniqueProcessId;
    HANDLE          InheritedFromUniqueProcessId;
    ULONG           HandleCount;
    ULONG           SessionId;
    ULONG_PTR       UniqueProcessKey;
    SIZE_T          PeakVirtualSize;
    SIZE_T          VirtualSize;
    ULONG           PageFaultCount;
    SIZE_T          PeakWorkingSetSize;
    SIZE_T          WorkingSetSize;
    SIZE_T          QuotaPeakPagedPoolUsage;
    SIZE_T          QuotaPagedPoolUsage;
    SIZE_T          QuotaPeakNonPagedPoolUsage;
    SIZE_T          QuotaNonPagedPoolUsage;
    SIZE_T          PagefileUsage;
    SIZE_T          PeakPagefileUsage;
    SIZE_T          PrivatePageCount;
    LARGE_INTEGER   ReadOperationCount;
    LARGE_INTEGER   WriteOperationCount;
    LARGE_INTEGER   OtherOperationCount;
    LARGE_INTEGER   ReadTransferCount;
    LARGE_INTEGER   WriteTransferCount;
    LARGE_INTEGER   OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
#endif /* _SYSTEM_PROCESS_INFORMATION_DEFINED */

/* ============================================================================
 * Undocumented / semi-documented kernel APIs used by the driver
 * ============================================================================ */

/* PsSuspendProcess - suspends all threads in a process */
NTSYSCALLAPI
NTSTATUS
NTAPI
PsSuspendProcess(
    _In_ PEPROCESS Process
    );

/* PsGetThreadStartAddress - gets the user-mode start address of a thread */
NTSYSCALLAPI
PVOID
NTAPI
PsGetThreadStartAddress(
    _In_ PETHREAD Thread
    );

/* ============================================================================
 * Compile-time configuration
 * ============================================================================ */

#define BLUD_DRIVER_VERSION_MAJOR   1
#define BLUD_DRIVER_VERSION_MINOR   0

/* Ring buffer states */
#define SLOT_FREE       0
#define SLOT_WRITING    1
#define SLOT_READY      2

/* Process context flags */
#define PROCESS_FLAG_PROTECTED          0x0001
#define PROCESS_FLAG_LSASS              0x0002
#define PROCESS_FLAG_SYSTEM             0x0004
#define PROCESS_FLAG_MONITORED          0x0008
#define PROCESS_FLAG_SUSPICIOUS         0x0010

/* ============================================================================
 * Internal structures
 * ============================================================================ */

/*
 * Per-process context attached via minifilter stream handle context.
 */
typedef struct _BLUD_PROCESS_CONTEXT {
    ULONG           ProcessId;
    ULONG           ParentProcessId;
    ULONG           Flags;
    LARGE_INTEGER   CreateTime;
    WCHAR           ImagePath[SENTINEL_MAX_PATH];
} BLUD_PROCESS_CONTEXT, *PBLUD_PROCESS_CONTEXT;

/*
 * Lock-free ring buffer for event queuing.
 */
typedef struct _BLUD_EVENT_QUEUE {
    PSENTINEL_QUEUE_ENTRY   Entries;
    volatile LONG           Head;           /* Producer index */
    volatile LONG           Tail;           /* Consumer index */
    ULONG                   Capacity;
    KEVENT                  DataReadyEvent; /* Signaled when data available */
    LONG                    DroppedCount;   /* Events dropped due to full queue */
} BLUD_EVENT_QUEUE, *PBLUD_EVENT_QUEUE;

/*
 * Communication port state.
 */
typedef struct _BLUD_COMM_PORT {
    PFLT_PORT       ServerPort;
    PFLT_PORT       ClientPort;
    HANDLE          WorkerThread;
    PETHREAD        WorkerThreadObject;
    volatile LONG   AgentConnected;
    volatile LONG   ShutdownWorker;
    KEVENT          WorkerStartEvent;
} BLUD_COMM_PORT, *PBLUD_COMM_PORT;

/*
 * Global driver data aggregated in a single structure.
 */
typedef struct _BLUD_GLOBALS {
    PDRIVER_OBJECT          DriverObject;
    PFLT_FILTER             FilterHandle;
    BLUD_COMM_PORT          CommPort;
    BLUD_EVENT_QUEUE        EventQueue;
    LARGE_INTEGER           RegistryCookie;
    PVOID                   ObCallbackHandle;
    volatile LONG           SequenceNumber;

    /* LSASS PID cached for object callback fast path */
    ULONG                   LsassPid;

    /* Flags */
    BOOLEAN                 ProcessCallbackRegistered;
    BOOLEAN                 ThreadCallbackRegistered;
    BOOLEAN                 ImageCallbackRegistered;
    BOOLEAN                 RegistryCallbackRegistered;
    BOOLEAN                 ObCallbackRegistered;
    BOOLEAN                 FilterRegistered;
    BOOLEAN                 CommPortCreated;
} BLUD_GLOBALS, *PBLUD_GLOBALS;

/* ============================================================================
 * Global instance (defined in driver_entry.c)
 * ============================================================================ */
extern BLUD_GLOBALS g_Globals;

/* ============================================================================
 * driver_entry.c
 * ============================================================================ */
DRIVER_INITIALIZE DriverEntry;

NTSTATUS
BludUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
BludInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS    FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE              VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE      VolumeFilesystemType
    );

NTSTATUS
BludInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS           FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

/* ============================================================================
 * minifilter_ops.c
 * ============================================================================ */
FLT_PREOP_CALLBACK_STATUS
BludPreCreate(
    _Inout_ PFLT_CALLBACK_DATA         Data,
    _In_    PCFLT_RELATED_OBJECTS       FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

/* ============================================================================
 * process_monitor.c
 * ============================================================================ */
VOID
BludProcessNotifyRoutineEx(
    _Inout_  PEPROCESS                  Process,
    _In_     HANDLE                     ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO  CreateInfo
    );

/* ============================================================================
 * thread_monitor.c
 * ============================================================================ */
VOID
BludThreadNotifyRoutine(
    _In_ HANDLE  ProcessId,
    _In_ HANDLE  ThreadId,
    _In_ BOOLEAN Create
    );

/* ============================================================================
 * image_monitor.c
 * ============================================================================ */
VOID
BludImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING  FullImageName,
    _In_     HANDLE           ProcessId,
    _In_     PIMAGE_INFO      ImageInfo
    );

/* ============================================================================
 * registry_monitor.c
 * ============================================================================ */
NTSTATUS
BludRegistryCallback(
    _In_ PVOID  CallbackContext,
    _In_ PVOID  Argument1,
    _In_ PVOID  Argument2
    );

/* ============================================================================
 * object_monitor.c
 * ============================================================================ */
OB_PREOP_CALLBACK_STATUS
BludObPreOperationCallback(
    _In_ PVOID                          RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

VOID
BludObPostOperationCallback(
    _In_ PVOID                            RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION   OperationInformation
    );

/* ============================================================================
 * comm_port.c
 * ============================================================================ */
NTSTATUS
BludCommPortInitialize(
    _In_ PFLT_FILTER Filter
    );

VOID
BludCommPortTeardown(
    VOID
    );

NTSTATUS
BludCommPortConnect(
    _In_  PFLT_PORT          ClientPort,
    _In_  PVOID              ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_  ULONG              SizeOfContext,
    _Out_ PVOID              *ConnectionPortCookie
    );

VOID
BludCommPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
BludCommPortMessageNotify(
    _In_  PVOID              PortCookie,
    _In_reads_bytes_(InputBufferLength)  PVOID InputBuffer,
    _In_  ULONG              InputBufferLength,
    _Out_writes_bytes_to_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_  ULONG              OutputBufferLength,
    _Out_ PULONG             ReturnOutputBufferLength
    );

VOID
BludCommWorkerThread(
    _In_ PVOID Context
    );

/* ============================================================================
 * event_queue.c
 * ============================================================================ */
NTSTATUS
BludEventQueueInitialize(
    _Out_ PBLUD_EVENT_QUEUE Queue,
    _In_  ULONG             Capacity
    );

VOID
BludEventQueueDestroy(
    _Inout_ PBLUD_EVENT_QUEUE Queue
    );

BOOLEAN
BludEnqueueEvent(
    _Inout_ PBLUD_EVENT_QUEUE Queue,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_    ULONG             DataSize
    );

BOOLEAN
BludDequeueEvent(
    _Inout_ PBLUD_EVENT_QUEUE Queue,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_    ULONG             BufferSize,
    _Out_   PULONG            BytesCopied
    );

/* ============================================================================
 * process_context.c
 * ============================================================================ */
NTSTATUS
BludProcessContextInitialize(
    VOID
    );

NTSTATUS
BludProcessContextCreate(
    _In_  ULONG               ProcessId,
    _In_  ULONG               ParentProcessId,
    _In_opt_ PUNICODE_STRING  ImagePath,
    _Out_ PBLUD_PROCESS_CONTEXT *Context
    );

PBLUD_PROCESS_CONTEXT
BludProcessContextLookup(
    _In_ ULONG ProcessId
    );

VOID
BludProcessContextRemove(
    _In_ ULONG ProcessId
    );

VOID
BludProcessContextCleanup(
    VOID
    );

/* ============================================================================
 * string_utils.c
 * ============================================================================ */
NTSTATUS
BludAllocateUnicodeString(
    _Out_ PUNICODE_STRING String,
    _In_  USHORT          MaximumLength
    );

VOID
BludFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    );

NTSTATUS
BludCopyUnicodeString(
    _Out_ PUNICODE_STRING Destination,
    _In_  PCUNICODE_STRING Source
    );

BOOLEAN
BludCompareExtension(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCWSTR           ExtensionList
    );

/* ============================================================================
 * Helper inline: populate event header
 * ============================================================================ */
static __inline VOID
BludFillEventHeader(
    _Out_ PSENTINEL_EVENT_HEADER Header,
    _In_  SENTINEL_EVENT_TYPE    Type,
    _In_  ULONG                  TotalSize
    )
{
    Header->Size = TotalSize;
    Header->Type = Type;
    KeQuerySystemTimePrecise(&Header->Timestamp);
    Header->ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    Header->ThreadId  = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    Header->SequenceNumber = (ULONG)InterlockedIncrement(&g_Globals.SequenceNumber);
}
