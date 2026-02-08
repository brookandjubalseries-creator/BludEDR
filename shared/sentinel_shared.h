/*
 * BludEDR - sentinel_shared.h
 * Communication protocol structs between kernel driver and userspace agent
 *
 * Made by @tarry
 */

#pragma once

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#else
#include <windows.h>
#include <fltUser.h>
#endif

#include "sentinel_events.h"
#include "sentinel_ioc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Communication port name */
#define BLUD_COMM_PORT_NAME     L"\\BludCommPort"
#define BLUD_HOOK_PIPE_PREFIX   L"\\\\.\\pipe\\BludHook_"

/* Pool tag for driver allocations */
#define BLUD_POOL_TAG           'dulB'

/* Maximum sizes */
#define SENTINEL_MAX_PATH           520
#define SENTINEL_MAX_COMMAND_LINE   4096
#define SENTINEL_MAX_CALLSTACK      16
#define SENTINEL_EVENT_QUEUE_SIZE   4096
#define SENTINEL_MAX_EXTENSION      16
#define SENTINEL_MAX_REGKEY         512
#define SENTINEL_MAX_REGVALUE       256
#define SENTINEL_MAX_REGDATA        1024

/* Minifilter altitude */
#define BLUD_ALTITUDE              L"385200"

/* Suspicious file extensions to monitor */
#define BLUD_SUSPICIOUS_EXTENSIONS  L".bat.vbs.ps1.js.wsf.hta.cmd.scr.pif.com"

/* ============================================================================
 * Event Header - Common prefix for all events
 * ============================================================================ */
typedef struct _SENTINEL_EVENT_HEADER {
    ULONG                   Size;           /* Total size of this event struct */
    SENTINEL_EVENT_TYPE     Type;           /* Event type */
    LARGE_INTEGER           Timestamp;      /* Kernel timestamp (KeQuerySystemTimePrecise) */
    ULONG                   ProcessId;
    ULONG                   ThreadId;
    ULONG                   SequenceNumber; /* Monotonic sequence */
} SENTINEL_EVENT_HEADER, *PSENTINEL_EVENT_HEADER;

/* ============================================================================
 * Process Events
 * ============================================================================ */
typedef struct _SENTINEL_PROCESS_EVENT {
    SENTINEL_EVENT_HEADER   Header;
    ULONG                   ParentProcessId;
    ULONG                   CreatorProcessId;
    ULONG                   CreatorThreadId;
    BOOLEAN                 IsTermination;
    ULONG                   ExitCode;
    WCHAR                   ImagePath[SENTINEL_MAX_PATH];
    WCHAR                   CommandLine[SENTINEL_MAX_COMMAND_LINE];
} SENTINEL_PROCESS_EVENT, *PSENTINEL_PROCESS_EVENT;

/* ============================================================================
 * Thread Events
 * ============================================================================ */
typedef struct _SENTINEL_THREAD_EVENT {
    SENTINEL_EVENT_HEADER   Header;
    ULONG                   TargetProcessId;
    ULONG                   TargetThreadId;
    BOOLEAN                 IsRemoteThread;     /* Creator PID != Target PID */
    PVOID                   StartAddress;
} SENTINEL_THREAD_EVENT, *PSENTINEL_THREAD_EVENT;

/* ============================================================================
 * Image/Module Load Events
 * ============================================================================ */
typedef struct _SENTINEL_IMAGE_EVENT {
    SENTINEL_EVENT_HEADER   Header;
    PVOID                   ImageBase;
    SIZE_T                  ImageSize;
    BOOLEAN                 IsSystemImage;
    WCHAR                   ImageName[SENTINEL_MAX_PATH];
} SENTINEL_IMAGE_EVENT, *PSENTINEL_IMAGE_EVENT;

/* ============================================================================
 * File Events
 * ============================================================================ */
typedef struct _SENTINEL_FILE_EVENT {
    SENTINEL_EVENT_HEADER   Header;
    ULONG                   DesiredAccess;
    ULONG                   CreateDisposition;
    BOOLEAN                 IsSuspiciousExtension;
    WCHAR                   Extension[SENTINEL_MAX_EXTENSION];
    WCHAR                   FileName[SENTINEL_MAX_PATH];
} SENTINEL_FILE_EVENT, *PSENTINEL_FILE_EVENT;

/* ============================================================================
 * Registry Events
 * ============================================================================ */
typedef struct _SENTINEL_REGISTRY_EVENT {
    SENTINEL_EVENT_HEADER   Header;
    ULONG                   Operation;          /* REG_NOTIFY_CLASS value */
    BOOLEAN                 IsPersistenceKey;
    WCHAR                   KeyName[SENTINEL_MAX_REGKEY];
    WCHAR                   ValueName[SENTINEL_MAX_REGVALUE];
    UCHAR                   Data[SENTINEL_MAX_REGDATA];
    ULONG                   DataSize;
    ULONG                   DataType;           /* REG_SZ, REG_DWORD, etc. */
} SENTINEL_REGISTRY_EVENT, *PSENTINEL_REGISTRY_EVENT;

/* ============================================================================
 * Object/Handle Events (LSASS protection)
 * ============================================================================ */
typedef struct _SENTINEL_OBJECT_EVENT {
    SENTINEL_EVENT_HEADER   Header;
    ULONG                   TargetProcessId;
    ACCESS_MASK             DesiredAccess;
    ACCESS_MASK             GrantedAccess;
    ACCESS_MASK             StrippedAccess;     /* Access bits we removed */
    WCHAR                   TargetImageName[SENTINEL_MAX_PATH];
} SENTINEL_OBJECT_EVENT, *PSENTINEL_OBJECT_EVENT;

/* ============================================================================
 * Memory Events (from hook DLL via named pipe)
 * ============================================================================ */
typedef struct _SENTINEL_MEMORY_EVENT {
    SENTINEL_EVENT_HEADER   Header;
    PVOID                   BaseAddress;
    SIZE_T                  RegionSize;
    ULONG                   OldProtect;
    ULONG                   NewProtect;
    ULONG                   TargetProcessId;    /* For cross-process operations */
    PVOID                   Callstack[SENTINEL_MAX_CALLSTACK];
    ULONG                   CallstackDepth;
    WCHAR                   Details[256];       /* Human-readable detail string */
} SENTINEL_MEMORY_EVENT, *PSENTINEL_MEMORY_EVENT;

/* ============================================================================
 * Network Events
 * ============================================================================ */
typedef struct _SENTINEL_NETWORK_EVENT {
    SENTINEL_EVENT_HEADER   Header;
    ULONG                   LocalAddress;
    USHORT                  LocalPort;
    ULONG                   RemoteAddress;
    USHORT                  RemotePort;
    ULONG                   Protocol;
    BOOLEAN                 IsOutbound;
} SENTINEL_NETWORK_EVENT, *PSENTINEL_NETWORK_EVENT;

/* ============================================================================
 * Agent->Driver Commands
 * ============================================================================ */
typedef struct _SENTINEL_COMMAND {
    SENTINEL_COMMAND_TYPE   CommandType;
    ULONG                   TargetProcessId;
    ULONG                   Flags;
    UCHAR                   Data[256];
} SENTINEL_COMMAND, *PSENTINEL_COMMAND;

typedef struct _SENTINEL_REPLY {
    NTSTATUS                Status;
    ULONG                   DataSize;
    UCHAR                   Data[256];
} SENTINEL_REPLY, *PSENTINEL_REPLY;

/* ============================================================================
 * Filter Message wrapper (for FltSendMessage / FilterGetMessage)
 * ============================================================================ */
typedef struct _SENTINEL_MESSAGE {
    FILTER_MESSAGE_HEADER   Header;
    union {
        SENTINEL_EVENT_HEADER       EventHeader;
        SENTINEL_PROCESS_EVENT      Process;
        SENTINEL_THREAD_EVENT       Thread;
        SENTINEL_IMAGE_EVENT        Image;
        SENTINEL_FILE_EVENT         File;
        SENTINEL_REGISTRY_EVENT     Registry;
        SENTINEL_OBJECT_EVENT       Object;
        SENTINEL_MEMORY_EVENT       Memory;
        SENTINEL_NETWORK_EVENT      Network;
    } Event;
} SENTINEL_MESSAGE, *PSENTINEL_MESSAGE;

/* Reply message from agent to driver */
typedef struct _SENTINEL_REPLY_MESSAGE {
    FILTER_REPLY_HEADER     Header;
    SENTINEL_REPLY          Reply;
} SENTINEL_REPLY_MESSAGE, *PSENTINEL_REPLY_MESSAGE;

/* ============================================================================
 * Lock-free ring buffer entry for event queue
 * ============================================================================ */
typedef struct _SENTINEL_QUEUE_ENTRY {
    volatile LONG           InUse;          /* 0=free, 1=writing, 2=ready */
    ULONG                   DataSize;
    UCHAR                   Data[sizeof(SENTINEL_REGISTRY_EVENT)]; /* Largest event */
} SENTINEL_QUEUE_ENTRY, *PSENTINEL_QUEUE_ENTRY;

#ifdef __cplusplus
}
#endif
