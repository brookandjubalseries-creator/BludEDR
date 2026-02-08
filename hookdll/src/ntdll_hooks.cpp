/*
 * BludEDR - ntdll_hooks.cpp
 * Six critical ntdll hooks for detecting process injection, memory manipulation,
 * and other suspicious behaviors.
 *
 * Each hook:
 *   1. Calls the original function via trampoline
 *   2. Captures a 16-frame callstack
 *   3. Evaluates the result for suspicious indicators
 *   4. Sends a SENTINEL_MEMORY_EVENT via the hook comm pipe if flagged
 */

#include "ntdll_hooks.h"
#include "hook_engine.h"
#include "hook_comm.h"
#include "callstack_capture.h"
#include "sleep_obfuscation_detect.h"

/* ============================================================================
 * Original function pointers
 * ============================================================================ */
pfnNtAllocateVirtualMemory  g_pOrigNtAllocateVirtualMemory  = nullptr;
pfnNtProtectVirtualMemory   g_pOrigNtProtectVirtualMemory   = nullptr;
pfnNtWriteVirtualMemory     g_pOrigNtWriteVirtualMemory     = nullptr;
pfnNtCreateThreadEx         g_pOrigNtCreateThreadEx         = nullptr;
pfnNtMapViewOfSection       g_pOrigNtMapViewOfSection       = nullptr;
pfnNtQueueApcThread         g_pOrigNtQueueApcThread         = nullptr;

/* ============================================================================
 * Helper: Sequence number generator (thread-safe)
 * ============================================================================ */
static volatile LONG g_sequenceNumber = 0;

static ULONG NextSequence()
{
    return static_cast<ULONG>(InterlockedIncrement(&g_sequenceNumber));
}

/* ============================================================================
 * Helper: check if protection flags include EXECUTE
 * ============================================================================ */
static BOOL ProtectHasExecute(ULONG protect)
{
    return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

/* ============================================================================
 * Helper: check if protection flags include WRITE
 * ============================================================================ */
static BOOL ProtectHasWrite(ULONG protect)
{
    return (protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

/* ============================================================================
 * Helper: check if protection is RWX
 * ============================================================================ */
static BOOL ProtectIsRWX(ULONG protect)
{
    return (protect & PAGE_EXECUTE_READWRITE) != 0;
}

/* ============================================================================
 * 1. NtAllocateVirtualMemory hook
 *    Flags: RWX allocations, remote allocations (cross-process)
 * ============================================================================ */
NTSTATUS NTAPI Detour_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    /* Call original first */
    NTSTATUS status = g_pOrigNtAllocateVirtualMemory(
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    /* Only analyze successful allocations */
    if (status < 0) return status;

    __try {
        BOOL isRemote = !IsCurrentProcess(ProcessHandle);
        BOOL isRwx = ProtectIsRWX(Protect);

        if (isRemote || isRwx) {
            SENTINEL_MEMORY_EVENT evt;
            BuildMemoryEvent(&evt, EVENT_MEMORY_ALLOC);
            evt.Header.SequenceNumber = NextSequence();
            evt.BaseAddress = BaseAddress ? *BaseAddress : nullptr;
            evt.RegionSize  = RegionSize ? *RegionSize : 0;
            evt.OldProtect  = 0;
            evt.NewProtect  = Protect;
            evt.TargetProcessId = isRemote ? GetProcessId(ProcessHandle) : GetCurrentProcessId();
            evt.CallstackDepth = CaptureCallstack(evt.Callstack, SENTINEL_MAX_CALLSTACK);

            if (isRemote && isRwx) {
                SafeDetail(evt.Details, _countof(evt.Details),
                    L"Remote RWX allocation in PID %lu, base=0x%p, size=0x%llX",
                    evt.TargetProcessId, evt.BaseAddress, (ULONGLONG)evt.RegionSize);
            } else if (isRemote) {
                SafeDetail(evt.Details, _countof(evt.Details),
                    L"Remote allocation in PID %lu, protect=0x%lX, size=0x%llX",
                    evt.TargetProcessId, Protect, (ULONGLONG)evt.RegionSize);
            } else {
                SafeDetail(evt.Details, _countof(evt.Details),
                    L"Local RWX allocation, base=0x%p, size=0x%llX",
                    evt.BaseAddress, (ULONGLONG)evt.RegionSize);
            }

            HookComm_SendEvent(&evt);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Never crash the target process */
    }

    return status;
}

/* ============================================================================
 * 2. NtProtectVirtualMemory hook
 *    Flags: RW -> RX transitions (common in injection and sleep obfuscation)
 * ============================================================================ */
NTSTATUS NTAPI Detour_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)
{
    /* Call original first */
    NTSTATUS status = g_pOrigNtProtectVirtualMemory(
        ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    if (status < 0) return status;

    __try {
        ULONG oldProt = OldProtect ? *OldProtect : 0;
        BOOL writeToExec = ProtectHasWrite(oldProt) && ProtectHasExecute(NewProtect);

        /* Feed the sleep obfuscation detector regardless of writeToExec */
        if (BaseAddress && *BaseAddress) {
            SleepDetect_RecordProtectEvent(*BaseAddress, NewProtect);
        }

        if (writeToExec) {
            SENTINEL_MEMORY_EVENT evt;
            BuildMemoryEvent(&evt, EVENT_MEMORY_PROTECT);
            evt.Header.SequenceNumber = NextSequence();
            evt.BaseAddress = BaseAddress ? *BaseAddress : nullptr;
            evt.RegionSize  = RegionSize ? *RegionSize : 0;
            evt.OldProtect  = oldProt;
            evt.NewProtect  = NewProtect;
            evt.TargetProcessId = IsCurrentProcess(ProcessHandle)
                ? GetCurrentProcessId()
                : GetProcessId(ProcessHandle);
            evt.CallstackDepth = CaptureCallstack(evt.Callstack, SENTINEL_MAX_CALLSTACK);

            SafeDetail(evt.Details, _countof(evt.Details),
                L"RW->RX transition: base=0x%p, old=0x%lX, new=0x%lX",
                evt.BaseAddress, oldProt, NewProtect);

            HookComm_SendEvent(&evt);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Never crash */
    }

    return status;
}

/* ============================================================================
 * 3. NtWriteVirtualMemory hook
 *    Flags: all cross-process writes
 * ============================================================================ */
NTSTATUS NTAPI Detour_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    NTSTATUS status = g_pOrigNtWriteVirtualMemory(
        ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

    if (status < 0) return status;

    __try {
        if (!IsCurrentProcess(ProcessHandle)) {
            SENTINEL_MEMORY_EVENT evt;
            BuildMemoryEvent(&evt, EVENT_MEMORY_WRITE);
            evt.Header.SequenceNumber = NextSequence();
            evt.BaseAddress = BaseAddress;
            evt.RegionSize = NumberOfBytesToWrite;
            evt.OldProtect = 0;
            evt.NewProtect = 0;
            evt.TargetProcessId = GetProcessId(ProcessHandle);
            evt.CallstackDepth = CaptureCallstack(evt.Callstack, SENTINEL_MAX_CALLSTACK);

            SafeDetail(evt.Details, _countof(evt.Details),
                L"Cross-process write to PID %lu, addr=0x%p, size=0x%llX",
                evt.TargetProcessId, BaseAddress, (ULONGLONG)NumberOfBytesToWrite);

            HookComm_SendEvent(&evt);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Never crash */
    }

    return status;
}

/* ============================================================================
 * 4. NtCreateThreadEx hook
 *    Flags: remote thread creation (ProcessHandle != current)
 * ============================================================================ */
NTSTATUS NTAPI Detour_NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList)
{
    NTSTATUS status = g_pOrigNtCreateThreadEx(
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
        StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
        MaximumStackSize, AttributeList);

    if (status < 0) return status;

    __try {
        if (!IsCurrentProcess(ProcessHandle)) {
            SENTINEL_MEMORY_EVENT evt;
            BuildMemoryEvent(&evt, EVENT_REMOTE_THREAD);
            evt.Header.SequenceNumber = NextSequence();
            evt.BaseAddress = StartRoutine;
            evt.RegionSize = 0;
            evt.OldProtect = 0;
            evt.NewProtect = 0;
            evt.TargetProcessId = GetProcessId(ProcessHandle);
            evt.CallstackDepth = CaptureCallstack(evt.Callstack, SENTINEL_MAX_CALLSTACK);

            SafeDetail(evt.Details, _countof(evt.Details),
                L"Remote thread created in PID %lu, start=0x%p",
                evt.TargetProcessId, StartRoutine);

            HookComm_SendEvent(&evt);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Never crash */
    }

    return status;
}

/* ============================================================================
 * 5. NtMapViewOfSection hook
 *    Flags: cross-process section mapping (process hollowing indicator)
 * ============================================================================ */
NTSTATUS NTAPI Detour_NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect)
{
    NTSTATUS status = g_pOrigNtMapViewOfSection(
        SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
        SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);

    if (status < 0) return status;

    __try {
        if (!IsCurrentProcess(ProcessHandle)) {
            SENTINEL_MEMORY_EVENT evt;
            BuildMemoryEvent(&evt, EVENT_MEMORY_MAP);
            evt.Header.SequenceNumber = NextSequence();
            evt.BaseAddress = BaseAddress ? *BaseAddress : nullptr;
            evt.RegionSize = ViewSize ? *ViewSize : 0;
            evt.OldProtect = 0;
            evt.NewProtect = Win32Protect;
            evt.TargetProcessId = GetProcessId(ProcessHandle);
            evt.CallstackDepth = CaptureCallstack(evt.Callstack, SENTINEL_MAX_CALLSTACK);

            SafeDetail(evt.Details, _countof(evt.Details),
                L"Cross-process section map in PID %lu, base=0x%p, size=0x%llX (hollowing indicator)",
                evt.TargetProcessId, evt.BaseAddress, (ULONGLONG)evt.RegionSize);

            HookComm_SendEvent(&evt);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Never crash */
    }

    return status;
}

/* ============================================================================
 * 6. NtQueueApcThread hook
 *    Flags: all APC queuing (APC injection)
 * ============================================================================ */
NTSTATUS NTAPI Detour_NtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3)
{
    NTSTATUS status = g_pOrigNtQueueApcThread(
        ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);

    if (status < 0) return status;

    __try {
        SENTINEL_MEMORY_EVENT evt;
        BuildMemoryEvent(&evt, EVENT_APC_QUEUE);
        evt.Header.SequenceNumber = NextSequence();
        evt.BaseAddress = ApcRoutine;
        evt.RegionSize = 0;
        evt.OldProtect = 0;
        evt.NewProtect = 0;

        /* Determine target thread's process ID */
        DWORD targetTid = GetThreadId(ThreadHandle);
        /* We cannot easily get PID from TID without NtQueryInformationThread,
           so report the thread handle info we have */
        evt.TargetProcessId = 0; /* Unknown without further query */
        evt.CallstackDepth = CaptureCallstack(evt.Callstack, SENTINEL_MAX_CALLSTACK);

        SafeDetail(evt.Details, _countof(evt.Details),
            L"APC queued to thread %lu, routine=0x%p",
            targetTid, ApcRoutine);

        HookComm_SendEvent(&evt);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Never crash */
    }

    return status;
}

/* ============================================================================
 * NtdllHooks_Install - resolve ntdll exports and install inline hooks
 * ============================================================================ */
BOOL NtdllHooks_Install()
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    PVOID pNtAllocate   = PeUtils_GetExportAddress(hNtdll, "NtAllocateVirtualMemory");
    PVOID pNtProtect    = PeUtils_GetExportAddress(hNtdll, "NtProtectVirtualMemory");
    PVOID pNtWrite      = PeUtils_GetExportAddress(hNtdll, "NtWriteVirtualMemory");
    PVOID pNtCreateTh   = PeUtils_GetExportAddress(hNtdll, "NtCreateThreadEx");
    PVOID pNtMapView    = PeUtils_GetExportAddress(hNtdll, "NtMapViewOfSection");
    PVOID pNtQueueApc   = PeUtils_GetExportAddress(hNtdll, "NtQueueApcThread");

    BOOL allOk = TRUE;

    if (pNtAllocate) {
        if (!HookEngine_InstallHook(pNtAllocate, &Detour_NtAllocateVirtualMemory,
                                     reinterpret_cast<PVOID*>(&g_pOrigNtAllocateVirtualMemory))) {
            allOk = FALSE;
        }
    } else {
        allOk = FALSE;
    }

    if (pNtProtect) {
        if (!HookEngine_InstallHook(pNtProtect, &Detour_NtProtectVirtualMemory,
                                     reinterpret_cast<PVOID*>(&g_pOrigNtProtectVirtualMemory))) {
            allOk = FALSE;
        }
    } else {
        allOk = FALSE;
    }

    if (pNtWrite) {
        if (!HookEngine_InstallHook(pNtWrite, &Detour_NtWriteVirtualMemory,
                                     reinterpret_cast<PVOID*>(&g_pOrigNtWriteVirtualMemory))) {
            allOk = FALSE;
        }
    } else {
        allOk = FALSE;
    }

    if (pNtCreateTh) {
        if (!HookEngine_InstallHook(pNtCreateTh, &Detour_NtCreateThreadEx,
                                     reinterpret_cast<PVOID*>(&g_pOrigNtCreateThreadEx))) {
            allOk = FALSE;
        }
    } else {
        allOk = FALSE;
    }

    if (pNtMapView) {
        if (!HookEngine_InstallHook(pNtMapView, &Detour_NtMapViewOfSection,
                                     reinterpret_cast<PVOID*>(&g_pOrigNtMapViewOfSection))) {
            allOk = FALSE;
        }
    } else {
        allOk = FALSE;
    }

    if (pNtQueueApc) {
        if (!HookEngine_InstallHook(pNtQueueApc, &Detour_NtQueueApcThread,
                                     reinterpret_cast<PVOID*>(&g_pOrigNtQueueApcThread))) {
            allOk = FALSE;
        }
    } else {
        allOk = FALSE;
    }

    return allOk;
}

/* ============================================================================
 * NtdllHooks_Remove - remove all ntdll hooks
 * ============================================================================ */
void NtdllHooks_Remove()
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    /* Remove in reverse order of install for safety */
    PVOID targets[] = {
        PeUtils_GetExportAddress(hNtdll, "NtQueueApcThread"),
        PeUtils_GetExportAddress(hNtdll, "NtMapViewOfSection"),
        PeUtils_GetExportAddress(hNtdll, "NtCreateThreadEx"),
        PeUtils_GetExportAddress(hNtdll, "NtWriteVirtualMemory"),
        PeUtils_GetExportAddress(hNtdll, "NtProtectVirtualMemory"),
        PeUtils_GetExportAddress(hNtdll, "NtAllocateVirtualMemory"),
    };

    for (PVOID t : targets) {
        if (t) HookEngine_RemoveHook(t);
    }

    g_pOrigNtAllocateVirtualMemory = nullptr;
    g_pOrigNtProtectVirtualMemory  = nullptr;
    g_pOrigNtWriteVirtualMemory    = nullptr;
    g_pOrigNtCreateThreadEx        = nullptr;
    g_pOrigNtMapViewOfSection      = nullptr;
    g_pOrigNtQueueApcThread        = nullptr;
}
