/*
 * BludEDR - hookdll.h
 * Main hook DLL header - includes, globals, function prototypes
 *
 * Made by @tarry
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>
#include <intrin.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <algorithm>

/* Shared protocol headers */
#include "../../shared/sentinel_shared.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * NT API typedefs not in winternl.h
 * ============================================================================ */

typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* pfnNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS(NTAPI* pfnNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(
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
    PVOID AttributeList
);

typedef NTSTATUS(NTAPI* pfnNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS(NTAPI* pfnNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef PVOID(WINAPI* pfnAddVectoredExceptionHandler)(
    ULONG First,
    PVECTORED_EXCEPTION_HANDLER Handler
);

/* ============================================================================
 * Global state
 * ============================================================================ */

extern HMODULE              g_hThisDll;
extern DWORD                g_dwCurrentPid;
extern BOOL                 g_bHooksInstalled;
extern std::atomic<bool>    g_bShutdown;

/* ============================================================================
 * Module-level function declarations
 * ============================================================================ */

/* hook_comm.cpp */
BOOL    HookComm_Initialize(DWORD pid);
void    HookComm_Shutdown();
BOOL    HookComm_SendEvent(const SENTINEL_MEMORY_EVENT* pEvent);

/* hook_engine.cpp */
BOOL    HookEngine_Initialize();
void    HookEngine_Shutdown();
BOOL    HookEngine_InstallHook(PVOID pTarget, PVOID pDetour, PVOID* ppOriginal);
BOOL    HookEngine_RemoveHook(PVOID pTarget);
void    HookEngine_RemoveAllHooks();

/* iat_hook.cpp */
BOOL    IAT_HookFunction(HMODULE hModule, const char* pszTargetDll, const char* pszTargetFunc,
                          PVOID pDetour, PVOID* ppOriginal);
BOOL    IAT_UnhookFunction(HMODULE hModule, const char* pszTargetDll, const char* pszTargetFunc,
                            PVOID pOriginal);

/* ntdll_hooks.cpp */
BOOL    NtdllHooks_Install();
void    NtdllHooks_Remove();

/* amsi_monitor.cpp */
BOOL    AmsiMonitor_Start();
void    AmsiMonitor_Stop();

/* etw_monitor.cpp */
BOOL    EtwMonitor_Start();
void    EtwMonitor_Stop();

/* veh_monitor.cpp */
BOOL    VehMonitor_Install();
void    VehMonitor_Remove();

/* memory_guard.cpp */
BOOL    MemoryGuard_Start();
void    MemoryGuard_Stop();

/* callstack_capture.cpp */
ULONG   CaptureCallstack(PVOID* pFrames, ULONG maxFrames);
BOOL    IsCallstackSuspicious(PVOID* pFrames, ULONG frameCount);
void    CallstackCache_Refresh();

/* token_scanner.cpp */
BOOL    TokenScanner_Start();
void    TokenScanner_Stop();

/* sleep_obfuscation_detect.cpp */
void    SleepDetect_RecordProtectEvent(PVOID baseAddress, ULONG newProtect);
BOOL    SleepDetect_Start();
void    SleepDetect_Stop();

/* pe_utils.cpp */
HMODULE PeUtils_GetModuleFromAddress(PVOID addr);
BOOL    PeUtils_IsAddressInModule(PVOID addr);
PVOID   PeUtils_GetExportAddress(HMODULE hMod, const char* pszName);
BOOL    PeUtils_ValidateModuleIntegrity(HMODULE hMod);

/* ============================================================================
 * Utility helpers
 * ============================================================================ */

/* Build a SENTINEL_MEMORY_EVENT with common fields filled in */
inline void BuildMemoryEvent(SENTINEL_MEMORY_EVENT* pEvent, SENTINEL_EVENT_TYPE type)
{
    ZeroMemory(pEvent, sizeof(*pEvent));
    pEvent->Header.Size = sizeof(SENTINEL_MEMORY_EVENT);
    pEvent->Header.Type = type;
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    pEvent->Header.Timestamp.LowPart = ft.dwLowDateTime;
    pEvent->Header.Timestamp.HighPart = ft.dwHighDateTime;
    pEvent->Header.ProcessId = GetCurrentProcessId();
    pEvent->Header.ThreadId = GetCurrentThreadId();
}

/* Check if a handle refers to the current process */
inline BOOL IsCurrentProcess(HANDLE hProcess)
{
    if (hProcess == reinterpret_cast<HANDLE>(-1) ||
        hProcess == GetCurrentProcess()) {
        return TRUE;
    }
    if (GetProcessId(hProcess) == GetCurrentProcessId()) {
        return TRUE;
    }
    return FALSE;
}

/* Safe swprintf wrapper */
inline void SafeDetail(WCHAR* dest, size_t destCount, const WCHAR* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(dest, destCount, _TRUNCATE, fmt, args);
    va_end(args);
}

#ifdef __cplusplus
}
#endif
