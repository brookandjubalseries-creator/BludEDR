/*
 * BludEDR - veh_monitor.cpp
 * Hook for AddVectoredExceptionHandler to monitor VEH registrations.
 *
 * Flags suspicious registrations:
 *   - Handler address in heap/stack (not backed by a loaded module)
 *   - Registration after process initialization phase
 */

#include "veh_monitor.h"
#include "hook_engine.h"
#include "hook_comm.h"
#include "callstack_capture.h"
#include "pe_utils.h"

/* ============================================================================
 * State
 * ============================================================================ */

pfnAddVectoredExceptionHandler g_pOrigAddVectoredExceptionHandler = nullptr;
static PVOID s_hookedTarget = nullptr;

/* Track process init phase: we consider the first 5 seconds after DLL load as "init" */
static ULONGLONG g_initTimestamp = 0;
static constexpr ULONGLONG INIT_PHASE_MS = 5000;

/* ============================================================================
 * Detour
 * ============================================================================ */
static PVOID WINAPI Detour_AddVectoredExceptionHandler(
    ULONG First,
    PVECTORED_EXCEPTION_HANDLER Handler)
{
    /* Call original */
    PVOID result = g_pOrigAddVectoredExceptionHandler(First, Handler);

    __try {
        BOOL isSuspicious = FALSE;
        WCHAR moduleName[MAX_PATH] = L"<unknown>";

        /* Check if handler is within a loaded module */
        HMODULE hHandlerMod = PeUtils_GetModuleFromAddress(reinterpret_cast<PVOID>(Handler));
        if (hHandlerMod) {
            GetModuleFileNameW(hHandlerMod, moduleName, MAX_PATH);
        } else {
            /* Handler is NOT in any loaded module -> very suspicious (heap/stack shellcode) */
            isSuspicious = TRUE;
            wcscpy_s(moduleName, L"<unbacked memory>");
        }

        /* Check if we're past the initialization phase */
        ULONGLONG now = GetTickCount64();
        BOOL pastInit = (now - g_initTimestamp) > INIT_PHASE_MS;
        if (pastInit && hHandlerMod == nullptr) {
            isSuspicious = TRUE;
        }

        /* Log all VEH registrations, flag suspicious ones */
        SENTINEL_MEMORY_EVENT evt;
        BuildMemoryEvent(&evt, EVENT_VEH_INSTALL);
        evt.BaseAddress = reinterpret_cast<PVOID>(Handler);
        evt.RegionSize = 0;
        evt.CallstackDepth = CaptureCallstack(evt.Callstack, SENTINEL_MAX_CALLSTACK);

        if (isSuspicious) {
            SafeDetail(evt.Details, _countof(evt.Details),
                L"[SUSPICIOUS] VEH handler registered at 0x%p, module=%s, first=%lu, post-init=%s",
                Handler, moduleName, First, pastInit ? L"YES" : L"NO");
        } else {
            SafeDetail(evt.Details, _countof(evt.Details),
                L"VEH handler registered at 0x%p, module=%s, first=%lu",
                Handler, moduleName, First);
        }

        HookComm_SendEvent(&evt);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Never crash */
    }

    return result;
}

/* ============================================================================
 * VehMonitor_Install
 * ============================================================================ */
BOOL VehMonitor_Install()
{
    g_initTimestamp = GetTickCount64();

    /* AddVectoredExceptionHandler is in kernelbase.dll on modern Windows,
       fallback to kernel32.dll */
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    PVOID pTarget = nullptr;

    if (hKernelBase) {
        pTarget = reinterpret_cast<PVOID>(
            GetProcAddress(hKernelBase, "AddVectoredExceptionHandler"));
    }

    if (!pTarget) {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32) {
            pTarget = reinterpret_cast<PVOID>(
                GetProcAddress(hKernel32, "AddVectoredExceptionHandler"));
        }
    }

    if (!pTarget) return FALSE;

    s_hookedTarget = pTarget;

    return HookEngine_InstallHook(
        pTarget,
        reinterpret_cast<PVOID>(&Detour_AddVectoredExceptionHandler),
        reinterpret_cast<PVOID*>(&g_pOrigAddVectoredExceptionHandler));
}

/* ============================================================================
 * VehMonitor_Remove
 * ============================================================================ */
void VehMonitor_Remove()
{
    if (s_hookedTarget) {
        HookEngine_RemoveHook(s_hookedTarget);
        s_hookedTarget = nullptr;
    }

    g_pOrigAddVectoredExceptionHandler = nullptr;
}
