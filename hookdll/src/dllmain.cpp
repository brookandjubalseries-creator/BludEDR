/*
 * BludEDR - dllmain.cpp
 * Hook DLL entry point.
 *
 * Made by @tarry
 *
 * DLL_PROCESS_ATTACH:
 *   1. Skip system-critical processes (csrss, smss, lsass, services, svchost)
 *   2. Initialize hook communication pipe to the BludEDR agent
 *   3. Initialize the hook engine
 *   4. Install all ntdll inline hooks
 *   5. Install VEH monitor hook
 *   6. Start monitoring threads: AMSI, ETW, memory guard, token scanner, sleep detect
 *
 * DLL_PROCESS_DETACH:
 *   1. Signal shutdown to all threads
 *   2. Stop all monitors
 *   3. Remove all hooks
 *   4. Close the communication pipe
 */

#include "../inc/hookdll.h"
#include "hook_engine.h"
#include "hook_comm.h"
#include "ntdll_hooks.h"
#include "amsi_monitor.h"
#include "etw_monitor.h"
#include "veh_monitor.h"
#include "memory_guard.h"
#include "callstack_capture.h"
#include "token_scanner.h"
#include "sleep_obfuscation_detect.h"

/* ============================================================================
 * Global state definitions
 * ============================================================================ */
HMODULE             g_hThisDll          = nullptr;
DWORD               g_dwCurrentPid      = 0;
BOOL                g_bHooksInstalled   = FALSE;
std::atomic<bool>   g_bShutdown{false};

/* ============================================================================
 * System-critical process names to skip hooking
 * ============================================================================ */
static const WCHAR* g_systemProcesses[] = {
    L"csrss.exe",
    L"smss.exe",
    L"lsass.exe",
    L"services.exe",
    L"svchost.exe",
    L"wininit.exe",
    L"winlogon.exe",
    L"dwm.exe",
    L"fontdrvhost.exe",
    L"System",
};
static constexpr DWORD NUM_SYSTEM_PROCESSES = sizeof(g_systemProcesses) / sizeof(g_systemProcesses[0]);

/* ============================================================================
 * IsSystemCriticalProcess
 * Returns TRUE if the current process should NOT be hooked.
 * ============================================================================ */
static BOOL IsSystemCriticalProcess()
{
    WCHAR exePath[MAX_PATH] = {};
    DWORD len = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (len == 0) return TRUE; /* Can't determine - be safe */

    /* Extract just the filename */
    const WCHAR* pFileName = exePath;
    for (DWORD i = len; i > 0; i--) {
        if (exePath[i - 1] == L'\\' || exePath[i - 1] == L'/') {
            pFileName = &exePath[i];
            break;
        }
    }

    /* Check against system process list */
    for (DWORD i = 0; i < NUM_SYSTEM_PROCESSES; i++) {
        if (_wcsicmp(pFileName, g_systemProcesses[i]) == 0) {
            return TRUE;
        }
    }

    /* Also skip our own agent process */
    if (_wcsicmp(pFileName, L"BludAgent.exe") == 0 ||
        _wcsicmp(pFileName, L"BludEDR.exe") == 0) {
        return TRUE;
    }

    /* Skip PID 0 and PID 4 (System) */
    DWORD pid = GetCurrentProcessId();
    if (pid == 0 || pid == 4) return TRUE;

    return FALSE;
}

/* ============================================================================
 * InitializeHooks - called from DLL_PROCESS_ATTACH
 * ============================================================================ */
static BOOL InitializeHooks()
{
    g_dwCurrentPid = GetCurrentProcessId();

    /* Step 1: Check if we should skip this process */
    if (IsSystemCriticalProcess()) {
        return FALSE; /* Signal that we don't want to stay loaded */
    }

    /* Step 2: Initialize communication pipe */
    if (!HookComm_Initialize(g_dwCurrentPid)) {
        /* Non-fatal: hooks still work, events will be buffered */
    }

    /* Step 3: Initialize hook engine */
    if (!HookEngine_Initialize()) {
        HookComm_Shutdown();
        return FALSE;
    }

    /* Step 4: Start sleep obfuscation detector (must be before ntdll hooks) */
    SleepDetect_Start();

    /* Step 5: Install ntdll hooks */
    BOOL ntdllOk = NtdllHooks_Install();
    /* Even if some hooks fail, continue with the ones that succeeded */

    /* Step 6: Install VEH monitor hook */
    VehMonitor_Install();

    /* Step 7: Start AMSI integrity monitor */
    AmsiMonitor_Start();

    /* Step 8: Start ETW integrity monitor */
    EtwMonitor_Start();

    /* Step 9: Start memory guard scanner */
    MemoryGuard_Start();

    /* Step 10: Start token scanner */
    TokenScanner_Start();

    g_bHooksInstalled = TRUE;

    /* Send an initial event to indicate successful hook installation */
    {
        SENTINEL_MEMORY_EVENT evt;
        BuildMemoryEvent(&evt, EVENT_MEMORY_ALLOC);
        evt.BaseAddress = reinterpret_cast<PVOID>(g_hThisDll);
        evt.RegionSize = 0;
        SafeDetail(evt.Details, _countof(evt.Details),
            L"BludEDR hook DLL loaded in PID %lu, ntdll hooks: %s",
            g_dwCurrentPid, ntdllOk ? L"ALL OK" : L"PARTIAL");
        HookComm_SendEvent(&evt);
    }

    return TRUE;
}

/* ============================================================================
 * ShutdownHooks - called from DLL_PROCESS_DETACH
 * ============================================================================ */
static void ShutdownHooks()
{
    if (!g_bHooksInstalled) return;

    /* Signal all threads to stop */
    g_bShutdown.store(true);

    /* Stop monitors (these have background threads) */
    TokenScanner_Stop();
    MemoryGuard_Stop();
    EtwMonitor_Stop();
    AmsiMonitor_Stop();
    SleepDetect_Stop();

    /* Remove hooks */
    VehMonitor_Remove();
    NtdllHooks_Remove();

    /* Shutdown hook engine (removes any remaining hooks) */
    HookEngine_Shutdown();

    /* Close pipe */
    HookComm_Shutdown();

    g_bHooksInstalled = FALSE;
}

/* ============================================================================
 * DllMain
 * ============================================================================ */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        g_hThisDll = hModule;

        /* Disable thread attach/detach notifications for performance */
        DisableThreadLibraryCalls(hModule);

        /* Initialize all hooks and monitors */
        if (!InitializeHooks()) {
            /* Return FALSE to indicate we don't want to be loaded in this process.
             * However, if the agent explicitly injected us, returning FALSE
             * might cause issues. So we still return TRUE but just don't hook. */
            return TRUE;
        }
        break;

    case DLL_PROCESS_DETACH:
        /* lpReserved != NULL means process is terminating.
         * In that case, skip cleanup to avoid potential deadlocks. */
        if (lpReserved == nullptr) {
            ShutdownHooks();
        }
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        /* Disabled via DisableThreadLibraryCalls */
        break;
    }

    return TRUE;
}
