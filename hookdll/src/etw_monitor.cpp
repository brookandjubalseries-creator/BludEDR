/*
 * BludEDR - etw_monitor.cpp
 * Periodic integrity checker for ETW functions.
 *
 * Monitors:
 *   - ntdll!EtwEventWrite
 *   - ntdll!NtTraceEvent
 * Detects the same bypass patterns as the AMSI monitor.
 */

#include "etw_monitor.h"
#include "hook_comm.h"

/* ============================================================================
 * Static state
 * ============================================================================ */

struct EtwTarget {
    const char* funcName;
    PVOID       pFunction;
    BYTE        snapshot[ETW_PROLOGUE_SIZE];
    BOOL        valid;
    BOOL        reported;
};

static EtwTarget g_etwTargets[2] = {
    { "EtwEventWrite", nullptr, {}, FALSE, FALSE },
    { "NtTraceEvent",  nullptr, {}, FALSE, FALSE },
};

static HANDLE               g_hMonitorThread = nullptr;
static std::atomic<bool>    g_etwRunning{false};
static HANDLE               g_etwShutdownEvent = NULL;

/* ============================================================================
 * Internal: Check for known bypass patterns
 * ============================================================================ */
static BOOL DetectEtwBypassPattern(const BYTE* current, const BYTE* original,
                                    const char* funcName,
                                    WCHAR* detailOut, size_t detailSize)
{
    /* RET */
    if (current[0] == 0xC3) {
        SafeDetail(detailOut, detailSize, L"%S patched with RET (0xC3)", funcName);
        return TRUE;
    }

    /* NOP sled */
    if (current[0] == 0x90 && current[1] == 0x90 && current[2] == 0x90 && current[3] == 0x90) {
        SafeDetail(detailOut, detailSize, L"%S patched with NOP sled", funcName);
        return TRUE;
    }

    /* XOR EAX, EAX; RET */
    if ((current[0] == 0x31 && current[1] == 0xC0 && current[2] == 0xC3) ||
        (current[0] == 0x33 && current[1] == 0xC0 && current[2] == 0xC3)) {
        SafeDetail(detailOut, detailSize, L"%S patched with XOR EAX,EAX; RET", funcName);
        return TRUE;
    }

    /* MOV EAX, imm32; RET */
    if (current[0] == 0xB8 && current[5] == 0xC3) {
        DWORD value = *reinterpret_cast<const DWORD*>(current + 1);
        SafeDetail(detailOut, detailSize,
            L"%S patched with MOV EAX, 0x%08lX; RET", funcName, value);
        return TRUE;
    }

    /* Generic change detection */
    if (memcmp(current, original, ETW_PROLOGUE_SIZE) != 0) {
        for (int i = 0; i < ETW_PROLOGUE_SIZE; i++) {
            if (current[i] != original[i]) {
                SafeDetail(detailOut, detailSize,
                    L"%S modified at offset %d: expected 0x%02X, found 0x%02X",
                    funcName, i, original[i], current[i]);
                return TRUE;
            }
        }
    }

    return FALSE;
}

/* ============================================================================
 * Monitor thread
 * ============================================================================ */
static DWORD WINAPI EtwMonitorThread(LPVOID /*param*/)
{
    while (g_etwRunning.load()) {
        WaitForSingleObject(g_etwShutdownEvent, ETW_CHECK_INTERVAL);

        if (!g_etwRunning.load()) break;

        for (int i = 0; i < 2; i++) {
            if (!g_etwTargets[i].valid || !g_etwTargets[i].pFunction)
                continue;

            __try {
                BYTE current[ETW_PROLOGUE_SIZE];
                memcpy(current, g_etwTargets[i].pFunction, ETW_PROLOGUE_SIZE);

                if (memcmp(current, g_etwTargets[i].snapshot, ETW_PROLOGUE_SIZE) != 0) {
                    if (!g_etwTargets[i].reported) {
                        WCHAR details[256] = {};
                        if (DetectEtwBypassPattern(current, g_etwTargets[i].snapshot,
                                                   g_etwTargets[i].funcName,
                                                   details, _countof(details))) {
                            SENTINEL_MEMORY_EVENT evt;
                            BuildMemoryEvent(&evt, EVENT_ETW_BYPASS);
                            evt.BaseAddress = g_etwTargets[i].pFunction;
                            evt.RegionSize = ETW_PROLOGUE_SIZE;
                            evt.CallstackDepth = 0;
                            wcsncpy_s(evt.Details, details, _TRUNCATE);

                            HookComm_SendEvent(&evt);
                            g_etwTargets[i].reported = TRUE;
                        }
                    }
                    /* Do NOT update snapshot - keep original baseline */
                } else {
                    g_etwTargets[i].reported = FALSE; /* bytes restored */
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                g_etwTargets[i].valid = FALSE;
            }
        }
    }

    return 0;
}

/* ============================================================================
 * EtwMonitor_Start
 * ============================================================================ */
BOOL EtwMonitor_Start()
{
    if (g_etwRunning.load()) return TRUE;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    /* Resolve ETW functions */
    g_etwTargets[0].pFunction = reinterpret_cast<PVOID>(
        GetProcAddress(hNtdll, "EtwEventWrite"));
    g_etwTargets[1].pFunction = reinterpret_cast<PVOID>(
        GetProcAddress(hNtdll, "NtTraceEvent"));

    /* Snapshot prologues */
    for (int i = 0; i < 2; i++) {
        if (g_etwTargets[i].pFunction) {
            __try {
                memcpy(g_etwTargets[i].snapshot, g_etwTargets[i].pFunction, ETW_PROLOGUE_SIZE);
                g_etwTargets[i].valid = TRUE;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                g_etwTargets[i].valid = FALSE;
            }
        }
    }

    g_etwShutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_etwRunning.store(true);
    g_hMonitorThread = CreateThread(nullptr, 0, EtwMonitorThread, nullptr, 0, nullptr);
    if (!g_hMonitorThread) {
        g_etwRunning.store(false);
        CloseHandle(g_etwShutdownEvent);
        g_etwShutdownEvent = NULL;
        return FALSE;
    }

    return TRUE;
}

/* ============================================================================
 * EtwMonitor_Stop
 * ============================================================================ */
void EtwMonitor_Stop()
{
    if (!g_etwRunning.load()) return;

    g_etwRunning.store(false);
    if (g_etwShutdownEvent) SetEvent(g_etwShutdownEvent);

    if (g_hMonitorThread) {
        WaitForSingleObject(g_hMonitorThread, 5000);
        CloseHandle(g_hMonitorThread);
        g_hMonitorThread = nullptr;
    }

    if (g_etwShutdownEvent) {
        CloseHandle(g_etwShutdownEvent);
        g_etwShutdownEvent = NULL;
    }
}
