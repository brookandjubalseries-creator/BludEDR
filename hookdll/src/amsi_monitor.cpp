/*
 * BludEDR - amsi_monitor.cpp
 * Periodic integrity checker for AmsiScanBuffer.
 *
 * Snapshots the first 16 bytes of amsi.dll!AmsiScanBuffer at init time,
 * then checks every 500ms for known bypass patterns:
 *   - 0xC3 (RET)
 *   - 0x90909090 (NOP sled)
 *   - 0x31C0C3 (XOR EAX,EAX; RET) or 0x33C0C3 (XOR EAX,EAX; RET alt)
 *   - 0xB8 followed by specific return values
 */

#include "amsi_monitor.h"
#include "hook_comm.h"

/* ============================================================================
 * Static state
 * ============================================================================ */
static BYTE         g_amsiSnapshot[AMSI_PROLOGUE_SIZE] = {};
static PVOID        g_pAmsiScanBuffer = nullptr;
static HANDLE       g_hMonitorThread = nullptr;
static std::atomic<bool> g_amsiRunning{false};
static BOOL         g_amsiPatchReported = FALSE;
static HANDLE       g_amsiShutdownEvent = NULL;

/* ============================================================================
 * Internal: Check for known bypass patterns
 * ============================================================================ */
static BOOL DetectBypassPattern(const BYTE* current, const BYTE* original, WCHAR* detailOut, size_t detailSize)
{
    /* 1. Simple RET at start */
    if (current[0] == 0xC3) {
        SafeDetail(detailOut, detailSize, L"AmsiScanBuffer patched with RET (0xC3) at offset 0");
        return TRUE;
    }

    /* 2. NOP sled (4+ NOPs) */
    if (current[0] == 0x90 && current[1] == 0x90 && current[2] == 0x90 && current[3] == 0x90) {
        SafeDetail(detailOut, detailSize, L"AmsiScanBuffer patched with NOP sled");
        return TRUE;
    }

    /* 3. XOR EAX, EAX; RET (return AMSI_RESULT_CLEAN) */
    if ((current[0] == 0x31 && current[1] == 0xC0 && current[2] == 0xC3) ||
        (current[0] == 0x33 && current[1] == 0xC0 && current[2] == 0xC3)) {
        SafeDetail(detailOut, detailSize, L"AmsiScanBuffer patched with XOR EAX,EAX; RET");
        return TRUE;
    }

    /* 4. MOV EAX, imm32; RET (0xB8 xx xx xx xx C3) */
    if (current[0] == 0xB8 && current[5] == 0xC3) {
        DWORD value = *reinterpret_cast<const DWORD*>(current + 1);
        SafeDetail(detailOut, detailSize,
            L"AmsiScanBuffer patched with MOV EAX, 0x%08lX; RET", value);
        return TRUE;
    }

    /* 5. Generic: first byte changed from original (catch-all) */
    if (memcmp(current, original, AMSI_PROLOGUE_SIZE) != 0) {
        /* Find first differing byte */
        for (int i = 0; i < AMSI_PROLOGUE_SIZE; i++) {
            if (current[i] != original[i]) {
                SafeDetail(detailOut, detailSize,
                    L"AmsiScanBuffer modified at offset %d: expected 0x%02X, found 0x%02X",
                    i, original[i], current[i]);
                return TRUE;
            }
        }
    }

    return FALSE;
}

/* ============================================================================
 * Monitor thread
 * ============================================================================ */
static DWORD WINAPI AmsiMonitorThread(LPVOID /*param*/)
{
    while (g_amsiRunning.load()) {
        WaitForSingleObject(g_amsiShutdownEvent, AMSI_CHECK_INTERVAL);

        if (!g_amsiRunning.load()) break;
        if (!g_pAmsiScanBuffer) continue;

        __try {
            BYTE current[AMSI_PROLOGUE_SIZE];
            memcpy(current, g_pAmsiScanBuffer, AMSI_PROLOGUE_SIZE);

            if (memcmp(current, g_amsiSnapshot, AMSI_PROLOGUE_SIZE) != 0) {
                if (!g_amsiPatchReported) {
                    WCHAR details[256] = {};
                    if (DetectBypassPattern(current, g_amsiSnapshot, details, _countof(details))) {
                        SENTINEL_MEMORY_EVENT evt;
                        BuildMemoryEvent(&evt, EVENT_AMSI_BYPASS);
                        evt.BaseAddress = g_pAmsiScanBuffer;
                        evt.RegionSize = AMSI_PROLOGUE_SIZE;
                        evt.CallstackDepth = 0;
                        wcsncpy_s(evt.Details, details, _TRUNCATE);

                        HookComm_SendEvent(&evt);
                        g_amsiPatchReported = TRUE;
                    }
                }
                /* Do NOT update g_amsiSnapshot - keep original baseline */
            } else {
                g_amsiPatchReported = FALSE; /* bytes restored, allow re-detection */
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* amsi.dll may have been unloaded */
            g_pAmsiScanBuffer = nullptr;
        }
    }

    return 0;
}

/* ============================================================================
 * AmsiMonitor_Start
 * ============================================================================ */
BOOL AmsiMonitor_Start()
{
    if (g_amsiRunning.load()) return TRUE;

    /* amsi.dll may not be loaded yet - that's OK, we'll check periodically */
    HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
    if (!hAmsi) {
        /* Try to load it - many processes will load it later */
        hAmsi = LoadLibraryW(L"amsi.dll");
    }

    if (hAmsi) {
        g_pAmsiScanBuffer = reinterpret_cast<PVOID>(
            GetProcAddress(hAmsi, "AmsiScanBuffer"));

        if (g_pAmsiScanBuffer) {
            __try {
                memcpy(g_amsiSnapshot, g_pAmsiScanBuffer, AMSI_PROLOGUE_SIZE);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                g_pAmsiScanBuffer = nullptr;
            }
        }
    }

    g_amsiShutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_amsiShutdownEvent) {
        return FALSE;
    }

    g_amsiRunning.store(true);
    g_hMonitorThread = CreateThread(nullptr, 0, AmsiMonitorThread, nullptr, 0, nullptr);
    if (!g_hMonitorThread) {
        g_amsiRunning.store(false);
        CloseHandle(g_amsiShutdownEvent);
        g_amsiShutdownEvent = NULL;
        return FALSE;
    }

    return TRUE;
}

/* ============================================================================
 * AmsiMonitor_Stop
 * ============================================================================ */
void AmsiMonitor_Stop()
{
    if (!g_amsiRunning.load()) return;

    g_amsiRunning.store(false);
    if (g_amsiShutdownEvent) SetEvent(g_amsiShutdownEvent);

    if (g_hMonitorThread) {
        WaitForSingleObject(g_hMonitorThread, 5000);
        CloseHandle(g_hMonitorThread);
        g_hMonitorThread = nullptr;
    }

    if (g_amsiShutdownEvent) {
        CloseHandle(g_amsiShutdownEvent);
        g_amsiShutdownEvent = NULL;
    }

    g_pAmsiScanBuffer = nullptr;
    g_amsiPatchReported = FALSE;
}
