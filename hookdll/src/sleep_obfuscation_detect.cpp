/*
 * BludEDR - sleep_obfuscation_detect.cpp
 * Detects Ekko/Cronos/Foliage sleep obfuscation.
 *
 * Sleep obfuscation works by encrypting the implant's memory during Sleep():
 *   1. VirtualProtect to RW (to encrypt)
 *   2. Encrypt memory
 *   3. Sleep
 *   4. Decrypt memory
 *   5. VirtualProtect to RX (to execute again)
 *
 * Detection pattern: PAGE_EXECUTE_READ -> PAGE_READWRITE -> PAGE_EXECUTE_READ
 * on the same memory region in rapid succession (< 1 second).
 * If this pattern repeats 3+ times -> sleep obfuscation detected.
 */

#include "sleep_obfuscation_detect.h"
#include "hook_comm.h"

/* ============================================================================
 * Static state
 * ============================================================================ */

static RegionTracker    g_trackers[SLEEP_DETECT_MAX_REGIONS] = {};
static ULONG            g_trackerCount = 0;
static CRITICAL_SECTION g_sleepLock;
static volatile LONG    g_sleepInit = FALSE;
static HANDLE           g_hCheckThread = nullptr;
static std::atomic<bool> g_sleepRunning{false};
static HANDLE           g_sleepShutdownEvent = NULL;

/* ============================================================================
 * Internal: Find or create a tracker for a base address
 * ============================================================================ */
static RegionTracker* FindOrCreateTracker(PVOID baseAddress)
{
    /* Search existing */
    for (ULONG i = 0; i < g_trackerCount; i++) {
        if (g_trackers[i].baseAddress == baseAddress) {
            g_trackers[i].lastTick = GetTickCount64();
            return &g_trackers[i];
        }
    }

    /* Create new if space available */
    if (g_trackerCount < SLEEP_DETECT_MAX_REGIONS) {
        RegionTracker* t = &g_trackers[g_trackerCount++];
        ZeroMemory(t, sizeof(*t));
        t->baseAddress = baseAddress;
        t->lastTick = GetTickCount64();
        return t;
    }

    /* No space - LRU eviction: find tracker with oldest lastTick */
    DWORD oldestIdx = 0;
    ULONGLONG oldestTick = g_trackers[0].lastTick;
    for (DWORD j = 1; j < g_trackerCount; j++) {
        if (g_trackers[j].lastTick < oldestTick) {
            oldestTick = g_trackers[j].lastTick;
            oldestIdx = j;
        }
    }
    RegionTracker* t = &g_trackers[oldestIdx];
    ZeroMemory(t, sizeof(*t));
    t->baseAddress = baseAddress;
    t->lastTick = GetTickCount64();
    return t;
}

/* ============================================================================
 * Internal: Check a tracker for the sleep obfuscation pattern
 * Returns TRUE if pattern is detected.
 *
 * Pattern: RX -> RW -> RX within SLEEP_DETECT_WINDOW_MS, repeated 3+ times
 * ============================================================================ */
static BOOL CheckSleepPattern(const RegionTracker* t)
{
    if (t->count < 3) return FALSE;

    /* Walk the history looking for RX->RW->RX sequences */
    ULONG patternCount = 0;
    ULONG histCount = min(t->count, (ULONG)SLEEP_DETECT_HISTORY_SIZE);

    for (ULONG i = 2; i < histCount; i++) {
        ULONG idx0 = (t->writeIndex + SLEEP_DETECT_HISTORY_SIZE - histCount + i - 2) % SLEEP_DETECT_HISTORY_SIZE;
        ULONG idx1 = (t->writeIndex + SLEEP_DETECT_HISTORY_SIZE - histCount + i - 1) % SLEEP_DETECT_HISTORY_SIZE;
        ULONG idx2 = (t->writeIndex + SLEEP_DETECT_HISTORY_SIZE - histCount + i)     % SLEEP_DETECT_HISTORY_SIZE;

        const ProtectRecord& r0 = t->history[idx0];
        const ProtectRecord& r1 = t->history[idx1];
        const ProtectRecord& r2 = t->history[idx2];

        BOOL isRx0 = (r0.newProtect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
        BOOL isRw1 = (r1.newProtect == PAGE_READWRITE) || (r1.newProtect == PAGE_WRITECOPY);
        BOOL isRx2 = (r2.newProtect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;

        if (isRx0 && isRw1 && isRx2) {
            /* Check timing: all within the window */
            ULONGLONG span = r2.timestampMs - r0.timestampMs;
            if (span <= SLEEP_DETECT_WINDOW_MS) {
                patternCount++;
            }
        }
    }

    return patternCount >= SLEEP_DETECT_THRESHOLD;
}

/* ============================================================================
 * SleepDetect_RecordProtectEvent
 * Called from the NtProtectVirtualMemory hook for every protect change.
 * ============================================================================ */
void SleepDetect_RecordProtectEvent(PVOID baseAddress, ULONG newProtect)
{
    if (!InterlockedCompareExchange(&g_sleepInit, TRUE, TRUE)) return;

    EnterCriticalSection(&g_sleepLock);

    __try {
        RegionTracker* t = FindOrCreateTracker(baseAddress);

        /* Record the protect event */
        ProtectRecord rec;
        rec.newProtect = newProtect;
        rec.timestampMs = GetTickCount64();

        t->history[t->writeIndex] = rec;
        t->writeIndex = (t->writeIndex + 1) % SLEEP_DETECT_HISTORY_SIZE;
        if (t->count < SLEEP_DETECT_HISTORY_SIZE) {
            t->count++;
        }

        /* Check for pattern immediately */
        if (CheckSleepPattern(t)) {
            SENTINEL_MEMORY_EVENT evt;
            BuildMemoryEvent(&evt, EVENT_SLEEP_OBFUSCATION);
            evt.BaseAddress = baseAddress;
            evt.NewProtect = newProtect;
            evt.CallstackDepth = 0;

            SafeDetail(evt.Details, _countof(evt.Details),
                L"Sleep obfuscation detected on region 0x%p: repeated RX->RW->RX pattern (%lu cycles)",
                baseAddress, (ULONG)SLEEP_DETECT_THRESHOLD);

            HookComm_SendEvent(&evt);

            /* Reset tracker to avoid spamming */
            t->count = 0;
            t->writeIndex = 0;
            ZeroMemory(t->history, sizeof(t->history));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Never crash */
    }

    LeaveCriticalSection(&g_sleepLock);
}

/* ============================================================================
 * Background cleanup thread - prune stale trackers every 30 seconds
 * ============================================================================ */
static DWORD WINAPI SleepDetectCleanupThread(LPVOID /*param*/)
{
    while (g_sleepRunning.load()) {
        WaitForSingleObject(g_sleepShutdownEvent, 30000);
        if (!g_sleepRunning.load()) break;

        EnterCriticalSection(&g_sleepLock);

        ULONGLONG now = GetTickCount64();
        for (ULONG i = 0; i < g_trackerCount; /* no increment */) {
            RegionTracker* t = &g_trackers[i];

            /* Check if the most recent event is stale (> 30 seconds old) */
            BOOL stale = TRUE;
            for (ULONG j = 0; j < t->count && j < SLEEP_DETECT_HISTORY_SIZE; j++) {
                if ((now - t->history[j].timestampMs) < 30000) {
                    stale = FALSE;
                    break;
                }
            }

            if (stale && t->count > 0) {
                /* Remove by swapping with last */
                if (i < g_trackerCount - 1) {
                    g_trackers[i] = g_trackers[g_trackerCount - 1];
                }
                g_trackerCount--;
            } else {
                i++;
            }
        }

        LeaveCriticalSection(&g_sleepLock);
    }

    return 0;
}

/* ============================================================================
 * SleepDetect_Start
 * ============================================================================ */
BOOL SleepDetect_Start()
{
    if (InterlockedCompareExchange(&g_sleepInit, FALSE, FALSE)) return TRUE;

    InitializeCriticalSection(&g_sleepLock);
    ZeroMemory(g_trackers, sizeof(g_trackers));
    g_trackerCount = 0;

    g_sleepShutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    InterlockedExchange(&g_sleepInit, TRUE);

    g_sleepRunning.store(true);
    g_hCheckThread = CreateThread(nullptr, 0, SleepDetectCleanupThread, nullptr, 0, nullptr);
    /* Cleanup thread is optional; don't fail if it can't start */

    return TRUE;
}

/* ============================================================================
 * SleepDetect_Stop
 * ============================================================================ */
void SleepDetect_Stop()
{
    if (!InterlockedExchange(&g_sleepInit, FALSE)) return;

    g_sleepRunning.store(false);
    if (g_sleepShutdownEvent) SetEvent(g_sleepShutdownEvent);

    if (g_hCheckThread) {
        WaitForSingleObject(g_hCheckThread, 5000);
        CloseHandle(g_hCheckThread);
        g_hCheckThread = nullptr;
    }

    if (g_sleepShutdownEvent) {
        CloseHandle(g_sleepShutdownEvent);
        g_sleepShutdownEvent = NULL;
    }

    /* Small delay to let any in-flight RecordProtectEvent calls complete */
    Sleep(10);
    DeleteCriticalSection(&g_sleepLock);
}
