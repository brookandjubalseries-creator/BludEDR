/*
 * BludEDR - callstack_capture.cpp
 * Callstack capture and analysis.
 * Uses RtlCaptureStackBackTrace for fast capture and a cached module list
 * to determine if any return address is outside a loaded module (unbacked).
 */

#include "callstack_capture.h"

/* ============================================================================
 * Module cache
 * ============================================================================ */

static std::vector<ModuleRange>     g_moduleCache;
static CRITICAL_SECTION             g_moduleCacheLock;
static volatile ULONGLONG           g_lastRefreshTick = 0;
static BOOL                         g_cacheInit = FALSE;

/* ============================================================================
 * Internal: Refresh the module cache
 * ============================================================================ */
static void RefreshModuleCache()
{
    ULONGLONG now = GetTickCount64();
    if (g_lastRefreshTick != 0 && (now - g_lastRefreshTick) < CALLSTACK_MODULE_CACHE_INTERVAL)
        return;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                            GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE)
        return;

    std::vector<ModuleRange> newCache;
    newCache.reserve(128);

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);

    if (Module32FirstW(hSnap, &me)) {
        do {
            ModuleRange range;
            range.baseAddress = me.modBaseAddr;
            range.size = me.modBaseSize;
            newCache.push_back(range);
        } while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);

    /* Sort by base address for binary search */
    std::sort(newCache.begin(), newCache.end(),
        [](const ModuleRange& a, const ModuleRange& b) {
            return reinterpret_cast<ULONG_PTR>(a.baseAddress) <
                   reinterpret_cast<ULONG_PTR>(b.baseAddress);
        });

    EnterCriticalSection(&g_moduleCacheLock);
    g_moduleCache = std::move(newCache);
    g_lastRefreshTick = now;
    LeaveCriticalSection(&g_moduleCacheLock);
}

/* ============================================================================
 * Internal: Initialize cache lock if needed
 * ============================================================================ */
static void EnsureCacheInit()
{
    if (!g_cacheInit) {
        InitializeCriticalSection(&g_moduleCacheLock);
        g_cacheInit = TRUE;
        RefreshModuleCache();
    }
}

/* ============================================================================
 * Internal: Is an address within any cached module?
 * ============================================================================ */
static BOOL IsAddressInCachedModules(PVOID addr)
{
    ULONG_PTR target = reinterpret_cast<ULONG_PTR>(addr);

    EnterCriticalSection(&g_moduleCacheLock);

    /* Binary search for the module containing this address */
    int lo = 0;
    int hi = static_cast<int>(g_moduleCache.size()) - 1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        ULONG_PTR base = reinterpret_cast<ULONG_PTR>(g_moduleCache[mid].baseAddress);
        ULONG_PTR end = base + g_moduleCache[mid].size;

        if (target < base) {
            hi = mid - 1;
        } else if (target >= end) {
            lo = mid + 1;
        } else {
            LeaveCriticalSection(&g_moduleCacheLock);
            return TRUE;
        }
    }

    LeaveCriticalSection(&g_moduleCacheLock);
    return FALSE;
}

/* ============================================================================
 * CaptureCallstack
 * ============================================================================ */
ULONG CaptureCallstack(PVOID* pFrames, ULONG maxFrames)
{
    if (!pFrames || maxFrames == 0) return 0;

    EnsureCacheInit();

    /* Skip 1 frame (this function itself) */
    ULONG captured = RtlCaptureStackBackTrace(1, maxFrames, pFrames, nullptr);
    return captured;
}

/* ============================================================================
 * IsCallstackSuspicious
 * Returns TRUE if any frame is NOT within a loaded module (unbacked memory).
 * This is a strong indicator of shellcode execution.
 * ============================================================================ */
BOOL IsCallstackSuspicious(PVOID* pFrames, ULONG frameCount)
{
    if (!pFrames || frameCount == 0) return FALSE;

    EnsureCacheInit();
    RefreshModuleCache();

    for (ULONG i = 0; i < frameCount; i++) {
        if (pFrames[i] == nullptr) continue;

        if (!IsAddressInCachedModules(pFrames[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

/* ============================================================================
 * CallstackCache_Refresh
 * Force a refresh of the module cache (called periodically by monitors).
 * ============================================================================ */
void CallstackCache_Refresh()
{
    EnsureCacheInit();
    g_lastRefreshTick = 0; /* Force refresh on next call */
    RefreshModuleCache();
}
