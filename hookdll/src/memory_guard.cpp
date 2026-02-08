/*
 * BludEDR - memory_guard.cpp
 * Periodic memory scanner (every 2 seconds).
 *
 * Walks process memory with VirtualQuery, flags MEM_PRIVATE + PAGE_EXECUTE_READWRITE
 * regions, then scans for:
 *   - Shellcode signatures (CLD+CALL+POP, syscall stubs, PEB walking)
 *   - AES SubBytes table (S-box) constants
 */

#include "memory_guard.h"
#include "hook_comm.h"

/* ============================================================================
 * Shellcode and crypto signatures
 * ============================================================================ */

/* PEB walking via GS segment: GS:[0x60]
 * 65 48 8B 04 25 60 00 00 00  =>  mov rax, gs:[60h] */
static const BYTE SIG_PEB_WALK[] = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 };
static constexpr SIZE_T SIG_PEB_WALK_LEN = sizeof(SIG_PEB_WALK);

/* Syscall instruction: 0F 05 */
static const BYTE SIG_SYSCALL[] = { 0x0F, 0x05 };
static constexpr SIZE_T SIG_SYSCALL_LEN = sizeof(SIG_SYSCALL);

/* AES S-box first 16 bytes */
static const BYTE SIG_AES_SBOX[] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
};
static constexpr SIZE_T SIG_AES_SBOX_LEN = sizeof(SIG_AES_SBOX);

/* POP registers after CALL (used with CLD+CALL+POP pattern) */
static const BYTE POP_REGS[] = { 0x58, 0x59, 0x5A, 0x5B, 0x5E, 0x5F };

/* ============================================================================
 * Static state
 * ============================================================================ */

static HANDLE               g_hScanThread = nullptr;
static std::atomic<bool>    g_memGuardRunning{false};
static HANDLE               g_memGuardShutdownEvent = NULL;

/* Track already-reported regions to avoid spamming */
static std::unordered_map<ULONG_PTR, ULONGLONG>* g_pReportedRegions = nullptr;
static CRITICAL_SECTION g_reportedLock;
static constexpr ULONGLONG REPORT_COOLDOWN_MS = 60000; /* Re-report after 60s */

/* ============================================================================
 * Internal: Search for a byte pattern in a memory region
 * ============================================================================ */
static BOOL FindPattern(const BYTE* pRegion, SIZE_T regionSize,
                        const BYTE* pattern, SIZE_T patternLen)
{
    if (regionSize < patternLen) return FALSE;

    SIZE_T limit = regionSize - patternLen;
    for (SIZE_T i = 0; i <= limit; i++) {
        if (memcmp(pRegion + i, pattern, patternLen) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ============================================================================
 * Internal: Detect CLD (0xFC) + CALL (0xE8) + POP reg pattern
 * This is a classic shellcode pattern: CLD; CALL $+5; POP <reg>
 * ============================================================================ */
static BOOL FindCldCallPop(const BYTE* pRegion, SIZE_T regionSize)
{
    if (regionSize < 8) return FALSE;

    SIZE_T limit = regionSize - 8;
    for (SIZE_T i = 0; i <= limit; i++) {
        if (pRegion[i] == 0xFC && pRegion[i + 1] == 0xE8) {
            /* CLD + CALL found, check if POP follows at CALL target */
            /* CALL rel32 is 5 bytes: E8 xx xx xx xx
             * The pattern CLD; CALL $+5; POP => FC E8 00 00 00 00 5x */
            SIZE_T afterCall = i + 1 + 5; /* skip E8 + 4-byte offset */
            if (afterCall < regionSize) {
                for (BYTE popReg : POP_REGS) {
                    if (pRegion[afterCall] == popReg) {
                        return TRUE;
                    }
                }
            }
        }
    }
    return FALSE;
}

/* ============================================================================
 * Internal: Check if a region should be reported
 * ============================================================================ */
static BOOL ShouldReport(ULONG_PTR baseAddr)
{
    ULONGLONG now = GetTickCount64();
    BOOL report = FALSE;

    EnterCriticalSection(&g_reportedLock);

    auto it = g_pReportedRegions->find(baseAddr);
    if (it == g_pReportedRegions->end()) {
        g_pReportedRegions->insert({ baseAddr, now });
        report = TRUE;
    } else if ((now - it->second) >= REPORT_COOLDOWN_MS) {
        it->second = now;
        report = TRUE;
    }

    LeaveCriticalSection(&g_reportedLock);
    return report;
}

/* ============================================================================
 * Scan thread
 * ============================================================================ */
static DWORD WINAPI MemoryGuardThread(LPVOID /*param*/)
{
    while (g_memGuardRunning.load()) {
        WaitForSingleObject(g_memGuardShutdownEvent, MEMGUARD_SCAN_INTERVAL);

        if (!g_memGuardRunning.load()) break;

        __try {
            SYSTEM_INFO si;
            GetSystemInfo(&si);

            ULONG_PTR addr = reinterpret_cast<ULONG_PTR>(si.lpMinimumApplicationAddress);
            ULONG_PTR maxAddr = reinterpret_cast<ULONG_PTR>(si.lpMaximumApplicationAddress);

            while (addr < maxAddr && g_memGuardRunning.load()) {
                MEMORY_BASIC_INFORMATION mbi = {};
                SIZE_T result = VirtualQuery(
                    reinterpret_cast<PVOID>(addr), &mbi, sizeof(mbi));

                if (result == 0) break;

                /* Guard against zero RegionSize to prevent infinite loop */
                if (mbi.RegionSize == 0) {
                    addr += 0x1000;
                    continue;
                }

                /* Look for MEM_PRIVATE + PAGE_EXECUTE_READWRITE */
                if (mbi.State == MEM_COMMIT &&
                    mbi.Type == MEM_PRIVATE &&
                    mbi.Protect == PAGE_EXECUTE_READWRITE &&
                    mbi.RegionSize > 0 &&
                    mbi.RegionSize <= 64 * 1024 * 1024) /* Skip absurdly large regions */
                {
                    ULONG_PTR baseAddr = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);

                    if (ShouldReport(baseAddr)) {
                        /* Build base event for RWX region */
                        SENTINEL_MEMORY_EVENT evt;
                        BuildMemoryEvent(&evt, EVENT_MEMORY_ALLOC);
                        evt.BaseAddress = mbi.BaseAddress;
                        evt.RegionSize = mbi.RegionSize;
                        evt.NewProtect = PAGE_EXECUTE_READWRITE;
                        evt.CallstackDepth = 0;

                        /* Scan for signatures */
                        const BYTE* pRegion = static_cast<const BYTE*>(mbi.BaseAddress);
                        SIZE_T regionSize = mbi.RegionSize;

                        BOOL hasCldCallPop = FindCldCallPop(pRegion, regionSize);
                        BOOL hasSyscall = FindPattern(pRegion, regionSize, SIG_SYSCALL, SIG_SYSCALL_LEN);
                        BOOL hasPebWalk = FindPattern(pRegion, regionSize, SIG_PEB_WALK, SIG_PEB_WALK_LEN);
                        BOOL hasAesSbox = FindPattern(pRegion, regionSize, SIG_AES_SBOX, SIG_AES_SBOX_LEN);

                        if (hasCldCallPop || hasSyscall || hasPebWalk || hasAesSbox) {
                            SafeDetail(evt.Details, _countof(evt.Details),
                                L"RWX region at 0x%p (0x%llX bytes): %s%s%s%s",
                                mbi.BaseAddress, (ULONGLONG)mbi.RegionSize,
                                hasCldCallPop ? L"[CLD+CALL+POP] " : L"",
                                hasSyscall ? L"[SYSCALL] " : L"",
                                hasPebWalk ? L"[PEB_WALK] " : L"",
                                hasAesSbox ? L"[AES_SBOX] " : L"");
                        } else {
                            SafeDetail(evt.Details, _countof(evt.Details),
                                L"RWX region at 0x%p, size=0x%llX bytes (MEM_PRIVATE)",
                                mbi.BaseAddress, (ULONGLONG)mbi.RegionSize);
                        }

                        HookComm_SendEvent(&evt);
                    }
                }

                addr += mbi.RegionSize;
            }

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Continue scanning after exceptions */
        }
    }

    return 0;
}

/* ============================================================================
 * MemoryGuard_Start
 * ============================================================================ */
BOOL MemoryGuard_Start()
{
    if (g_memGuardRunning.load()) return TRUE;

    InitializeCriticalSection(&g_reportedLock);
    g_pReportedRegions = new (std::nothrow) std::unordered_map<ULONG_PTR, ULONGLONG>();
    if (!g_pReportedRegions) return FALSE;

    g_memGuardShutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_memGuardRunning.store(true);
    g_hScanThread = CreateThread(nullptr, 0, MemoryGuardThread, nullptr, 0, nullptr);
    if (!g_hScanThread) {
        g_memGuardRunning.store(false);
        delete g_pReportedRegions;
        g_pReportedRegions = nullptr;
        CloseHandle(g_memGuardShutdownEvent);
        g_memGuardShutdownEvent = NULL;
        DeleteCriticalSection(&g_reportedLock);
        return FALSE;
    }

    return TRUE;
}

/* ============================================================================
 * MemoryGuard_Stop
 * ============================================================================ */
void MemoryGuard_Stop()
{
    if (!g_memGuardRunning.load()) return;

    g_memGuardRunning.store(false);
    if (g_memGuardShutdownEvent) SetEvent(g_memGuardShutdownEvent);

    if (g_hScanThread) {
        WaitForSingleObject(g_hScanThread, 5000);
        CloseHandle(g_hScanThread);
        g_hScanThread = nullptr;
    }

    if (g_memGuardShutdownEvent) {
        CloseHandle(g_memGuardShutdownEvent);
        g_memGuardShutdownEvent = NULL;
    }

    EnterCriticalSection(&g_reportedLock);
    delete g_pReportedRegions;
    g_pReportedRegions = nullptr;
    LeaveCriticalSection(&g_reportedLock);

    Sleep(10);
    DeleteCriticalSection(&g_reportedLock);
}
