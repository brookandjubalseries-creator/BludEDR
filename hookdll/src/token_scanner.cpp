/*
 * BludEDR - token_scanner.cpp
 * Memory scanner for credential material.
 *
 * Scans MEM_PRIVATE + PAGE_READWRITE heap regions for:
 *   - "Authorization: Bearer " (HTTP bearer tokens)
 *   - "eyJ" (JWT prefix - base64 of '{"')
 *   - "AKIA" (AWS access key prefix)
 *   - Common API key patterns
 *
 * Runs every 10 seconds. Sends EVENT_TOKEN_FOUND with sanitized match info.
 */

#include "token_scanner.h"
#include "hook_comm.h"

/* ============================================================================
 * Token patterns to scan for
 * ============================================================================ */

struct TokenPattern {
    const char* pattern;
    SIZE_T      patternLen;
    const WCHAR* description;
};

static const TokenPattern g_patterns[] = {
    { "Authorization: Bearer ",  24, L"HTTP Bearer Token" },
    { "eyJhbGciOi",             11, L"JWT Token (alg header)" },
    { "eyJ0eXAiOi",             11, L"JWT Token (typ header)" },
    { "eyJhbGci",                8, L"JWT Token" },
    { "AKIA",                    4, L"AWS Access Key" },
    { "ABIA",                    4, L"AWS STS Token" },
    { "AROA",                    4, L"AWS IAM Role" },
    { "sk-",                     3, L"API Secret Key (sk-)" },
    { "ghp_",                    4, L"GitHub PAT" },
    { "gho_",                    4, L"GitHub OAuth Token" },
    { "glpat-",                  6, L"GitLab PAT" },
    { "xox",                     3, L"Slack Token" },
};
static constexpr SIZE_T NUM_PATTERNS = sizeof(g_patterns) / sizeof(g_patterns[0]);

/* ============================================================================
 * Static state
 * ============================================================================ */

static HANDLE               g_hScanThread = nullptr;
static std::atomic<bool>    g_tokenScanRunning{false};

/* Track reported tokens (hash of location + first bytes) to avoid duplicates */
static std::unordered_map<ULONG_PTR, ULONGLONG>* g_pReportedTokens = nullptr;
static CRITICAL_SECTION g_tokenReportLock;
static constexpr ULONGLONG TOKEN_REPORT_COOLDOWN_MS = 120000; /* 2 minutes */

/* ============================================================================
 * Internal: Boyer-Moore-Horspool-like search for a pattern in memory
 * ============================================================================ */
static const BYTE* FindBytes(const BYTE* haystack, SIZE_T haystackLen,
                             const BYTE* needle, SIZE_T needleLen)
{
    if (haystackLen < needleLen) return nullptr;

    SIZE_T limit = haystackLen - needleLen;
    for (SIZE_T i = 0; i <= limit; i++) {
        if (memcmp(haystack + i, needle, needleLen) == 0) {
            return haystack + i;
        }
    }
    return nullptr;
}

/* ============================================================================
 * Internal: Sanitize a match for safe reporting (truncate, redact)
 * ============================================================================ */
static void SanitizeMatch(const BYTE* pMatch, SIZE_T available, WCHAR* dest, size_t destCount)
{
    /* Show first TOKEN_MAX_MATCH_LEN chars, replacing non-printable */
    SIZE_T showLen = min(available, (SIZE_T)TOKEN_MAX_MATCH_LEN);

    WCHAR temp[TOKEN_MAX_MATCH_LEN + 1] = {};
    for (SIZE_T i = 0; i < showLen; i++) {
        BYTE b = pMatch[i];
        if (b >= 0x20 && b <= 0x7E) {
            temp[i] = static_cast<WCHAR>(b);
        } else {
            temp[i] = L'.';
        }
    }
    temp[showLen] = L'\0';

    /* Redact middle portion to avoid leaking full credentials */
    if (showLen > 12) {
        for (SIZE_T i = 8; i < showLen - 4; i++) {
            temp[i] = L'*';
        }
    }

    wcsncpy_s(dest, destCount, temp, _TRUNCATE);
}

/* ============================================================================
 * Internal: Check reporting cooldown
 * ============================================================================ */
static BOOL ShouldReportToken(ULONG_PTR matchAddr)
{
    ULONGLONG now = GetTickCount64();
    BOOL report = FALSE;

    EnterCriticalSection(&g_tokenReportLock);

    auto it = g_pReportedTokens->find(matchAddr);
    if (it == g_pReportedTokens->end()) {
        g_pReportedTokens->insert({ matchAddr, now });
        report = TRUE;
    } else if ((now - it->second) >= TOKEN_REPORT_COOLDOWN_MS) {
        it->second = now;
        report = TRUE;
    }

    LeaveCriticalSection(&g_tokenReportLock);
    return report;
}

/* ============================================================================
 * Scan thread
 * ============================================================================ */
static DWORD WINAPI TokenScanThread(LPVOID /*param*/)
{
    while (g_tokenScanRunning.load()) {
        Sleep(TOKEN_SCAN_INTERVAL);

        if (!g_tokenScanRunning.load()) break;

        __try {
            SYSTEM_INFO si;
            GetSystemInfo(&si);

            ULONG_PTR addr = reinterpret_cast<ULONG_PTR>(si.lpMinimumApplicationAddress);
            ULONG_PTR maxAddr = reinterpret_cast<ULONG_PTR>(si.lpMaximumApplicationAddress);

            while (addr < maxAddr && g_tokenScanRunning.load()) {
                MEMORY_BASIC_INFORMATION mbi = {};
                SIZE_T result = VirtualQuery(
                    reinterpret_cast<PVOID>(addr), &mbi, sizeof(mbi));

                if (result == 0) break;

                /* Only scan MEM_PRIVATE + PAGE_READWRITE (heap-like) */
                if (mbi.State == MEM_COMMIT &&
                    mbi.Type == MEM_PRIVATE &&
                    mbi.Protect == PAGE_READWRITE &&
                    mbi.RegionSize > 0 &&
                    mbi.RegionSize <= 16 * 1024 * 1024) /* Skip huge regions */
                {
                    const BYTE* pRegion = static_cast<const BYTE*>(mbi.BaseAddress);
                    SIZE_T regionSize = mbi.RegionSize;

                    /* Scan for each pattern */
                    for (SIZE_T pi = 0; pi < NUM_PATTERNS; pi++) {
                        const BYTE* needle = reinterpret_cast<const BYTE*>(g_patterns[pi].pattern);
                        SIZE_T needleLen = g_patterns[pi].patternLen;

                        const BYTE* pMatch = FindBytes(pRegion, regionSize, needle, needleLen);
                        if (pMatch) {
                            ULONG_PTR matchAddr = reinterpret_cast<ULONG_PTR>(pMatch);

                            if (ShouldReportToken(matchAddr)) {
                                SENTINEL_MEMORY_EVENT evt;
                                BuildMemoryEvent(&evt, EVENT_TOKEN_FOUND);
                                evt.BaseAddress = const_cast<PVOID>(
                                    reinterpret_cast<const void*>(pMatch));
                                evt.RegionSize = regionSize;
                                evt.CallstackDepth = 0;

                                /* Sanitize the matched content */
                                SIZE_T available = regionSize -
                                    (reinterpret_cast<ULONG_PTR>(pMatch) -
                                     reinterpret_cast<ULONG_PTR>(pRegion));
                                WCHAR sanitized[TOKEN_MAX_MATCH_LEN + 1] = {};
                                SanitizeMatch(pMatch, available, sanitized, _countof(sanitized));

                                SafeDetail(evt.Details, _countof(evt.Details),
                                    L"[%s] at 0x%p: %s",
                                    g_patterns[pi].description, pMatch, sanitized);

                                HookComm_SendEvent(&evt);
                            }

                            /* Only report one match per pattern per region */
                            break;
                        }
                    }
                }

                addr += mbi.RegionSize;
            }

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Continue */
        }
    }

    return 0;
}

/* ============================================================================
 * TokenScanner_Start
 * ============================================================================ */
BOOL TokenScanner_Start()
{
    if (g_tokenScanRunning.load()) return TRUE;

    InitializeCriticalSection(&g_tokenReportLock);
    g_pReportedTokens = new (std::nothrow) std::unordered_map<ULONG_PTR, ULONGLONG>();
    if (!g_pReportedTokens) return FALSE;

    g_tokenScanRunning.store(true);
    g_hScanThread = CreateThread(nullptr, 0, TokenScanThread, nullptr, 0, nullptr);
    if (!g_hScanThread) {
        g_tokenScanRunning.store(false);
        delete g_pReportedTokens;
        g_pReportedTokens = nullptr;
        DeleteCriticalSection(&g_tokenReportLock);
        return FALSE;
    }

    return TRUE;
}

/* ============================================================================
 * TokenScanner_Stop
 * ============================================================================ */
void TokenScanner_Stop()
{
    if (!g_tokenScanRunning.load()) return;

    g_tokenScanRunning.store(false);

    if (g_hScanThread) {
        WaitForSingleObject(g_hScanThread, 15000);
        CloseHandle(g_hScanThread);
        g_hScanThread = nullptr;
    }

    EnterCriticalSection(&g_tokenReportLock);
    delete g_pReportedTokens;
    g_pReportedTokens = nullptr;
    LeaveCriticalSection(&g_tokenReportLock);

    DeleteCriticalSection(&g_tokenReportLock);
}
