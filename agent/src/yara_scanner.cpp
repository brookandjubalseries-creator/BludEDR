/*
 * BludEDR - yara_scanner.cpp
 * YARA rule scanner for process memory and files
 *
 * NOTE: Requires libyara linked statically. If YARA is not available,
 * this module operates in stub mode (all scans return empty).
 */

#include "../inc/yara_scanner.h"

/*
 * YARA integration - conditional compilation.
 * Define BLUD_HAS_YARA if libyara is available.
 */
#ifdef BLUD_HAS_YARA
#include <yara.h>
#endif

#include <algorithm>

namespace blud {

#ifdef BLUD_HAS_YARA

/* YARA scan callback context */
struct ScanContext {
    std::vector<YaraMatch>* Matches;
    DWORD ProcessId;
    std::wstring FileName;
};

static int YaraScanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    auto* ctx = reinterpret_cast<ScanContext*>(user_data);

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = reinterpret_cast<YR_RULE*>(message_data);

        YaraMatch match;
        match.RuleName = rule->identifier ? rule->identifier : "unknown";
        match.RuleNamespace = rule->ns ? (rule->ns->name ? rule->ns->name : "") : "";
        match.ProcessId = ctx->ProcessId;
        match.FileName = ctx->FileName;
        match.MatchAddress = nullptr;
        match.MatchLength = 0;

        /* Collect tags */
        const char* tag = nullptr;
        yr_rule_tags_foreach(rule, tag) {
            if (!match.Tags.empty()) match.Tags += ",";
            match.Tags += tag;
        }

        /* Get first match string info */
        YR_STRING* str = nullptr;
        yr_rule_strings_foreach(rule, str) {
            YR_MATCH* m = nullptr;
            yr_string_matches_foreach(context, str, m) {
                match.MatchAddress = (PVOID)(uintptr_t)m->offset;
                match.MatchLength = (SIZE_T)m->match_length;
                break;
            }
            if (match.MatchAddress) break;
        }

        ctx->Matches->push_back(std::move(match));
    }

    return CALLBACK_CONTINUE;
}

#endif /* BLUD_HAS_YARA */

YaraScanner::YaraScanner() {}

YaraScanner::~YaraScanner() {
    Shutdown();
}

bool YaraScanner::Initialize(const std::wstring& rulesDir) {
#ifdef BLUD_HAS_YARA
    if (yr_initialize() != ERROR_SUCCESS) {
        return false;
    }

    if (yr_compiler_create(&m_compiler) != ERROR_SUCCESS) {
        yr_finalize();
        return false;
    }

    if (!LoadRulesFromDirectory(rulesDir)) {
        /* Non-fatal: we can still scan with whatever rules loaded */
    }

    /* Get compiled rules */
    if (yr_compiler_get_rules(m_compiler, &m_rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(m_compiler);
        m_compiler = nullptr;
        yr_finalize();
        return false;
    }

    m_initialized = true;
    return true;
#else
    /* Stub mode - YARA not linked */
    m_initialized = true;
    return true;
#endif
}

void YaraScanner::Shutdown() {
#ifdef BLUD_HAS_YARA
    if (m_rules) {
        yr_rules_destroy(m_rules);
        m_rules = nullptr;
    }
    if (m_compiler) {
        yr_compiler_destroy(m_compiler);
        m_compiler = nullptr;
    }
    yr_finalize();
#endif
    m_initialized = false;
}

bool YaraScanner::LoadRulesFromDirectory(const std::wstring& dir) {
#ifdef BLUD_HAS_YARA
    std::wstring searchPath = dir + L"\\*.yar";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

    if (hFind == INVALID_HANDLE_VALUE) return false;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring fullPath = dir + L"\\" + fd.cFileName;
            CompileRuleFile(fullPath);
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return true;
#else
    return true;
#endif
}

bool YaraScanner::CompileRuleFile(const std::wstring& filePath) {
#ifdef BLUD_HAS_YARA
    FILE* fp = _wfopen(filePath.c_str(), L"r");
    if (!fp) return false;

    /* Extract namespace from filename */
    std::wstring fname = filePath;
    auto pos = fname.find_last_of(L"\\/");
    if (pos != std::wstring::npos) fname = fname.substr(pos + 1);
    auto dot = fname.find_last_of(L'.');
    if (dot != std::wstring::npos) fname = fname.substr(0, dot);

    /* Convert to narrow string for YARA */
    char ns[256];
    WideCharToMultiByte(CP_UTF8, 0, fname.c_str(), -1, ns, sizeof(ns), nullptr, nullptr);

    int errors = yr_compiler_add_file(m_compiler, fp, ns, nullptr);
    fclose(fp);

    if (errors == 0) {
        m_ruleCount++;
        return true;
    }
    return false;
#else
    return true;
#endif
}

std::vector<YaraMatch> YaraScanner::ScanProcessMemory(DWORD pid) {
    std::vector<YaraMatch> matches;

#ifdef BLUD_HAS_YARA
    if (!m_initialized.load() || !m_rules) return matches;
    std::lock_guard<std::recursive_mutex> lock(m_scanMutex);

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return matches;

    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID addr = nullptr;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ |
                           PAGE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.Type == MEM_PRIVATE &&
            mbi.RegionSize <= (16 * 1024 * 1024)) /* Skip huge regions */
        {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(),
                                  mbi.RegionSize, &bytesRead) && bytesRead > 0)
            {
                auto regionMatches = ScanBuffer(buffer.data(), bytesRead, pid);
                for (auto& m : regionMatches) {
                    /* Adjust address to be process-relative */
                    m.MatchAddress = (PVOID)((uintptr_t)mbi.BaseAddress +
                                             (uintptr_t)m.MatchAddress);
                    matches.push_back(std::move(m));
                }
            }
        }

        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        if ((uintptr_t)addr < (uintptr_t)mbi.BaseAddress) break;
    }

    CloseHandle(hProcess);
#endif

    /* Notify callback */
    if (m_callback) {
        for (const auto& m : matches) {
            m_callback(m);
        }
    }

    return matches;
}

std::vector<YaraMatch> YaraScanner::ScanFile(const std::wstring& filePath) {
    std::vector<YaraMatch> matches;

#ifdef BLUD_HAS_YARA
    if (!m_initialized.load() || !m_rules) return matches;
    std::lock_guard<std::recursive_mutex> lock(m_scanMutex);

    /* Convert path to narrow for YARA */
    char narrowPath[MAX_PATH * 2];
    WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1,
                        narrowPath, sizeof(narrowPath), nullptr, nullptr);

    ScanContext ctx;
    ctx.Matches = &matches;
    ctx.ProcessId = 0;
    ctx.FileName = filePath;

    yr_rules_scan_file(m_rules, narrowPath, 0, YaraScanCallback, &ctx, 30);
#endif

    if (m_callback) {
        for (const auto& m : matches) {
            m_callback(m);
        }
    }

    return matches;
}

std::vector<YaraMatch> YaraScanner::ScanBuffer(const BYTE* data, SIZE_T size, DWORD pid) {
    std::vector<YaraMatch> matches;

#ifdef BLUD_HAS_YARA
    if (!m_initialized.load() || !m_rules) return matches;
    std::lock_guard<std::recursive_mutex> lock(m_scanMutex);

    ScanContext ctx;
    ctx.Matches = &matches;
    ctx.ProcessId = pid;

    yr_rules_scan_mem(m_rules, data, size, 0, YaraScanCallback, &ctx, 30);
#endif

    return matches;
}

void YaraScanner::SetCallback(YaraMatchCallback cb) {
    std::lock_guard<std::recursive_mutex> lock(m_scanMutex);
    m_callback = std::move(cb);
}

} // namespace blud
