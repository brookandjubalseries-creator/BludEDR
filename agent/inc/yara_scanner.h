/*
 * BludEDR - yara_scanner.h
 * YARA rule scanner for process memory and files
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <functional>

/* Forward declare YARA types to avoid header dependency */
struct YR_RULES;
struct YR_COMPILER;

namespace blud {

struct YaraMatch {
    std::string     RuleName;
    std::string     RuleNamespace;
    std::string     Tags;
    DWORD           ProcessId;
    PVOID           MatchAddress;
    SIZE_T          MatchLength;
    std::wstring    FileName;   /* Non-empty for file scans */
};

using YaraMatchCallback = std::function<void(const YaraMatch&)>;

class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();

    /* Initialize YARA library and load rules from directory */
    bool Initialize(const std::wstring& rulesDir);
    void Shutdown();

    /* Scan process memory */
    std::vector<YaraMatch> ScanProcessMemory(DWORD pid);

    /* Scan a file */
    std::vector<YaraMatch> ScanFile(const std::wstring& filePath);

    /* Scan a memory buffer */
    std::vector<YaraMatch> ScanBuffer(const BYTE* data, SIZE_T size, DWORD pid = 0);

    /* Set match callback for real-time notification */
    void SetCallback(YaraMatchCallback cb);

    /* Get loaded rule count */
    size_t GetRuleCount() const { return m_ruleCount; }

private:
    bool LoadRulesFromDirectory(const std::wstring& dir);
    bool CompileRuleFile(const std::wstring& filePath);

    YR_RULES*           m_rules = nullptr;
    YR_COMPILER*        m_compiler = nullptr;
    YaraMatchCallback   m_callback;
    std::recursive_mutex m_scanMutex;
    std::atomic<bool>   m_initialized{false};
    size_t              m_ruleCount = 0;
};

} // namespace blud
