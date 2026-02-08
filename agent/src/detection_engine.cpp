/*
 * BludEDR - detection_engine.cpp
 * Rule evaluation pipeline with built-in detection rules
 */

#include "detection_engine.h"
#include "process_tree.h"
#include "ioc_scoring.h"
#include "alert_manager.h"
#include "lolbas_detector.h"
#include "logger.h"

namespace blud {

DetectionEngine* DetectionEngine::s_Instance = nullptr;

DetectionEngine::DetectionEngine()
{
    InitializeSRWLock(&m_Lock);
    s_Instance = this;
}

DetectionEngine::~DetectionEngine()
{
    s_Instance = nullptr;
}

DetectionEngine& DetectionEngine::Instance()
{
    static DetectionEngine instance;
    return instance;
}

void DetectionEngine::Initialize()
{
    RegisterBuiltinRules();
    LOG_INFO("DetectionEngine", "Initialized with " + std::to_string(m_Rules.size()) + " rules");
}

void DetectionEngine::Shutdown()
{
    {
        SrwExclusiveLock lock(m_Lock);
        m_Rules.clear();
    }
    LOG_INFO("DetectionEngine", "Shut down");
}

/* ============================================================================
 * Rule match handler
 * ============================================================================ */
void DetectionEngine::OnRuleMatch(const DetectionRule& rule, DWORD pid, const std::string& detail)
{
    /* Add IoC score */
    IoCScoring::Instance().AddScore(pid, rule.ruleId, rule.score, rule.category);

    /* Determine action from current cumulative score */
    double currentScore = IoCScoring::Instance().GetCurrentScore(pid);

    LOG_WARNING("DetectionEngine",
        "Rule " + std::to_string(rule.ruleId) + " [" + rule.name +
        "] matched for PID " + std::to_string(pid) +
        " (+" + std::to_string((int)rule.score) +
        ", total=" + std::to_string((int)currentScore) +
        "): " + detail);

    /* Alert manager handles response actions */
    AlertManager::Instance().ProcessAlert(pid, currentScore, rule.ruleId, rule.name, detail);
}

/* ============================================================================
 * Add a custom rule
 * ============================================================================ */
void DetectionEngine::AddRule(DetectionRule rule)
{
    SrwExclusiveLock lock(m_Lock);
    m_Rules.push_back(std::move(rule));
}

/* ============================================================================
 * Register all built-in rules
 * ============================================================================ */
void DetectionEngine::RegisterBuiltinRules()
{
    /* ----- Rule 1001: cmd.exe spawns powershell.exe ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_CMD_SPAWNS_POWERSHELL;
        r.name    = "cmd.exe spawns powershell.exe";
        r.score   = 25.0;
        r.severity = IOC_SEVERITY_LOW;
        r.category = IOC_CAT_PROCESS_LINEAGE;
        r.processEval = [](const SENTINEL_PROCESS_EVENT& evt) -> bool {
            std::wstring image = ToLowerW(ExtractFilename(evt.ImagePath));
            if (image != L"powershell.exe" && image != L"pwsh.exe") return false;
            /* Check if parent is cmd.exe */
            ProcessNode parent;
            if (ProcessTree::Instance().GetProcess(evt.ParentProcessId, parent)) {
                std::wstring parentName = ToLowerW(ExtractFilename(parent.imagePath));
                return parentName == L"cmd.exe";
            }
            return false;
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1002: powershell -enc / obfuscated ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_POWERSHELL_ENCODED;
        r.name    = "PowerShell encoded/obfuscated command";
        r.score   = 90.0;
        r.severity = IOC_SEVERITY_VERY_HIGH;
        r.category = IOC_CAT_COMMAND_LINE;
        r.processEval = [](const SENTINEL_PROCESS_EVENT& evt) -> bool {
            std::wstring image = ToLowerW(ExtractFilename(evt.ImagePath));
            if (image != L"powershell.exe" && image != L"pwsh.exe") return false;
            std::wstring cmd = ToLowerW(evt.CommandLine);
            return ContainsInsensitive(cmd, L"-enc") ||
                   ContainsInsensitive(cmd, L"-encodedcommand") ||
                   ContainsInsensitive(cmd, L"frombase64string") ||
                   ContainsInsensitive(cmd, L"[convert]::") ||
                   ContainsInsensitive(cmd, L"-e ");
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1003: Script file dropped to disk ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_SCRIPT_FILE_DROP;
        r.name    = "Suspicious script file dropped";
        r.score   = 100.0;
        r.severity = IOC_SEVERITY_CRITICAL;
        r.category = IOC_CAT_FILE_DROP;
        r.fileEval = [](const SENTINEL_FILE_EVENT& evt) -> bool {
            if (!evt.IsSuspiciousExtension) return false;
            /* Check if it's a write/create with suspicious extension */
            std::wstring ext = ToLowerW(evt.Extension);
            return (ext == L".ps1" || ext == L".vbs" || ext == L".js" ||
                    ext == L".wsf" || ext == L".hta" || ext == L".bat" ||
                    ext == L".cmd" || ext == L".scr");
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1004: LOLBAS with suspicious arguments ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_LOLBAS_SUSPICIOUS_ARGS;
        r.name    = "LOLBAS binary with suspicious arguments";
        r.score   = 75.0;
        r.severity = IOC_SEVERITY_HIGH;
        r.category = IOC_CAT_DEFENSE_EVASION;
        r.processEval = [](const SENTINEL_PROCESS_EVENT& evt) -> bool {
            std::wstring imageName = ExtractFilename(evt.ImagePath);
            std::wstring cmdLine = evt.CommandLine;
            auto result = LolbasDetector::Instance().CheckProcess(imageName, cmdLine);
            return result.isLolbas && !result.suspiciousArgs.empty();
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1005: Suspicious parent-child relationship ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_SUSPICIOUS_PARENT_CHILD;
        r.name    = "Suspicious parent-child relationship";
        r.score   = 50.0;
        r.severity = IOC_SEVERITY_HIGH;
        r.category = IOC_CAT_PROCESS_LINEAGE;
        r.processEval = [](const SENTINEL_PROCESS_EVENT& evt) -> bool {
            std::wstring child = ToLowerW(ExtractFilename(evt.ImagePath));
            ProcessNode parent;
            if (!ProcessTree::Instance().GetProcess(evt.ParentProcessId, parent))
                return false;
            std::wstring parentName = ToLowerW(ExtractFilename(parent.imagePath));

            /* Known suspicious pairings */
            /* Word/Excel/PowerPoint spawning cmd/powershell */
            bool officeParent = (parentName == L"winword.exe" ||
                                 parentName == L"excel.exe" ||
                                 parentName == L"powerpnt.exe" ||
                                 parentName == L"outlook.exe");
            bool shellChild = (child == L"cmd.exe" ||
                               child == L"powershell.exe" ||
                               child == L"pwsh.exe" ||
                               child == L"wscript.exe" ||
                               child == L"cscript.exe" ||
                               child == L"mshta.exe");

            if (officeParent && shellChild) return true;

            /* svchost spawning interactive shells */
            if (parentName == L"svchost.exe" && shellChild) return true;

            /* wmiprvse spawning shells */
            if (parentName == L"wmiprvse.exe" && shellChild) return true;

            return false;
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1007: Remote thread creation ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_REMOTE_THREAD_CREATION;
        r.name    = "Remote thread creation";
        r.score   = 85.0;
        r.severity = IOC_SEVERITY_VERY_HIGH;
        r.category = IOC_CAT_PROCESS_INJECTION;
        r.threadEval = [](const SENTINEL_THREAD_EVENT& evt) -> bool {
            return evt.IsRemoteThread ? true : false;
        };
        r.memoryEval = [](const SENTINEL_MEMORY_EVENT& evt) -> bool {
            return evt.Header.Type == EVENT_REMOTE_THREAD;
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1008: LSASS handle with VM_READ ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_LSASS_ACCESS;
        r.name    = "LSASS handle with VM_READ access";
        r.score   = 100.0;
        r.severity = IOC_SEVERITY_CRITICAL;
        r.category = IOC_CAT_CREDENTIAL_ACCESS;
        r.objectEval = [](const SENTINEL_OBJECT_EVENT& evt) -> bool {
            std::wstring target = ToLowerW(ExtractFilename(evt.TargetImageName));
            if (target != L"lsass.exe") return false;
            /* PROCESS_VM_READ = 0x0010 */
            return (evt.DesiredAccess & 0x0010) != 0;
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1009: AMSI bypass detected ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_AMSI_BYPASS;
        r.name    = "AMSI bypass detected";
        r.score   = 90.0;
        r.severity = IOC_SEVERITY_VERY_HIGH;
        r.category = IOC_CAT_DEFENSE_EVASION;
        r.memoryEval = [](const SENTINEL_MEMORY_EVENT& evt) -> bool {
            return evt.Header.Type == EVENT_AMSI_BYPASS;
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1010: ETW bypass detected ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_ETW_BYPASS;
        r.name    = "ETW bypass detected";
        r.score   = 90.0;
        r.severity = IOC_SEVERITY_VERY_HIGH;
        r.category = IOC_CAT_DEFENSE_EVASION;
        r.memoryEval = [](const SENTINEL_MEMORY_EVENT& evt) -> bool {
            return evt.Header.Type == EVENT_ETW_BYPASS;
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1011: RWX allocation ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_RWX_ALLOCATION;
        r.name    = "RWX memory allocation";
        r.score   = 40.0;
        r.severity = IOC_SEVERITY_MEDIUM;
        r.category = IOC_CAT_MEMORY_TAMPERING;
        r.memoryEval = [](const SENTINEL_MEMORY_EVENT& evt) -> bool {
            if (evt.Header.Type != EVENT_MEMORY_ALLOC &&
                evt.Header.Type != EVENT_MEMORY_PROTECT)
                return false;
            /* PAGE_EXECUTE_READWRITE = 0x40 */
            return (evt.NewProtect == 0x40);
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1012: RW -> RX transition ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_RW_TO_RX_TRANSITION;
        r.name    = "RW to RX memory protection change";
        r.score   = 60.0;
        r.severity = IOC_SEVERITY_HIGH;
        r.category = IOC_CAT_MEMORY_TAMPERING;
        r.memoryEval = [](const SENTINEL_MEMORY_EVENT& evt) -> bool {
            if (evt.Header.Type != EVENT_MEMORY_PROTECT) return false;
            /* PAGE_READWRITE = 0x04, PAGE_EXECUTE_READ = 0x20 */
            bool wasRW = (evt.OldProtect == 0x04);
            bool nowRX = (evt.NewProtect == 0x20);
            return wasRW && nowRX;
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1013: Registry persistence ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_REGISTRY_PERSISTENCE;
        r.name    = "Registry persistence mechanism";
        r.score   = 75.0;
        r.severity = IOC_SEVERITY_HIGH;
        r.category = IOC_CAT_PERSISTENCE;
        r.registryEval = [](const SENTINEL_REGISTRY_EVENT& evt) -> bool {
            if (!evt.IsPersistenceKey) return false;
            std::wstring key = ToLowerW(evt.KeyName);
            /* Well-known autostart locations */
            return ContainsInsensitive(key, L"\\run") ||
                   ContainsInsensitive(key, L"\\runonce") ||
                   ContainsInsensitive(key, L"\\winlogon") ||
                   ContainsInsensitive(key, L"\\userinit") ||
                   ContainsInsensitive(key, L"\\shell") ||
                   ContainsInsensitive(key, L"\\currentversion\\explorer") ||
                   ContainsInsensitive(key, L"\\services\\") ||
                   ContainsInsensitive(key, L"\\image file execution options");
        };
        m_Rules.push_back(std::move(r));
    }

    /* ----- Rule 1014: Sleep obfuscation ----- */
    {
        DetectionRule r;
        r.ruleId  = RULE_SLEEP_OBFUSCATION;
        r.name    = "Sleep obfuscation detected";
        r.score   = 70.0;
        r.severity = IOC_SEVERITY_HIGH;
        r.category = IOC_CAT_DEFENSE_EVASION;
        r.memoryEval = [](const SENTINEL_MEMORY_EVENT& evt) -> bool {
            return evt.Header.Type == EVENT_SLEEP_OBFUSCATION;
        };
        m_Rules.push_back(std::move(r));
    }
}

/* ============================================================================
 * Evaluate process events
 * ============================================================================ */
void DetectionEngine::EvaluateProcessEvent(const SENTINEL_PROCESS_EVENT& evt)
{
    struct Match { DetectionRule rule; std::string detail; };
    std::vector<Match> matches;

    {
        SrwSharedLock lock(m_Lock);
        for (const auto& rule : m_Rules) {
            if (rule.processEval) {
                try {
                    if (rule.processEval(evt)) {
                        std::string detail = "Image: " + WideToUtf8(ExtractFilename(evt.ImagePath)) +
                                             ", CmdLine: " + WideToUtf8(std::wstring(evt.CommandLine, wcsnlen(evt.CommandLine, _countof(evt.CommandLine))));
                        matches.push_back({rule, std::move(detail)});
                    }
                } catch (...) {
                    LOG_ERROR("DetectionEngine", "Exception in processEval rule " + std::to_string(rule.ruleId));
                }
            }
        }
    }

    for (const auto& m : matches) {
        OnRuleMatch(m.rule, evt.Header.ProcessId, m.detail);
    }
}

/* ============================================================================
 * Evaluate thread events
 * ============================================================================ */
void DetectionEngine::EvaluateThreadEvent(const SENTINEL_THREAD_EVENT& evt)
{
    struct Match { DetectionRule rule; std::string detail; };
    std::vector<Match> matches;

    {
        SrwSharedLock lock(m_Lock);
        for (const auto& rule : m_Rules) {
            if (rule.threadEval) {
                try {
                    if (rule.threadEval(evt)) {
                        std::string detail = "TargetPID=" + std::to_string(evt.TargetProcessId) +
                                             ", Remote=" + (evt.IsRemoteThread ? "true" : "false");
                        matches.push_back({rule, std::move(detail)});
                    }
                } catch (...) {
                    LOG_ERROR("DetectionEngine", "Exception in threadEval rule " + std::to_string(rule.ruleId));
                }
            }
        }
    }

    for (const auto& m : matches) {
        OnRuleMatch(m.rule, evt.Header.ProcessId, m.detail);
    }
}

/* ============================================================================
 * Evaluate image load events
 * ============================================================================ */
void DetectionEngine::EvaluateImageEvent(const SENTINEL_IMAGE_EVENT& evt)
{
    struct Match { DetectionRule rule; std::string detail; };
    std::vector<Match> matches;

    {
        SrwSharedLock lock(m_Lock);
        for (const auto& rule : m_Rules) {
            if (rule.imageEval) {
                try {
                    if (rule.imageEval(evt)) {
                        std::string detail = "Module: " + WideToUtf8(ExtractFilename(evt.ImageName));
                        matches.push_back({rule, std::move(detail)});
                    }
                } catch (...) {
                    LOG_ERROR("DetectionEngine", "Exception in imageEval rule " + std::to_string(rule.ruleId));
                }
            }
        }
    }

    for (const auto& m : matches) {
        OnRuleMatch(m.rule, evt.Header.ProcessId, m.detail);
    }
}

/* ============================================================================
 * Evaluate file events
 * ============================================================================ */
void DetectionEngine::EvaluateFileEvent(const SENTINEL_FILE_EVENT& evt)
{
    struct Match { DetectionRule rule; std::string detail; };
    std::vector<Match> matches;

    {
        SrwSharedLock lock(m_Lock);
        for (const auto& rule : m_Rules) {
            if (rule.fileEval) {
                try {
                    if (rule.fileEval(evt)) {
                        std::string detail = "File: " + WideToUtf8(ExtractFilename(evt.FileName)) +
                                             ", Ext: " + WideToUtf8(evt.Extension);
                        matches.push_back({rule, std::move(detail)});
                    }
                } catch (...) {
                    LOG_ERROR("DetectionEngine", "Exception in fileEval rule " + std::to_string(rule.ruleId));
                }
            }
        }
    }

    for (const auto& m : matches) {
        OnRuleMatch(m.rule, evt.Header.ProcessId, m.detail);
    }
}

/* ============================================================================
 * Evaluate registry events
 * ============================================================================ */
void DetectionEngine::EvaluateRegistryEvent(const SENTINEL_REGISTRY_EVENT& evt)
{
    struct Match { DetectionRule rule; std::string detail; };
    std::vector<Match> matches;

    {
        SrwSharedLock lock(m_Lock);
        for (const auto& rule : m_Rules) {
            if (rule.registryEval) {
                try {
                    if (rule.registryEval(evt)) {
                        std::string detail = "Key: " + WideToUtf8(std::wstring(evt.KeyName, wcsnlen(evt.KeyName, _countof(evt.KeyName)))) +
                                             ", Value: " + WideToUtf8(std::wstring(evt.ValueName, wcsnlen(evt.ValueName, _countof(evt.ValueName))));
                        matches.push_back({rule, std::move(detail)});
                    }
                } catch (...) {
                    LOG_ERROR("DetectionEngine", "Exception in registryEval rule " + std::to_string(rule.ruleId));
                }
            }
        }
    }

    for (const auto& m : matches) {
        OnRuleMatch(m.rule, evt.Header.ProcessId, m.detail);
    }
}

/* ============================================================================
 * Evaluate object/handle events
 * ============================================================================ */
void DetectionEngine::EvaluateObjectEvent(const SENTINEL_OBJECT_EVENT& evt)
{
    struct Match { DetectionRule rule; std::string detail; };
    std::vector<Match> matches;

    {
        SrwSharedLock lock(m_Lock);
        for (const auto& rule : m_Rules) {
            if (rule.objectEval) {
                try {
                    if (rule.objectEval(evt)) {
                        std::string detail = "TargetPID=" + std::to_string(evt.TargetProcessId) +
                                             ", Target: " + WideToUtf8(ExtractFilename(evt.TargetImageName)) +
                                             ", Access=0x" +
                                             ([&]() { std::ostringstream o; o << std::hex << evt.DesiredAccess; return o.str(); })();
                        matches.push_back({rule, std::move(detail)});
                    }
                } catch (...) {
                    LOG_ERROR("DetectionEngine", "Exception in objectEval rule " + std::to_string(rule.ruleId));
                }
            }
        }
    }

    for (const auto& m : matches) {
        OnRuleMatch(m.rule, evt.Header.ProcessId, m.detail);
    }
}

/* ============================================================================
 * Evaluate memory events
 * ============================================================================ */
void DetectionEngine::EvaluateMemoryEvent(const SENTINEL_MEMORY_EVENT& evt)
{
    struct Match { DetectionRule rule; std::string detail; };
    std::vector<Match> matches;

    {
        SrwSharedLock lock(m_Lock);
        for (const auto& rule : m_Rules) {
            if (rule.memoryEval) {
                try {
                    if (rule.memoryEval(evt)) {
                        std::string detail = "Addr=0x" +
                            ([&]() { std::ostringstream o; o << std::hex << (uintptr_t)evt.BaseAddress; return o.str(); })() +
                            ", OldProt=0x" +
                            ([&]() { std::ostringstream o; o << std::hex << evt.OldProtect; return o.str(); })() +
                            ", NewProt=0x" +
                            ([&]() { std::ostringstream o; o << std::hex << evt.NewProtect; return o.str(); })();
                        if (evt.Details[0] != L'\0') {
                            detail += ", Detail: " + WideToUtf8(evt.Details);
                        }
                        matches.push_back({rule, std::move(detail)});
                    }
                } catch (...) {
                    LOG_ERROR("DetectionEngine", "Exception in memoryEval rule " + std::to_string(rule.ruleId));
                }
            }
        }
    }

    for (const auto& m : matches) {
        OnRuleMatch(m.rule, evt.Header.ProcessId, m.detail);
    }
}

} /* namespace blud */
