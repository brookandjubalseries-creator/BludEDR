/*
 * BludEDR - config_manager.cpp
 * Simple JSON-like config file parser for blud_config.json
 *
 * Expected format (simplified JSON):
 * {
 *     "logPath": "C:\\ProgramData\\BludEDR\\logs\\agent.log",
 *     "logLevel": "INFO",
 *     "enableHookDll": true,
 *     "enableYara": false,
 *     "enableEtw": true,
 *     "scoreThresholdAlert": 50,
 *     "scoreThresholdSuspend": 80,
 *     "scoreThresholdTerminate": 90,
 *     "whitelistedProcesses": ["svchost.exe", "csrss.exe"],
 *     "hookDllPath": "C:\\ProgramData\\BludEDR\\blud_hook.dll"
 * }
 */

#include "config_manager.h"
#include "logger.h"

namespace blud {

ConfigManager* ConfigManager::s_Instance = nullptr;

ConfigManager::ConfigManager()
{
    InitializeSRWLock(&m_Lock);
    s_Instance = this;
}

ConfigManager::~ConfigManager()
{
    s_Instance = nullptr;
}

ConfigManager& ConfigManager::Instance()
{
    static ConfigManager instance;
    return instance;
}

/* ============================================================================
 * String utilities
 * ============================================================================ */
std::string ConfigManager::Trim(const std::string& s) const
{
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string ConfigManager::StripQuotes(const std::string& s) const
{
    std::string t = Trim(s);
    /* Remove trailing comma */
    if (!t.empty() && t.back() == ',') t.pop_back();
    t = Trim(t);
    if (t.size() >= 2 && t.front() == '"' && t.back() == '"') {
        return t.substr(1, t.size() - 2);
    }
    return t;
}

bool ConfigManager::ParseBool(const std::string& s) const
{
    std::string t = Trim(s);
    if (!t.empty() && t.back() == ',') t.pop_back();
    t = Trim(t);
    return (t == "true" || t == "1" || t == "yes");
}

/* ============================================================================
 * Load config from file
 * ============================================================================ */
bool ConfigManager::Load(const std::wstring& filePath)
{
    SrwExclusiveLock lock(m_Lock);

    /* Try to open the file */
    std::ifstream file(WideToUtf8(filePath));
    if (!file.is_open()) {
        /* Use defaults if no config file found */
        return false;
    }

    std::string line;
    bool inArray = false;

    while (std::getline(file, line)) {
        std::string trimmed = Trim(line);

        /* Skip braces and empty lines */
        if (trimmed.empty() || trimmed == "{" || trimmed == "}") continue;
        if (trimmed == "]" || trimmed == "],") { inArray = false; continue; }

        if (inArray) {
            /* Parsing whitelist array items */
            std::string val = StripQuotes(trimmed);
            if (!val.empty() && val != "[" && val != "]") {
                m_Config.whitelistedProcesses.push_back(Utf8ToWide(val));
            }
            continue;
        }

        /* Find key: value pairs */
        auto colonPos = trimmed.find(':');
        if (colonPos == std::string::npos) continue;

        std::string key = StripQuotes(trimmed.substr(0, colonPos));
        std::string value = Trim(trimmed.substr(colonPos + 1));

        if (key == "logPath") {
            m_Config.logPath = Utf8ToWide(StripQuotes(value));
        }
        else if (key == "logLevel") {
            std::string level = StripQuotes(value);
            if (level == "DEBUG")        m_Config.logLevel = LogLevel::DEBUG;
            else if (level == "INFO")    m_Config.logLevel = LogLevel::INFO;
            else if (level == "WARNING") m_Config.logLevel = LogLevel::WARNING;
            else if (level == "ERROR")   m_Config.logLevel = LogLevel::ERR;
            else if (level == "CRITICAL") m_Config.logLevel = LogLevel::CRITICAL;
        }
        else if (key == "enableHookDll") {
            m_Config.enableHookDll = ParseBool(value);
        }
        else if (key == "enableYara") {
            m_Config.enableYara = ParseBool(value);
        }
        else if (key == "enableEtw") {
            m_Config.enableEtw = ParseBool(value);
        }
        else if (key == "scoreThresholdAlert") {
            std::string numStr = StripQuotes(value);
            try { m_Config.scoreThresholdAlert = std::stod(numStr); } catch (...) {}
        }
        else if (key == "scoreThresholdSuspend") {
            std::string numStr = StripQuotes(value);
            try { m_Config.scoreThresholdSuspend = std::stod(numStr); } catch (...) {}
        }
        else if (key == "scoreThresholdTerminate") {
            std::string numStr = StripQuotes(value);
            try { m_Config.scoreThresholdTerminate = std::stod(numStr); } catch (...) {}
        }
        else if (key == "whitelistedProcesses") {
            m_Config.whitelistedProcesses.clear();
            /* Check if it's an inline array or multi-line */
            if (value.find('[') != std::string::npos && value.find(']') != std::string::npos) {
                /* Inline array: ["foo.exe", "bar.exe"] */
                auto arrStart = value.find('[');
                auto arrEnd = value.find(']');
                std::string inner = value.substr(arrStart + 1, arrEnd - arrStart - 1);
                /* Split by comma */
                std::istringstream ss(inner);
                std::string item;
                while (std::getline(ss, item, ',')) {
                    std::string val = StripQuotes(Trim(item));
                    if (!val.empty()) {
                        m_Config.whitelistedProcesses.push_back(Utf8ToWide(val));
                    }
                }
            } else if (value.find('[') != std::string::npos) {
                inArray = true;
            }
        }
        else if (key == "hookDllPath") {
            m_Config.hookDllPath = Utf8ToWide(StripQuotes(value));
        }
    }

    file.close();
    return true;
}

/* ============================================================================
 * Check if a process is whitelisted
 * ============================================================================ */
bool ConfigManager::IsWhitelisted(const std::wstring& processName) const
{
    std::wstring lower = ToLowerW(processName);

    SrwSharedLock lock(m_Lock);
    for (const auto& entry : m_Config.whitelistedProcesses) {
        if (ToLowerW(entry) == lower) {
            return true;
        }
    }
    return false;
}

} /* namespace blud */
