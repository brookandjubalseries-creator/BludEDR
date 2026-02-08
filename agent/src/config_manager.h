/*
 * BludEDR - config_manager.h
 * Simple JSON-like config loading from blud_config.json
 */

#pragma once
#include "../inc/agent.h"

namespace blud {

/* Log levels for config */
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERR = 3,
    CRITICAL = 4
};

struct AgentConfig {
    std::wstring    logPath;
    LogLevel        logLevel;
    bool            enableHookDll;
    bool            enableYara;
    bool            enableEtw;
    double          scoreThresholdAlert;
    double          scoreThresholdSuspend;
    double          scoreThresholdTerminate;
    std::vector<std::wstring> whitelistedProcesses;
    std::wstring    hookDllPath;

    AgentConfig()
        : logPath(L"C:\\ProgramData\\BludEDR\\logs\\agent.log")
        , logLevel(LogLevel::INFO)
        , enableHookDll(true)
        , enableYara(false)
        , enableEtw(true)
        , scoreThresholdAlert(50.0)
        , scoreThresholdSuspend(80.0)
        , scoreThresholdTerminate(90.0)
        , hookDllPath(L"C:\\ProgramData\\BludEDR\\blud_hook.dll")
    {}
};

class ConfigManager {
public:
    ConfigManager();
    ~ConfigManager();

    /* Load config from a JSON file */
    bool Load(const std::wstring& filePath);

    /* Accessors */
    const AgentConfig& GetConfig() const { return m_Config; }
    std::wstring GetLogPath() const { return m_Config.logPath; }
    LogLevel GetLogLevel() const { return m_Config.logLevel; }
    bool IsHookDllEnabled() const { return m_Config.enableHookDll; }
    bool IsYaraEnabled() const { return m_Config.enableYara; }
    bool IsEtwEnabled() const { return m_Config.enableEtw; }
    const std::vector<std::wstring>& GetWhitelist() const { return m_Config.whitelistedProcesses; }
    std::wstring GetHookDllPath() const { return m_Config.hookDllPath; }

    /* Check if a process is whitelisted */
    bool IsWhitelisted(const std::wstring& processName) const;

    /* Singleton */
    static ConfigManager& Instance();

private:
    /* Simple key-value parser for our config format */
    std::string Trim(const std::string& s) const;
    std::string StripQuotes(const std::string& s) const;
    bool ParseBool(const std::string& s) const;

    AgentConfig     m_Config;
    mutable SRWLOCK m_Lock;

    static ConfigManager* s_Instance;
};

} /* namespace blud */
