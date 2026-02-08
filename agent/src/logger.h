/*
 * BludEDR - logger.h
 * Structured logging to file and Windows Event Log
 */

#pragma once
#include "../inc/agent.h"
#include "config_manager.h" /* For LogLevel enum */

namespace blud {

class Logger {
public:
    Logger();
    ~Logger();

    /* Initialize with path and minimum level */
    void Initialize(const std::wstring& logPath, LogLevel minLevel);

    /* Shut down and flush */
    void Shutdown();

    /* Log a message */
    void Log(LogLevel level, const std::string& component, const std::string& message);

    /* Get the log file path */
    std::wstring GetLogPath() const { return m_LogPath; }

    /* Singleton */
    static Logger& Instance();

private:
    /* Format timestamp string */
    std::string GetTimestamp() const;

    /* Level to string */
    static const char* LevelToString(LogLevel level);

    /* Rotate log if needed (50 MB threshold) */
    void RotateIfNeeded();

    /* Write to Windows Event Log */
    void WriteToEventLog(LogLevel level, const std::string& message);

    static constexpr uint64_t MAX_LOG_SIZE = 50ULL * 1024 * 1024; /* 50 MB */

    std::wstring        m_LogPath;
    LogLevel            m_MinLevel;
    std::ofstream       m_File;
    std::mutex          m_Mutex;
    HANDLE              m_EventLog;
    bool                m_Initialized;

    static Logger* s_Instance;
};

} /* namespace blud */
