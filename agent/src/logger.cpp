/*
 * BludEDR - logger.cpp
 * Structured logging to file and Windows EventLog with rotation
 *
 * Format: [TIMESTAMP][LEVEL][COMPONENT] message
 */

#include "logger.h"
#include <iomanip>
#include <filesystem>

namespace blud {

Logger* Logger::s_Instance = nullptr;

Logger::Logger()
    : m_MinLevel(LogLevel::INFO)
    , m_EventLog(nullptr)
    , m_Initialized(false)
{
    s_Instance = this;
}

Logger::~Logger()
{
    Shutdown();
    s_Instance = nullptr;
}

Logger& Logger::Instance()
{
    static Logger instance;
    return instance;
}

/* ============================================================================
 * Initialize
 * ============================================================================ */
void Logger::Initialize(const std::wstring& logPath, LogLevel minLevel)
{
    std::lock_guard<std::mutex> lock(m_Mutex);

    m_LogPath = logPath;
    m_MinLevel = minLevel;

    /* Ensure log directory exists */
    try {
        std::filesystem::path p(logPath);
        std::filesystem::create_directories(p.parent_path());
    } catch (...) {
        /* Best effort */
    }

    /* Open log file in append mode */
    std::string utf8Path = WideToUtf8(logPath);
    m_File.open(utf8Path, std::ios::app | std::ios::out);

    /* Register as event source */
    m_EventLog = RegisterEventSourceW(nullptr, BLUD_SERVICE_NAME);

    m_Initialized = true;

    /* Write startup banner */
    if (m_File.is_open()) {
        m_File << "\n";
        m_File << "========================================\n";
        m_File << " BludEDR Agent Log Started\n";
        m_File << " " << GetTimestamp() << "\n";
        m_File << "========================================\n";
        m_File.flush();
    }
}

/* ============================================================================
 * Shutdown
 * ============================================================================ */
void Logger::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_Mutex);

    if (m_File.is_open()) {
        m_File << "[" << GetTimestamp() << "][INFO][Logger] Shutting down logger\n";
        m_File.flush();
        m_File.close();
    }

    if (m_EventLog) {
        DeregisterEventSource(m_EventLog);
        m_EventLog = nullptr;
    }

    m_Initialized = false;
}

/* ============================================================================
 * Log a message
 * ============================================================================ */
void Logger::Log(LogLevel level, const std::string& component, const std::string& message)
{
    if (level < m_MinLevel) return;

    std::lock_guard<std::mutex> lock(m_Mutex);

    std::string entry = "[" + GetTimestamp() + "][" +
        LevelToString(level) + "][" + component + "] " + message;

    /* Write to file */
    if (m_File.is_open()) {
        m_File << entry << "\n";
        m_File.flush();
        RotateIfNeeded();
    }

    /* Write to stderr in debug/console mode */
#ifdef _DEBUG
    OutputDebugStringA((entry + "\n").c_str());
#endif

    /* Critical and error messages also go to Windows Event Log */
    if (level >= LogLevel::ERR) {
        WriteToEventLog(level, entry);
    }
}

/* ============================================================================
 * Format timestamp
 * ============================================================================ */
std::string Logger::GetTimestamp() const
{
    SYSTEMTIME st;
    GetLocalTime(&st);

    std::ostringstream oss;
    oss << std::setfill('0')
        << st.wYear << "-"
        << std::setw(2) << st.wMonth << "-"
        << std::setw(2) << st.wDay << " "
        << std::setw(2) << st.wHour << ":"
        << std::setw(2) << st.wMinute << ":"
        << std::setw(2) << st.wSecond << "."
        << std::setw(3) << st.wMilliseconds;

    return oss.str();
}

/* ============================================================================
 * Level to string
 * ============================================================================ */
const char* Logger::LevelToString(LogLevel level)
{
    switch (level) {
    case LogLevel::DEBUG:    return "DEBUG";
    case LogLevel::INFO:     return "INFO";
    case LogLevel::WARNING:  return "WARNING";
    case LogLevel::ERR:      return "ERROR";
    case LogLevel::CRITICAL: return "CRITICAL";
    default:                 return "UNKNOWN";
    }
}

/* ============================================================================
 * Rotate log if over 50 MB
 * ============================================================================ */
void Logger::RotateIfNeeded()
{
    if (!m_File.is_open()) return;

    /* Check current position as proxy for file size */
    auto pos = m_File.tellp();
    if (pos < 0 || static_cast<uint64_t>(pos) < MAX_LOG_SIZE) return;

    m_File.close();

    /* Rename current log to .old */
    std::string utf8Path = WideToUtf8(m_LogPath);
    std::string backupPath = utf8Path + ".old";

    /* Remove previous backup */
    try {
        std::filesystem::remove(backupPath);
        std::filesystem::rename(utf8Path, backupPath);
    } catch (...) {
        /* Best effort rotation */
    }

    /* Reopen fresh log */
    m_File.open(utf8Path, std::ios::out | std::ios::trunc);
    if (m_File.is_open()) {
        m_File << "[" << GetTimestamp() << "][INFO][Logger] Log rotated (previous saved as .old)\n";
        m_File.flush();
    }
}

/* ============================================================================
 * Write to Windows Event Log
 * ============================================================================ */
void Logger::WriteToEventLog(LogLevel level, const std::string& message)
{
    if (!m_EventLog) return;

    WORD eventType = EVENTLOG_INFORMATION_TYPE;
    switch (level) {
    case LogLevel::WARNING:  eventType = EVENTLOG_WARNING_TYPE;     break;
    case LogLevel::ERR:      eventType = EVENTLOG_ERROR_TYPE;       break;
    case LogLevel::CRITICAL: eventType = EVENTLOG_ERROR_TYPE;       break;
    default: break;
    }

    std::wstring wMsg = Utf8ToWide(message);
    const wchar_t* strings[] = { wMsg.c_str() };

    ReportEventW(
        m_EventLog,
        eventType,
        0,          /* Category */
        0,          /* Event ID */
        nullptr,    /* SID */
        1,          /* Number of strings */
        0,          /* Data size */
        strings,
        nullptr);   /* Data */
}

} /* namespace blud */
