/*
 * BludEDR - console_dashboard.cpp
 * Real-time colored console TUI with ASCII art banner, process list,
 * alert feed, event counters, and system stats. Refreshes every 500ms.
 *
 * Made by @tarry
 */

#include "console_dashboard.h"
#include "process_tree.h"
#include "event_dispatcher.h"
#include "alert_manager.h"
#include "ioc_scoring.h"
#include "driver_comm.h"
#include "logger.h"

#include <iomanip>

namespace blud {

ConsoleDashboard* ConsoleDashboard::s_Instance = nullptr;

ConsoleDashboard::ConsoleDashboard()
    : m_Console(INVALID_HANDLE_VALUE)
    , m_RefreshThread(nullptr)
    , m_Running(false)
    , m_StartTick(0)
    , m_LastEventCount(0)
    , m_LastCountTick(0)
    , m_EventsPerSec(0.0)
{
    s_Instance = this;
}

ConsoleDashboard::~ConsoleDashboard()
{
    Stop();
    s_Instance = nullptr;
}

ConsoleDashboard& ConsoleDashboard::Instance()
{
    static ConsoleDashboard instance;
    return instance;
}

/* ============================================================================
 * Start
 * ============================================================================ */
void ConsoleDashboard::Start()
{
    if (m_Running.load()) return;

    m_Console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (m_Console == INVALID_HANDLE_VALUE) return;

    /* Set console size */
    SMALL_RECT windowSize = { 0, 0, CONSOLE_WIDTH - 1, CONSOLE_HEIGHT - 1 };
    SetConsoleWindowInfo(m_Console, TRUE, &windowSize);

    COORD bufferSize = { CONSOLE_WIDTH, CONSOLE_HEIGHT };
    SetConsoleScreenBufferSize(m_Console, bufferSize);

    /* Hide cursor */
    CONSOLE_CURSOR_INFO cursorInfo;
    cursorInfo.dwSize = 1;
    cursorInfo.bVisible = FALSE;
    SetConsoleCursorInfo(m_Console, &cursorInfo);

    SetConsoleTitleW(L"BludEDR - Endpoint Detection and Response");

    m_StartTick = GetTickCount64();
    m_LastCountTick = m_StartTick;
    m_LastEventCount = 0;
    m_Running.store(true, std::memory_order_release);

    m_RefreshThread = CreateThread(nullptr, 0, RefreshThreadProc, this, 0, nullptr);
}

/* ============================================================================
 * Stop
 * ============================================================================ */
void ConsoleDashboard::Stop()
{
    m_Running.store(false, std::memory_order_release);

    if (m_RefreshThread) {
        WaitForSingleObject(m_RefreshThread, 3000);
        CloseHandle(m_RefreshThread);
        m_RefreshThread = nullptr;
    }

    /* Restore cursor */
    if (m_Console != INVALID_HANDLE_VALUE) {
        CONSOLE_CURSOR_INFO cursorInfo;
        cursorInfo.dwSize = 25;
        cursorInfo.bVisible = TRUE;
        SetConsoleCursorInfo(m_Console, &cursorInfo);
    }
}

/* ============================================================================
 * Refresh thread
 * ============================================================================ */
DWORD WINAPI ConsoleDashboard::RefreshThreadProc(LPVOID param)
{
    auto* self = static_cast<ConsoleDashboard*>(param);
    if (self) self->RefreshLoop();
    return 0;
}

void ConsoleDashboard::RefreshLoop()
{
    while (m_Running.load(std::memory_order_acquire)) {
        ClearScreen();
        DrawHeader();
        DrawProcessList();
        DrawAlertFeed();
        DrawEventCounters();
        DrawSystemStats();

        /* Calculate events/sec */
        uint64_t now = GetTickCount64();
        uint64_t currentEvents = EventDispatcher::Instance().GetCounters().totalEvents.load(std::memory_order_relaxed);
        uint64_t elapsed = now - m_LastCountTick;
        if (elapsed >= 1000) {
            m_EventsPerSec.store(
                static_cast<double>(currentEvents - m_LastEventCount) /
                (static_cast<double>(elapsed) / 1000.0),
                std::memory_order_relaxed);
            m_LastEventCount = currentEvents;
            m_LastCountTick = now;
        }

        Sleep(500);
    }
}

/* ============================================================================
 * Draw ASCII art header
 * ============================================================================ */
void ConsoleDashboard::DrawHeader()
{
    const char* banner[] = {
        R"(  ____  _           _ _____ ____  ____  )",
        R"( | __ )| |_   _  __| | ____|  _ \|  _ \ )",
        R"( |  _ \| | | | |/ _` |  _| | | | | |_) |)",
        R"( | |_) | | |_| | (_| | |___| |_| |  _ < )",
        R"( |____/|_|\__,_|\__,_|_____|____/|_| \_\)",
    };

    for (int i = 0; i < 5; ++i) {
        WriteAt(2, (SHORT)i, banner[i], CLR_HEADER);
    }

    /* Status line */
    std::string status = "  [ACTIVE]  Uptime: " + FormatUptime();
    status += "  |  Driver: ";
    status += DriverComm::Instance().IsConnected() ? "CONNECTED" : "DISCONNECTED";

    WriteAt(2, 6, status, CLR_GREEN);
    DrawHorizontalLine(7, CONSOLE_WIDTH - 2, CLR_BORDER);
}

/* ============================================================================
 * Draw live process list (top 20 by IoC score)
 * ============================================================================ */
void ConsoleDashboard::DrawProcessList()
{
    SHORT startY = 8;
    WriteAt(2, startY, " PROCESS MONITOR (Top 20 by IoC Score)", CLR_TITLE);
    WriteAt(2, startY + 1,
        " PID      PPID     Score  Image Name                    Command Line", CLR_DIM);
    DrawHorizontalLine(startY + 2, CONSOLE_WIDTH - 2, CLR_BORDER);

    auto processes = ProcessTree::Instance().GetTopByScore(20);
    SHORT y = startY + 3;

    for (const auto& proc : processes) {
        if (y >= startY + 23) break;

        std::ostringstream line;
        line << " " << std::left << std::setw(9) << proc.pid
             << std::setw(9) << proc.ppid
             << std::setw(7) << std::fixed << std::setprecision(0) << proc.iocScore
             << std::setw(30) << WideToUtf8(ExtractFilename(proc.imagePath)).substr(0, 29);

        std::string cmdLine = WideToUtf8(proc.commandLine);
        if (cmdLine.length() > 50) cmdLine = cmdLine.substr(0, 47) + "...";
        line << cmdLine;

        WORD color = GetScoreColor(proc.iocScore);
        WriteAt(2, y, line.str(), color);
        ++y;
    }

    /* Fill remaining rows with empty */
    for (; y < startY + 23; ++y) {
        WriteAt(2, y, std::string(CONSOLE_WIDTH - 4, ' '), CLR_NORMAL);
    }

    DrawHorizontalLine(startY + 23, CONSOLE_WIDTH - 2, CLR_BORDER);
}

/* ============================================================================
 * Draw alert feed (last 15 alerts)
 * ============================================================================ */
void ConsoleDashboard::DrawAlertFeed()
{
    SHORT startY = 32;
    WriteAt(2, startY, " ALERT FEED (Last 15)", CLR_TITLE);
    DrawHorizontalLine(startY + 1, CONSOLE_WIDTH - 2, CLR_BORDER);

    auto alerts = AlertManager::Instance().GetRecentAlerts(15);
    SHORT y = startY + 2;

    for (const auto& alert : alerts) {
        if (y >= startY + 17) break;

        /* Format timestamp from tick count */
        uint64_t elapsedSec = (GetTickCount64() - alert.timestamp) / 1000;
        std::string timeAgo;
        if (elapsedSec < 60) timeAgo = std::to_string(elapsedSec) + "s ago";
        else if (elapsedSec < 3600) timeAgo = std::to_string(elapsedSec / 60) + "m ago";
        else timeAgo = std::to_string(elapsedSec / 3600) + "h ago";

        const char* actionStr = "LOG";
        switch (alert.action) {
        case ACTION_LOG:        actionStr = "LOG "; break;
        case ACTION_ALERT:      actionStr = "ALRT"; break;
        case ACTION_SUSPEND:    actionStr = "SUSP"; break;
        case ACTION_TERMINATE:  actionStr = "TERM"; break;
        }

        std::ostringstream line;
        line << " [" << actionStr << "] "
             << std::setw(8) << std::right << timeAgo << "  "
             << "PID=" << std::setw(6) << std::left << alert.pid << " "
             << "R" << alert.ruleId << " "
             << WideToUtf8(alert.imageName).substr(0, 20) << " "
             << alert.description.substr(0, 40);

        WORD color = GetScoreColor(alert.score);
        WriteAt(2, y, line.str(), color);
        ++y;
    }

    for (; y < startY + 17; ++y) {
        WriteAt(2, y, std::string(CONSOLE_WIDTH - 4, ' '), CLR_NORMAL);
    }
}

/* ============================================================================
 * Draw event counters
 * ============================================================================ */
void ConsoleDashboard::DrawEventCounters()
{
    SHORT y = 49 - 4;
    DrawHorizontalLine(y, CONSOLE_WIDTH - 2, CLR_BORDER);
    ++y;

    const auto& c = EventDispatcher::Instance().GetCounters();

    std::ostringstream line;
    line << " Events: "
         << "Proc=" << FormatNumber(c.processEvents.load()) << "  "
         << "Thrd=" << FormatNumber(c.threadEvents.load()) << "  "
         << "Img="  << FormatNumber(c.imageEvents.load()) << "  "
         << "File=" << FormatNumber(c.fileEvents.load()) << "  "
         << "Reg="  << FormatNumber(c.registryEvents.load()) << "  "
         << "Obj="  << FormatNumber(c.objectEvents.load()) << "  "
         << "Mem="  << FormatNumber(c.memoryEvents.load()) << "  "
         << "Net="  << FormatNumber(c.networkEvents.load());

    WriteAt(2, y, line.str(), CLR_CYAN);
}

/* ============================================================================
 * Draw system stats
 * ============================================================================ */
void ConsoleDashboard::DrawSystemStats()
{
    SHORT y = 49 - 2;

    const auto& c = EventDispatcher::Instance().GetCounters();
    uint64_t totalAlerts = AlertManager::Instance().GetTotalAlertCount();

    std::ostringstream line;
    line << " Stats: "
         << "Events/sec=" << std::fixed << std::setprecision(1) << m_EventsPerSec.load(std::memory_order_relaxed) << "  "
         << "Active Procs=" << ProcessTree::Instance().GetProcessCount() << "  "
         << "Total Events=" << FormatNumber(c.totalEvents.load()) << "  "
         << "Alerts=" << FormatNumber(totalAlerts);

    WriteAt(2, y, line.str(), CLR_GREEN);
}

/* ============================================================================
 * Console helpers
 * ============================================================================ */
void ConsoleDashboard::SetColor(WORD attributes)
{
    SetConsoleTextAttribute(m_Console, attributes);
}

void ConsoleDashboard::SetCursorPos(SHORT x, SHORT y)
{
    COORD pos = { x, y };
    SetConsoleCursorPosition(m_Console, pos);
}

void ConsoleDashboard::ClearScreen()
{
    COORD topLeft = { 0, 0 };
    DWORD written;
    DWORD consoleSize = CONSOLE_WIDTH * CONSOLE_HEIGHT;

    FillConsoleOutputCharacterA(m_Console, ' ', consoleSize, topLeft, &written);
    FillConsoleOutputAttribute(m_Console, CLR_NORMAL, consoleSize, topLeft, &written);
    SetCursorPos(0, 0);
}

void ConsoleDashboard::WriteAt(SHORT x, SHORT y, const std::string& text, WORD color)
{
    if (y >= CONSOLE_HEIGHT || x >= CONSOLE_WIDTH) return;

    SetCursorPos(x, y);
    SetColor(color);

    DWORD written;
    std::string truncated = text;
    if ((int)truncated.length() > CONSOLE_WIDTH - x) {
        truncated = truncated.substr(0, CONSOLE_WIDTH - x);
    }
    WriteConsoleA(m_Console, truncated.c_str(), (DWORD)truncated.length(), &written, nullptr);
}

void ConsoleDashboard::DrawHorizontalLine(SHORT y, SHORT width, WORD color)
{
    if (y >= CONSOLE_HEIGHT) return;
    std::string line(width, '-');
    WriteAt(1, y, line, color);
}

/* ============================================================================
 * Get color for IoC score
 * ============================================================================ */
WORD ConsoleDashboard::GetScoreColor(double score) const
{
    if (score < 25.0)   return CLR_GREEN;
    if (score < 50.0)   return CLR_YELLOW;
    if (score < 75.0)   return CLR_RED;
    return CLR_BRIGHT_RED;
}

/* ============================================================================
 * Format helpers
 * ============================================================================ */
std::string ConsoleDashboard::FormatUptime() const
{
    uint64_t elapsed = (GetTickCount64() - m_StartTick) / 1000;
    uint64_t hours = elapsed / 3600;
    uint64_t mins  = (elapsed % 3600) / 60;
    uint64_t secs  = elapsed % 60;

    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(2) << hours << ":"
        << std::setw(2) << mins << ":"
        << std::setw(2) << secs;
    return oss.str();
}

std::string ConsoleDashboard::FormatNumber(uint64_t n) const
{
    if (n >= 1000000) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << (n / 1000000.0) << "M";
        return oss.str();
    }
    if (n >= 1000) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << (n / 1000.0) << "K";
        return oss.str();
    }
    return std::to_string(n);
}

std::string ConsoleDashboard::FormatEventsPerSec() const
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << m_EventsPerSec.load(std::memory_order_relaxed);
    return oss.str();
}

} /* namespace blud */
