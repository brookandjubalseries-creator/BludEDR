/*
 * BludEDR - console_dashboard.h
 * Real-time colored console TUI using Windows Console API
 */

#pragma once
#include "../inc/agent.h"

namespace blud {

class ConsoleDashboard {
public:
    ConsoleDashboard();
    ~ConsoleDashboard();

    /* Start the dashboard refresh thread */
    void Start();

    /* Stop the dashboard */
    void Stop();

    /* Check if running */
    bool IsRunning() const { return m_Running.load(std::memory_order_acquire); }

    /* Singleton */
    static ConsoleDashboard& Instance();

private:
    /* Refresh thread */
    static DWORD WINAPI RefreshThreadProc(LPVOID param);
    void RefreshLoop();

    /* Draw individual sections */
    void DrawHeader();
    void DrawProcessList();
    void DrawAlertFeed();
    void DrawEventCounters();
    void DrawSystemStats();

    /* Console helpers */
    void SetColor(WORD attributes);
    void SetCursorPos(SHORT x, SHORT y);
    void ClearScreen();
    void WriteAt(SHORT x, SHORT y, const std::string& text, WORD color);
    void DrawHorizontalLine(SHORT y, SHORT width, WORD color);

    /* Color codes for IoC scores */
    WORD GetScoreColor(double score) const;

    /* Format helpers */
    std::string FormatUptime() const;
    std::string FormatNumber(uint64_t n) const;
    std::string FormatEventsPerSec() const;

    HANDLE              m_Console;
    HANDLE              m_RefreshThread;
    std::atomic<bool>   m_Running;
    uint64_t            m_StartTick;

    /* For events/sec calculation */
    uint64_t            m_LastEventCount;
    uint64_t            m_LastCountTick;
    double              m_EventsPerSec;

    /* Console dimensions */
    static constexpr SHORT CONSOLE_WIDTH = 120;
    static constexpr SHORT CONSOLE_HEIGHT = 50;

    /* Color constants */
    static constexpr WORD CLR_HEADER       = FOREGROUND_RED | FOREGROUND_INTENSITY;
    static constexpr WORD CLR_TITLE        = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    static constexpr WORD CLR_NORMAL       = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    static constexpr WORD CLR_DIM          = FOREGROUND_INTENSITY;
    static constexpr WORD CLR_GREEN        = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    static constexpr WORD CLR_YELLOW       = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    static constexpr WORD CLR_RED          = FOREGROUND_RED | FOREGROUND_INTENSITY;
    static constexpr WORD CLR_BRIGHT_RED   = FOREGROUND_RED | FOREGROUND_INTENSITY | BACKGROUND_RED;
    static constexpr WORD CLR_CYAN         = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    static constexpr WORD CLR_BORDER       = FOREGROUND_BLUE | FOREGROUND_INTENSITY;

    static ConsoleDashboard* s_Instance;
};

} /* namespace blud */
