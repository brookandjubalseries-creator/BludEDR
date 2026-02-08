/*
 * BludEDR - alert_manager.h
 * Alert generation, response actions, and alert history
 */

#pragma once
#include "../inc/agent.h"

namespace blud {

/* ============================================================================
 * Alert structure
 * ============================================================================ */
struct Alert {
    uint64_t        timestamp;      /* GetTickCount64 */
    DWORD           pid;
    std::wstring    imageName;
    double          score;
    ALERT_ACTION    action;
    ULONG           ruleId;
    std::string     ruleName;
    std::string     description;
};

class AlertManager {
public:
    AlertManager();
    ~AlertManager();

    void Initialize();
    void Shutdown();

    /* Process an alert: log it and take action based on score thresholds */
    void ProcessAlert(DWORD pid, double score, ULONG ruleId,
                      const std::string& ruleName, const std::string& description);

    /* Get recent alerts (thread-safe copy) */
    std::vector<Alert> GetRecentAlerts(int count = 15) const;

    /* Get total alert count */
    uint64_t GetTotalAlertCount() const { return m_TotalAlerts.load(std::memory_order_relaxed); }

    /* Singleton */
    static AlertManager& Instance();

private:
    /* Execute response action */
    void ExecuteAction(DWORD pid, ALERT_ACTION action, const std::string& reason);

    /* Send suspend command to driver */
    bool SuspendProcess(DWORD pid);

    /* Send terminate command to driver */
    bool TerminateProcess(DWORD pid);

    static constexpr size_t MAX_ALERT_HISTORY = 1000;

    mutable SRWLOCK         m_Lock;
    std::deque<Alert>       m_AlertHistory;
    std::atomic<uint64_t>   m_TotalAlerts;

    static AlertManager* s_Instance;
};

} /* namespace blud */
