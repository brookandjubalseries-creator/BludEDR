/*
 * BludEDR - alert_manager.cpp
 * Alert generation with score-based response: LOG, ALERT, SUSPEND, TERMINATE
 */

#include "alert_manager.h"
#include "driver_comm.h"
#include "process_tree.h"
#include "ioc_scoring.h"
#include "logger.h"

namespace blud {

AlertManager* AlertManager::s_Instance = nullptr;

AlertManager::AlertManager()
    : m_TotalAlerts(0)
{
    InitializeSRWLock(&m_Lock);
    s_Instance = this;
}

AlertManager::~AlertManager()
{
    s_Instance = nullptr;
}

AlertManager& AlertManager::Instance()
{
    static AlertManager instance;
    return instance;
}

void AlertManager::Initialize()
{
    LOG_INFO("AlertManager", "Initialized (thresholds: LOG<50, ALERT=50-79, SUSPEND=80-89, TERMINATE>=90)");
}

void AlertManager::Shutdown()
{
    {
        SrwExclusiveLock lock(m_Lock);
        m_AlertHistory.clear();
    }
    LOG_INFO("AlertManager", "Shut down");
}

/* ============================================================================
 * Process an alert
 * ============================================================================ */
void AlertManager::ProcessAlert(DWORD pid, double score, ULONG ruleId,
                                const std::string& ruleName,
                                const std::string& description)
{
    ALERT_ACTION action = IoCScoring::GetActionForScore(score);

    /* Build alert record */
    Alert alert;
    alert.timestamp = GetTickCount64();
    alert.pid = pid;
    alert.score = score;
    alert.action = action;
    alert.ruleId = ruleId;
    alert.ruleName = ruleName;
    alert.description = description;

    /* Retrieve image name from process tree */
    ProcessNode node;
    if (ProcessTree::Instance().GetProcess(pid, node)) {
        alert.imageName = ExtractFilename(node.imagePath);
    } else {
        alert.imageName = L"<unknown>";
    }

    /* Store in history */
    {
        SrwExclusiveLock lock(m_Lock);
        m_AlertHistory.push_back(alert);
        while (m_AlertHistory.size() > MAX_ALERT_HISTORY) {
            m_AlertHistory.pop_front();
        }
    }

    m_TotalAlerts.fetch_add(1, std::memory_order_relaxed);

    /* Determine action string for logging */
    const char* actionStr = "LOG";
    switch (action) {
    case ACTION_LOG:        actionStr = "LOG";       break;
    case ACTION_ALERT:      actionStr = "ALERT";     break;
    case ACTION_SUSPEND:    actionStr = "SUSPEND";   break;
    case ACTION_TERMINATE:  actionStr = "TERMINATE"; break;
    }

    std::string logMsg = "[" + std::string(actionStr) + "] PID=" + std::to_string(pid) +
        " Score=" + std::to_string((int)score) +
        " Rule=" + std::to_string(ruleId) +
        " (" + ruleName + ") " +
        " Image=" + WideToUtf8(alert.imageName) +
        " -- " + description;

    /* Log at appropriate level */
    switch (action) {
    case ACTION_LOG:
        LOG_INFO("AlertManager", logMsg);
        break;
    case ACTION_ALERT:
        LOG_WARNING("AlertManager", logMsg);
        break;
    case ACTION_SUSPEND:
        LOG_ERROR("AlertManager", logMsg);
        ExecuteAction(pid, ACTION_SUSPEND, logMsg);
        break;
    case ACTION_TERMINATE:
        LOG_CRITICAL("AlertManager", logMsg);
        ExecuteAction(pid, ACTION_TERMINATE, logMsg);
        break;
    }
}

/* ============================================================================
 * Execute response action
 * ============================================================================ */
void AlertManager::ExecuteAction(DWORD pid, ALERT_ACTION action, const std::string& reason)
{
    switch (action) {
    case ACTION_SUSPEND:
        LOG_WARNING("AlertManager", "Suspending PID " + std::to_string(pid) + ": " + reason);
        SuspendProcess(pid);
        break;

    case ACTION_TERMINATE:
        LOG_CRITICAL("AlertManager", "Terminating PID " + std::to_string(pid) + ": " + reason);
        TerminateProcess(pid);
        break;

    default:
        break;
    }
}

/* ============================================================================
 * Send suspend command to driver
 * ============================================================================ */
bool AlertManager::SuspendProcess(DWORD pid)
{
    SENTINEL_COMMAND cmd = {};
    cmd.CommandType = CMD_SUSPEND_PROCESS;
    cmd.TargetProcessId = pid;
    cmd.Flags = 0;

    SENTINEL_REPLY reply = {};
    bool sent = DriverComm::Instance().SendCommand(cmd, &reply);

    if (!sent) {
        LOG_ERROR("AlertManager", "Failed to send SUSPEND command for PID " + std::to_string(pid));
    }
    return sent;
}

/* ============================================================================
 * Send terminate command to driver
 * ============================================================================ */
bool AlertManager::TerminateProcess(DWORD pid)
{
    SENTINEL_COMMAND cmd = {};
    cmd.CommandType = CMD_TERMINATE_PROCESS;
    cmd.TargetProcessId = pid;
    cmd.Flags = 0;

    SENTINEL_REPLY reply = {};
    bool sent = DriverComm::Instance().SendCommand(cmd, &reply);

    if (!sent) {
        LOG_ERROR("AlertManager", "Failed to send TERMINATE command for PID " + std::to_string(pid));
    }
    return sent;
}

/* ============================================================================
 * Get recent alerts
 * ============================================================================ */
std::vector<Alert> AlertManager::GetRecentAlerts(int count) const
{
    std::vector<Alert> result;

    SrwSharedLock lock(m_Lock);

    int total = static_cast<int>(m_AlertHistory.size());
    int start = (total > count) ? (total - count) : 0;

    for (int i = start; i < total; ++i) {
        result.push_back(m_AlertHistory[i]);
    }

    return result;
}

} /* namespace blud */
