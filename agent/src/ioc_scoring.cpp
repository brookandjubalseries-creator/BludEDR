/*
 * BludEDR - ioc_scoring.cpp
 * Time-decaying IoC scores with 5-minute half-life and lineage inheritance
 */

#include "ioc_scoring.h"
#include "process_tree.h"
#include "logger.h"

namespace blud {

IoCScoring* IoCScoring::s_Instance = nullptr;

IoCScoring::IoCScoring()
{
    InitializeSRWLock(&m_Lock);
    s_Instance = this;
}

IoCScoring::~IoCScoring()
{
    s_Instance = nullptr;
}

IoCScoring& IoCScoring::Instance()
{
    static IoCScoring instance;
    return instance;
}

void IoCScoring::Initialize()
{
    LOG_INFO("IoCScoring", "Initialized (half-life=" +
        std::to_string((int)DECAY_HALF_LIFE) + "s, parent_contrib=" +
        std::to_string((int)(PARENT_CONTRIBUTION * 100)) + "%)");
}

void IoCScoring::Shutdown()
{
    AcquireSRWLockExclusive(&m_Lock);
    m_Scores.clear();
    ReleaseSRWLockExclusive(&m_Lock);
    LOG_INFO("IoCScoring", "Shut down");
}

/* ============================================================================
 * Time helpers
 * ============================================================================ */
double IoCScoring::NowSeconds()
{
    return static_cast<double>(GetTickCount64()) / 1000.0;
}

/* score * 2^(-elapsed / half_life) */
double IoCScoring::ApplyDecay(double baseScore, double entryTime, double now)
{
    double elapsed = now - entryTime;
    if (elapsed <= 0.0) return baseScore;
    return baseScore * std::pow(2.0, -elapsed / DECAY_HALF_LIFE);
}

/* ============================================================================
 * Add a score for a process
 * ============================================================================ */
void IoCScoring::AddScore(DWORD pid, ULONG ruleId, double score, IOC_CATEGORY category)
{
    /* Determine severity from score */
    IOC_SEVERITY severity;
    if (score >= 90.0)      severity = IOC_SEVERITY_CRITICAL;
    else if (score >= 75.0) severity = IOC_SEVERITY_VERY_HIGH;
    else if (score >= 50.0) severity = IOC_SEVERITY_HIGH;
    else if (score >= 25.0) severity = IOC_SEVERITY_MEDIUM;
    else if (score >= 1.0)  severity = IOC_SEVERITY_LOW;
    else                    severity = IOC_SEVERITY_INFO;

    ScoreEntry entry;
    entry.ruleId = ruleId;
    entry.baseScore = score;
    entry.severity = severity;
    entry.category = category;
    entry.timestamp = NowSeconds();

    AcquireSRWLockExclusive(&m_Lock);
    m_Scores[pid].push_back(entry);
    ReleaseSRWLockExclusive(&m_Lock);

    /* Update the process tree node score */
    double currentScore = GetCurrentScore(pid);
    ProcessTree::Instance().UpdateScore(pid, currentScore);

    /* Lineage inheritance: propagate fraction of score to parent */
    ProcessNode node;
    if (ProcessTree::Instance().GetProcess(pid, node) && node.ppid != 0) {
        double inheritedScore = score * PARENT_CONTRIBUTION;
        if (inheritedScore >= 1.0) {
            ScoreEntry parentEntry;
            parentEntry.ruleId = ruleId;
            parentEntry.baseScore = inheritedScore;
            parentEntry.severity = IOC_SEVERITY_INFO;
            parentEntry.category = category;
            parentEntry.timestamp = NowSeconds();

            AcquireSRWLockExclusive(&m_Lock);
            m_Scores[node.ppid].push_back(parentEntry);
            ReleaseSRWLockExclusive(&m_Lock);

            double parentScore = GetCurrentScore(node.ppid);
            ProcessTree::Instance().UpdateScore(node.ppid, parentScore);
        }
    }
}

/* ============================================================================
 * Get current time-decayed score
 * ============================================================================ */
double IoCScoring::GetCurrentScore(DWORD pid) const
{
    double now = NowSeconds();
    double total = 0.0;

    AcquireSRWLockShared(&m_Lock);

    auto it = m_Scores.find(pid);
    if (it != m_Scores.end()) {
        for (const auto& entry : it->second) {
            total += ApplyDecay(entry.baseScore, entry.timestamp, now);
        }
    }

    ReleaseSRWLockShared(&m_Lock);

    /* Clamp to 0-100 range */
    if (total > 100.0) total = 100.0;
    if (total < 0.0)   total = 0.0;

    return total;
}

/* ============================================================================
 * Get recommended action from current score
 * ============================================================================ */
ALERT_ACTION IoCScoring::GetAction(DWORD pid) const
{
    double score = GetCurrentScore(pid);
    return GetActionForScore(score);
}

ALERT_ACTION IoCScoring::GetActionForScore(double score)
{
    if (score >= 90.0) return ACTION_TERMINATE;
    if (score >= 80.0) return ACTION_SUSPEND;
    if (score >= 50.0) return ACTION_ALERT;
    return ACTION_LOG;
}

/* ============================================================================
 * Clear scores for a terminated process
 * ============================================================================ */
void IoCScoring::ClearProcess(DWORD pid)
{
    AcquireSRWLockExclusive(&m_Lock);
    m_Scores.erase(pid);
    ReleaseSRWLockExclusive(&m_Lock);
}

} /* namespace blud */
