/*
 * BludEDR - ioc_scoring.h
 * Weighted IoC scoring per process with time-decay and lineage inheritance
 */

#pragma once
#include "../inc/agent.h"

namespace blud {

/* ============================================================================
 * Score entry with timestamp for decay calculation
 * ============================================================================ */
struct ScoreEntry {
    ULONG           ruleId;
    double          baseScore;
    IOC_SEVERITY    severity;
    IOC_CATEGORY    category;
    double          timestamp;  /* seconds since epoch, from GetTickCount64 / 1000 */
};

class IoCScoring {
public:
    IoCScoring();
    ~IoCScoring();

    void Initialize();
    void Shutdown();

    /* Add a score contribution for a process */
    void AddScore(DWORD pid, ULONG ruleId, double score, IOC_CATEGORY category);

    /* Get current (time-decayed) score for a process */
    double GetCurrentScore(DWORD pid) const;

    /* Get the recommended action based on thresholds */
    ALERT_ACTION GetAction(DWORD pid) const;

    /* Get action from raw score */
    static ALERT_ACTION GetActionForScore(double score);

    /* Clear scores for a process (e.g. on termination) */
    void ClearProcess(DWORD pid);

    /* Singleton */
    static IoCScoring& Instance();

private:
    /* Decay half-life in seconds */
    static constexpr double DECAY_HALF_LIFE = 300.0;  /* 5 minutes */

    /* Parent contribution factor */
    static constexpr double PARENT_CONTRIBUTION = 0.30;

    /* Apply time decay to a base score */
    static double ApplyDecay(double baseScore, double entryTime, double now);

    /* Get current time in seconds */
    static double NowSeconds();

    mutable SRWLOCK                                         m_Lock;
    std::unordered_map<DWORD, std::vector<ScoreEntry>>      m_Scores;

    static IoCScoring* s_Instance;
};

} /* namespace blud */
