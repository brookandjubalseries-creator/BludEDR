/*
 * BludEDR - correlation_engine.h
 * Cross-event correlation rules with time windows
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <atomic>
#include "../../shared/sentinel_shared.h"
#include "../../shared/sentinel_ioc.h"

namespace blud {

/* A correlation event - simplified view of any system event */
struct CorrelationEvent {
    SENTINEL_EVENT_TYPE Type;
    DWORD               ProcessId;
    DWORD               TargetProcessId;    /* For cross-process operations */
    DWORD               ThreadId;
    LONGLONG            Timestamp;          /* Performance counter ticks */
    PVOID               Address;            /* Memory address if relevant */
    DWORD               Protect;            /* Protection flags if relevant */
    DWORD               Access;             /* Access mask if relevant */
    std::wstring        ImageName;
    std::wstring        Details;
};

/* A correlation match result */
struct CorrelationMatch {
    ULONG               RuleId;
    std::wstring        RuleName;
    DWORD               PrimaryPid;
    DWORD               SecondaryPid;
    IOC_SEVERITY        Severity;
    ULONG               Score;
    std::vector<CorrelationEvent> MatchedEvents;
    std::wstring        Description;
};

using CorrelationCallback = std::function<void(const CorrelationMatch&)>;

class CorrelationEngine {
public:
    CorrelationEngine();
    ~CorrelationEngine();

    bool Initialize();
    void Shutdown();

    /* Feed an event into the correlation engine */
    void ProcessEvent(const CorrelationEvent& event);

    /* Set callback for matches */
    void SetCallback(CorrelationCallback cb);

    /* Stats */
    ULONGLONG GetMatchCount() const { return m_matchCount; }

private:
    /* Correlation rule evaluation */
    void EvaluateProcessInjection(const CorrelationEvent& event);
    void EvaluateAmsiBypassExecution(const CorrelationEvent& event);
    void EvaluateCredentialTheft(const CorrelationEvent& event);
    void EvaluateSleepObfuscation(const CorrelationEvent& event);

    /* Emit a correlation match */
    void EmitMatch(const CorrelationMatch& match);

    /* Event history per process (recent events for correlation) */
    struct ProcessEventHistory {
        std::deque<CorrelationEvent> Events;
        static constexpr size_t MAX_EVENTS = 256;

        void Push(const CorrelationEvent& evt) {
            if (Events.size() >= MAX_EVENTS) Events.pop_front();
            Events.push_back(evt);
        }

        /* Find events of a specific type within a time window */
        std::vector<const CorrelationEvent*> FindEvents(
            SENTINEL_EVENT_TYPE type, LONGLONG windowTicks) const;

        /* Find events targeting a specific PID */
        std::vector<const CorrelationEvent*> FindByTarget(
            DWORD targetPid, LONGLONG windowTicks) const;
    };

    /* Event history per target PID (for injection tracking) */
    struct TargetEventHistory {
        std::deque<CorrelationEvent> Events;
        static constexpr size_t MAX_EVENTS = 64;

        void Push(const CorrelationEvent& evt) {
            if (Events.size() >= MAX_EVENTS) Events.pop_front();
            Events.push_back(evt);
        }
    };

    std::unordered_map<DWORD, ProcessEventHistory>  m_processHistory;
    std::unordered_map<DWORD, TargetEventHistory>   m_targetHistory;
    CorrelationCallback                             m_callback;
    std::mutex                                      m_mutex;
    std::atomic<ULONGLONG>                          m_matchCount{0};
    LARGE_INTEGER                                   m_perfFreq;

    /* Time window constants (in seconds, converted to ticks at init) */
    LONGLONG m_injectionWindowTicks;    /* 5 seconds */
    LONGLONG m_amsiWindowTicks;         /* 10 seconds */
    LONGLONG m_credWindowTicks;         /* 30 seconds */
    LONGLONG m_sleepWindowTicks;        /* 3 seconds */
};

} // namespace blud
