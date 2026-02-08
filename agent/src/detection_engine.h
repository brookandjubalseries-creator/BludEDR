/*
 * BludEDR - detection_engine.h
 * Rule-based detection pipeline with evaluators for each event type
 */

#pragma once
#include "../inc/agent.h"

namespace blud {

/* ============================================================================
 * Detection rule structure
 * ============================================================================ */
struct DetectionRule {
    ULONG           ruleId;
    std::string     name;
    double          score;
    IOC_SEVERITY    severity;
    IOC_CATEGORY    category;

    /* Evaluator function pointers - one per event type.
     * Each returns true if the rule matched. */
    std::function<bool(const SENTINEL_PROCESS_EVENT&)>      processEval;
    std::function<bool(const SENTINEL_THREAD_EVENT&)>       threadEval;
    std::function<bool(const SENTINEL_IMAGE_EVENT&)>        imageEval;
    std::function<bool(const SENTINEL_FILE_EVENT&)>         fileEval;
    std::function<bool(const SENTINEL_REGISTRY_EVENT&)>     registryEval;
    std::function<bool(const SENTINEL_OBJECT_EVENT&)>       objectEval;
    std::function<bool(const SENTINEL_MEMORY_EVENT&)>       memoryEval;
};

class DetectionEngine {
public:
    DetectionEngine();
    ~DetectionEngine();

    void Initialize();
    void Shutdown();

    /* Evaluate events against all applicable rules */
    void EvaluateProcessEvent(const SENTINEL_PROCESS_EVENT& evt);
    void EvaluateThreadEvent(const SENTINEL_THREAD_EVENT& evt);
    void EvaluateImageEvent(const SENTINEL_IMAGE_EVENT& evt);
    void EvaluateFileEvent(const SENTINEL_FILE_EVENT& evt);
    void EvaluateRegistryEvent(const SENTINEL_REGISTRY_EVENT& evt);
    void EvaluateObjectEvent(const SENTINEL_OBJECT_EVENT& evt);
    void EvaluateMemoryEvent(const SENTINEL_MEMORY_EVENT& evt);

    /* Add a custom rule */
    void AddRule(DetectionRule rule);

    /* Singleton */
    static DetectionEngine& Instance();

private:
    /* Register all built-in rules */
    void RegisterBuiltinRules();

    /* Trigger a match: push score and alert */
    void OnRuleMatch(const DetectionRule& rule, DWORD pid, const std::string& detail);

    std::vector<DetectionRule>  m_Rules;
    mutable SRWLOCK             m_Lock;

    static DetectionEngine* s_Instance;
};

} /* namespace blud */
