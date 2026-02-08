/*
 * BludEDR - correlation_engine.cpp
 * Cross-event correlation rules with time windows
 *
 * Correlation patterns:
 *   1. Process Injection: RWX_ALLOC -> REMOTE_WRITE -> REMOTE_THREAD (5s, same target PID)
 *   2. AMSI Bypass + Execution: AMSI_BYPASS -> PROCESS_CREATE(powershell -enc) (10s, same tree)
 *   3. Credential Theft: LSASS_ACCESS -> FILE_WRITE(.dmp) (30s, same source PID)
 *   4. Sleep Obfuscation: RWX -> RW_TO_RX on same region, repeated 3+ times (1s intervals)
 */

#include "../inc/correlation_engine.h"
#include <algorithm>
#include <sstream>

namespace blud {

/* ProcessEventHistory helpers */
std::vector<const CorrelationEvent*> CorrelationEngine::ProcessEventHistory::FindEvents(
    SENTINEL_EVENT_TYPE type, LONGLONG windowTicks) const
{
    std::vector<const CorrelationEvent*> result;
    if (Events.empty()) return result;

    LONGLONG cutoff = Events.back().Timestamp - windowTicks;
    for (auto it = Events.rbegin(); it != Events.rend(); ++it) {
        if (it->Timestamp < cutoff) break;
        if (it->Type == type) {
            result.push_back(&(*it));
        }
    }
    return result;
}

std::vector<const CorrelationEvent*> CorrelationEngine::ProcessEventHistory::FindByTarget(
    DWORD targetPid, LONGLONG windowTicks) const
{
    std::vector<const CorrelationEvent*> result;
    if (Events.empty()) return result;

    LONGLONG cutoff = Events.back().Timestamp - windowTicks;
    for (auto it = Events.rbegin(); it != Events.rend(); ++it) {
        if (it->Timestamp < cutoff) break;
        if (it->TargetProcessId == targetPid) {
            result.push_back(&(*it));
        }
    }
    return result;
}

CorrelationEngine::CorrelationEngine() {}

CorrelationEngine::~CorrelationEngine() {
    Shutdown();
}

bool CorrelationEngine::Initialize() {
    QueryPerformanceFrequency(&m_perfFreq);

    /* Convert time windows to perf counter ticks */
    m_injectionWindowTicks = m_perfFreq.QuadPart * 5;   /* 5 seconds */
    m_amsiWindowTicks = m_perfFreq.QuadPart * 10;       /* 10 seconds */
    m_credWindowTicks = m_perfFreq.QuadPart * 30;       /* 30 seconds */
    m_sleepWindowTicks = m_perfFreq.QuadPart * 3;       /* 3 seconds */

    return true;
}

void CorrelationEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_processHistory.clear();
    m_targetHistory.clear();
}

void CorrelationEngine::ProcessEvent(const CorrelationEvent& event) {
    std::lock_guard<std::mutex> lock(m_mutex);

    /* Store in process history */
    m_processHistory[event.ProcessId].Push(event);

    /* Store in target history if cross-process */
    if (event.TargetProcessId != 0 && event.TargetProcessId != event.ProcessId) {
        m_targetHistory[event.TargetProcessId].Push(event);
    }

    /* Evaluate all correlation rules */
    EvaluateProcessInjection(event);
    EvaluateAmsiBypassExecution(event);
    EvaluateCredentialTheft(event);
    EvaluateSleepObfuscation(event);
}

void CorrelationEngine::EvaluateProcessInjection(const CorrelationEvent& event) {
    /*
     * Pattern: Process Injection
     *   Step 1: NtAllocateVirtualMemory (RWX) targeting another process
     *   Step 2: NtWriteVirtualMemory to the target
     *   Step 3: NtCreateThreadEx / NtQueueApcThread in the target
     * All within 5 seconds, all targeting the same PID
     */

    if (event.Type != EVENT_REMOTE_THREAD && event.Type != EVENT_APC_QUEUE) {
        return;
    }

    DWORD sourcePid = event.ProcessId;
    DWORD targetPid = event.TargetProcessId;
    if (targetPid == 0 || targetPid == sourcePid) return;

    auto& history = m_processHistory[sourcePid];

    /* Look for recent cross-process write to same target */
    auto writes = history.FindEvents(EVENT_MEMORY_WRITE, m_injectionWindowTicks);
    bool hasWrite = false;
    for (auto* w : writes) {
        if (w->TargetProcessId == targetPid) {
            hasWrite = true;
            break;
        }
    }
    if (!hasWrite) return;

    /* Look for recent RWX alloc targeting same process */
    auto allocs = history.FindEvents(EVENT_MEMORY_ALLOC, m_injectionWindowTicks);
    bool hasAlloc = false;
    for (auto* a : allocs) {
        if (a->TargetProcessId == targetPid &&
            (a->Protect & PAGE_EXECUTE_READWRITE))
        {
            hasAlloc = true;
            break;
        }
    }

    /* Even without alloc step, write + remote thread is suspicious */
    CorrelationMatch match;
    match.RuleId = RULE_CORRELATION_MATCH;
    match.RuleName = L"Process Injection";
    match.PrimaryPid = sourcePid;
    match.SecondaryPid = targetPid;
    match.Severity = hasAlloc ? IOC_SEVERITY_CRITICAL : IOC_SEVERITY_VERY_HIGH;
    match.Score = hasAlloc ? 95 : 85;

    std::wostringstream ss;
    ss << L"Process injection detected: PID " << sourcePid
       << L" -> PID " << targetPid;
    if (hasAlloc) ss << L" (full chain: ALLOC+WRITE+THREAD)";
    else ss << L" (WRITE+THREAD)";
    match.Description = ss.str();

    match.MatchedEvents.push_back(event);
    EmitMatch(match);
}

void CorrelationEngine::EvaluateAmsiBypassExecution(const CorrelationEvent& event) {
    /*
     * Pattern: AMSI Bypass + Malicious Execution
     *   Step 1: AMSI bypass detected (AmsiScanBuffer patched)
     *   Step 2: Process creates powershell with -enc or suspicious command
     * Within 10 seconds, same process tree
     */

    if (event.Type != EVENT_PROCESS_CREATE) return;

    /* Check if this is a suspicious powershell launch */
    std::wstring cmdLower = event.Details;
    std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::towlower);

    bool isSuspiciousPowershell =
        (cmdLower.find(L"powershell") != std::wstring::npos) &&
        (cmdLower.find(L"-enc") != std::wstring::npos ||
         cmdLower.find(L"iex") != std::wstring::npos ||
         cmdLower.find(L"invoke-expression") != std::wstring::npos ||
         cmdLower.find(L"downloadstring") != std::wstring::npos);

    if (!isSuspiciousPowershell) return;

    /* Look for AMSI bypass in parent's history */
    auto& parentHistory = m_processHistory[event.ProcessId];
    auto amsiEvents = parentHistory.FindEvents(EVENT_AMSI_BYPASS, m_amsiWindowTicks);

    if (amsiEvents.empty()) return;

    CorrelationMatch match;
    match.RuleId = RULE_CORRELATION_MATCH;
    match.RuleName = L"AMSI Bypass + Execution";
    match.PrimaryPid = event.ProcessId;
    match.SecondaryPid = 0;
    match.Severity = IOC_SEVERITY_CRITICAL;
    match.Score = 100;

    std::wostringstream ss;
    ss << L"AMSI bypass followed by suspicious PowerShell execution in PID "
       << event.ProcessId;
    match.Description = ss.str();

    match.MatchedEvents.push_back(*amsiEvents[0]);
    match.MatchedEvents.push_back(event);
    EmitMatch(match);
}

void CorrelationEngine::EvaluateCredentialTheft(const CorrelationEvent& event) {
    /*
     * Pattern: Credential Theft
     *   Step 1: Handle opened to LSASS with VM_READ
     *   Step 2: File write with .dmp extension
     * Within 30 seconds, same source PID
     */

    if (event.Type != EVENT_FILE_CREATE && event.Type != EVENT_FILE_WRITE) return;

    /* Check if file is a .dmp */
    std::wstring details = event.Details;
    std::transform(details.begin(), details.end(), details.begin(), ::towlower);
    if (details.find(L".dmp") == std::wstring::npos) return;

    /* Look for recent LSASS access */
    auto& history = m_processHistory[event.ProcessId];
    auto objEvents = history.FindEvents(EVENT_OBJECT_HANDLE_CREATE, m_credWindowTicks);

    bool hasLsassAccess = false;
    for (auto* o : objEvents) {
        std::wstring img = o->ImageName;
        std::transform(img.begin(), img.end(), img.begin(), ::towlower);
        if (img.find(L"lsass") != std::wstring::npos) {
            hasLsassAccess = true;
            break;
        }
    }

    if (!hasLsassAccess) return;

    CorrelationMatch match;
    match.RuleId = RULE_CORRELATION_MATCH;
    match.RuleName = L"Credential Theft";
    match.PrimaryPid = event.ProcessId;
    match.SecondaryPid = 0;
    match.Severity = IOC_SEVERITY_CRITICAL;
    match.Score = 100;

    std::wostringstream ss;
    ss << L"Credential dump: PID " << event.ProcessId
       << L" accessed LSASS then wrote .dmp file";
    match.Description = ss.str();

    match.MatchedEvents.push_back(event);
    EmitMatch(match);
}

void CorrelationEngine::EvaluateSleepObfuscation(const CorrelationEvent& event) {
    /*
     * Pattern: Sleep Obfuscation
     *   Rapid RX->RW->RX cycles on the same memory region
     *   3+ cycles within 3 seconds
     */

    if (event.Type != EVENT_MEMORY_PROTECT) return;

    auto& history = m_processHistory[event.ProcessId];
    auto protEvents = history.FindEvents(EVENT_MEMORY_PROTECT, m_sleepWindowTicks);

    /* Count RX<->RW transitions on the same base address */
    int transitionCount = 0;
    PVOID targetAddr = event.Address;

    for (auto* e : protEvents) {
        if (e->Address != targetAddr) continue;

        bool isRxToRw = (e->Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                        (event.Protect & PAGE_READWRITE);
        bool isRwToRx = (e->Protect & PAGE_READWRITE) &&
                        (event.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));

        if (isRxToRw || isRwToRx) {
            transitionCount++;
        }
    }

    if (transitionCount < 6) return; /* Need 3 full cycles */

    CorrelationMatch match;
    match.RuleId = RULE_SLEEP_OBFUSCATION;
    match.RuleName = L"Sleep Obfuscation";
    match.PrimaryPid = event.ProcessId;
    match.SecondaryPid = 0;
    match.Severity = IOC_SEVERITY_HIGH;
    match.Score = 70;

    std::wostringstream ss;
    ss << L"Sleep obfuscation pattern (RX<->RW cycling) at 0x"
       << std::hex << (uintptr_t)event.Address
       << L" in PID " << std::dec << event.ProcessId
       << L" (" << transitionCount << L" transitions)";
    match.Description = ss.str();

    match.MatchedEvents.push_back(event);
    EmitMatch(match);
}

void CorrelationEngine::EmitMatch(const CorrelationMatch& match) {
    m_matchCount++;

    if (m_callback) {
        m_callback(match);
    }
}

void CorrelationEngine::SetCallback(CorrelationCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_callback = std::move(cb);
}

} // namespace blud
