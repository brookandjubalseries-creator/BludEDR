/*
 * BludEDR - process_tree.cpp
 * In-memory parent-child process tree protected by SRWLOCK
 */

#include "process_tree.h"
#include "logger.h"

namespace blud {

ProcessTree* ProcessTree::s_Instance = nullptr;

ProcessTree::ProcessTree()
{
    InitializeSRWLock(&m_Lock);
    s_Instance = this;
}

ProcessTree::~ProcessTree()
{
    s_Instance = nullptr;
}

ProcessTree& ProcessTree::Instance()
{
    static ProcessTree instance;
    return instance;
}

void ProcessTree::Initialize()
{
    /* Could snapshot running processes via CreateToolhelp32Snapshot here */
    LOG_INFO("ProcessTree", "Initialized");
}

void ProcessTree::Shutdown()
{
    {
        SrwExclusiveLock lock(m_Lock);
        m_Processes.clear();
    }
    LOG_INFO("ProcessTree", "Shut down");
}

/* ============================================================================
 * Add a process
 * ============================================================================ */
void ProcessTree::AddProcess(DWORD pid, DWORD ppid,
                             const std::wstring& imagePath,
                             const std::wstring& commandLine,
                             LARGE_INTEGER creationTime)
{
    ProcessNode node;
    node.pid = pid;
    node.ppid = ppid;
    node.imagePath = imagePath;
    node.commandLine = commandLine;
    node.creationTime = creationTime;
    node.iocScore = 0.0;

    {
        SrwExclusiveLock lock(m_Lock);

        m_Processes[pid] = std::move(node);

        /* Register this process as a child of its parent */
        auto parentIt = m_Processes.find(ppid);
        if (parentIt != m_Processes.end()) {
            parentIt->second.children.push_back(pid);
        }
    }
}

/* ============================================================================
 * Remove a terminated process
 * ============================================================================ */
void ProcessTree::RemoveProcess(DWORD pid)
{
    SrwExclusiveLock lock(m_Lock);

    auto it = m_Processes.find(pid);
    if (it != m_Processes.end()) {
        /* Remove from parent's children list */
        auto parentIt = m_Processes.find(it->second.ppid);
        if (parentIt != m_Processes.end()) {
            auto& siblings = parentIt->second.children;
            siblings.erase(
                std::remove(siblings.begin(), siblings.end(), pid),
                siblings.end());
        }

        /* Re-parent children to the terminated process's parent */
        for (DWORD childPid : it->second.children) {
            auto childIt = m_Processes.find(childPid);
            if (childIt != m_Processes.end()) {
                childIt->second.ppid = it->second.ppid;
                if (parentIt != m_Processes.end()) {
                    parentIt->second.children.push_back(childPid);
                }
            }
        }

        m_Processes.erase(it);
    }
}

/* ============================================================================
 * Get a copy of a process node
 * ============================================================================ */
bool ProcessTree::GetProcess(DWORD pid, ProcessNode& outNode) const
{
    SrwSharedLock lock(m_Lock);
    auto it = m_Processes.find(pid);
    bool found = (it != m_Processes.end());
    if (found) {
        outNode = it->second;
    }
    return found;
}

/* ============================================================================
 * Get ancestors (walking up parent chain)
 * ============================================================================ */
std::vector<ProcessNode> ProcessTree::GetAncestors(DWORD pid, int maxDepth) const
{
    std::vector<ProcessNode> result;

    SrwSharedLock lock(m_Lock);

    DWORD current = pid;
    for (int i = 0; i < maxDepth; ++i) {
        auto it = m_Processes.find(current);
        if (it == m_Processes.end()) break;

        DWORD parentPid = it->second.ppid;
        if (parentPid == 0 || parentPid == current) break;

        auto parentIt = m_Processes.find(parentPid);
        if (parentIt == m_Processes.end()) break;

        result.push_back(parentIt->second);
        current = parentPid;
    }

    return result;
}

/* ============================================================================
 * Get all descendants (recursive)
 * ============================================================================ */
std::vector<ProcessNode> ProcessTree::GetDescendants(DWORD pid) const
{
    std::vector<ProcessNode> result;

    SrwSharedLock lock(m_Lock);
    CollectDescendants(pid, result);

    return result;
}

void ProcessTree::CollectDescendants(DWORD pid, std::vector<ProcessNode>& out) const
{
    auto it = m_Processes.find(pid);
    if (it == m_Processes.end()) return;

    for (DWORD childPid : it->second.children) {
        auto childIt = m_Processes.find(childPid);
        if (childIt != m_Processes.end()) {
            out.push_back(childIt->second);
            CollectDescendants(childPid, out);
        }
    }
}

/* ============================================================================
 * Compute depth from explorer.exe
 * ============================================================================ */
int ProcessTree::GetDepthFromExplorer(DWORD pid) const
{
    SrwSharedLock lock(m_Lock);

    int depth = 0;
    DWORD current = pid;
    const int MAX_WALK = 64;

    for (int i = 0; i < MAX_WALK; ++i) {
        auto it = m_Processes.find(current);
        if (it == m_Processes.end()) break;

        std::wstring name = ToLowerW(ExtractFilename(it->second.imagePath));
        if (name == L"explorer.exe") {
            return depth;
        }

        DWORD parentPid = it->second.ppid;
        if (parentPid == 0 || parentPid == current) break;

        current = parentPid;
        ++depth;
    }

    return -1; /* explorer.exe not found in ancestry */
}

/* ============================================================================
 * Get full lineage (ancestors + self + descendants)
 * ============================================================================ */
std::vector<ProcessNode> ProcessTree::GetLineage(DWORD pid) const
{
    std::vector<ProcessNode> result;

    /* Ancestors in reverse order (root first) */
    auto ancestors = GetAncestors(pid, 32);
    std::reverse(ancestors.begin(), ancestors.end());
    result.insert(result.end(), ancestors.begin(), ancestors.end());

    /* Self */
    ProcessNode self;
    if (GetProcess(pid, self)) {
        result.push_back(self);
    }

    /* Descendants */
    auto descendants = GetDescendants(pid);
    result.insert(result.end(), descendants.begin(), descendants.end());

    return result;
}

/* ============================================================================
 * Get top N processes by IoC score
 * ============================================================================ */
std::vector<ProcessNode> ProcessTree::GetTopByScore(int count) const
{
    std::vector<ProcessNode> all;

    {
        SrwSharedLock lock(m_Lock);
        all.reserve(m_Processes.size());
        for (auto& [pid, node] : m_Processes) {
            (void)pid;
            all.push_back(node);
        }
    }

    /* Sort descending by IoC score */
    std::sort(all.begin(), all.end(),
        [](const ProcessNode& a, const ProcessNode& b) {
            return a.iocScore > b.iocScore;
        });

    if ((int)all.size() > count) {
        all.resize(count);
    }
    return all;
}

/* ============================================================================
 * Update IoC score
 * ============================================================================ */
void ProcessTree::UpdateScore(DWORD pid, double score)
{
    SrwExclusiveLock lock(m_Lock);
    auto it = m_Processes.find(pid);
    if (it != m_Processes.end()) {
        it->second.iocScore = score;
    }
}

/* ============================================================================
 * Get process count
 * ============================================================================ */
size_t ProcessTree::GetProcessCount() const
{
    SrwSharedLock lock(m_Lock);
    return m_Processes.size();
}

} /* namespace blud */
