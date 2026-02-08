/*
 * BludEDR - process_tree.h
 * In-memory parent-child process tree with thread-safe access
 */

#pragma once
#include "../inc/agent.h"

namespace blud {

/* ============================================================================
 * Process node in the tree
 * ============================================================================ */
struct ProcessNode {
    DWORD               pid;
    DWORD               ppid;
    std::wstring        imagePath;
    std::wstring        commandLine;
    std::vector<DWORD>  children;
    LARGE_INTEGER       creationTime;
    double              iocScore;

    ProcessNode()
        : pid(0), ppid(0), iocScore(0.0)
    {
        creationTime.QuadPart = 0;
    }
};

class ProcessTree {
public:
    ProcessTree();
    ~ProcessTree();

    /* Initialize (snapshot current processes if desired) */
    void Initialize();

    /* Shut down */
    void Shutdown();

    /* Add a new process */
    void AddProcess(DWORD pid, DWORD ppid,
                    const std::wstring& imagePath,
                    const std::wstring& commandLine,
                    LARGE_INTEGER creationTime);

    /* Remove a terminated process */
    void RemoveProcess(DWORD pid);

    /* Get a copy of a process node */
    bool GetProcess(DWORD pid, ProcessNode& outNode) const;

    /* Get ancestor chain (walking up parent links) */
    std::vector<ProcessNode> GetAncestors(DWORD pid, int maxDepth = 10) const;

    /* Get all descendants (recursive children) */
    std::vector<ProcessNode> GetDescendants(DWORD pid) const;

    /* Compute depth from explorer.exe in the tree */
    int GetDepthFromExplorer(DWORD pid) const;

    /* Get full lineage: ancestors + self + descendants */
    std::vector<ProcessNode> GetLineage(DWORD pid) const;

    /* Get the top N processes by IoC score */
    std::vector<ProcessNode> GetTopByScore(int count) const;

    /* Update IoC score for a process */
    void UpdateScore(DWORD pid, double score);

    /* Get number of tracked processes */
    size_t GetProcessCount() const;

    /* Singleton */
    static ProcessTree& Instance();

private:
    void CollectDescendants(DWORD pid, std::vector<ProcessNode>& out) const;

    mutable SRWLOCK                             m_Lock;
    std::unordered_map<DWORD, ProcessNode>      m_Processes;

    static ProcessTree* s_Instance;
};

} /* namespace blud */
