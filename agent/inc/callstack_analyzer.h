/*
 * BludEDR - callstack_analyzer.h
 * Callstack analysis with StackWalk64 / DbgHelp integration
 */

#pragma once

#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

#pragma comment(lib, "dbghelp.lib")

namespace blud {

struct ModuleInfo {
    PVOID       BaseAddress;
    SIZE_T      Size;
    std::wstring Name;
    std::wstring Path;
};

struct CallstackFrame {
    PVOID       Address;
    PVOID       ReturnAddress;
    std::wstring ModuleName;
    std::string  SymbolName;
    DWORD        Displacement;
    bool         IsUnbacked;    /* Executing from non-module memory */
};

struct CallstackAnalysis {
    std::vector<CallstackFrame> Frames;
    bool        HasUnbackedFrames;  /* Any frame outside loaded modules */
    bool        IsSuspicious;
    std::wstring Summary;
};

class CallstackAnalyzer {
public:
    CallstackAnalyzer();
    ~CallstackAnalyzer();

    bool Initialize();
    void Shutdown();

    /* Analyze a callstack from SENTINEL_MEMORY_EVENT */
    CallstackAnalysis AnalyzeCallstack(DWORD pid, PVOID* frames, ULONG frameCount);

    /* Walk the callstack of a specific thread */
    CallstackAnalysis WalkThread(DWORD pid, DWORD tid);

    /* Refresh module list for a process */
    void RefreshModuleCache(DWORD pid);

    /* Check if an address is within a loaded module */
    bool IsAddressInModule(DWORD pid, PVOID address);

    /* Get module containing an address */
    const ModuleInfo* GetModuleForAddress(DWORD pid, PVOID address);

private:
    /* Per-process module cache */
    struct ProcessModuleCache {
        std::vector<ModuleInfo> Modules;
        ULONGLONG LastRefreshTick;
    };

    void LoadModulesForProcess(DWORD pid, ProcessModuleCache& cache);

    std::unordered_map<DWORD, ProcessModuleCache> m_moduleCache;
    std::mutex m_mutex;
    bool m_symbolsInitialized = false;

    static constexpr ULONGLONG MODULE_CACHE_TTL_MS = 5000; /* Refresh every 5 seconds */
};

} // namespace blud
