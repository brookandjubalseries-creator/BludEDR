/*
 * BludEDR - callstack_analyzer.cpp
 * Callstack analysis for detecting code execution from unbacked memory
 */

#include "../inc/callstack_analyzer.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <sstream>

#pragma comment(lib, "psapi.lib")

namespace blud {

CallstackAnalyzer::CallstackAnalyzer() {}

CallstackAnalyzer::~CallstackAnalyzer() {
    Shutdown();
}

bool CallstackAnalyzer::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);

    /* Initialize DbgHelp symbol handler for our process */
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    m_symbolsInitialized = SymInitialize(GetCurrentProcess(), nullptr, TRUE);

    return true; /* We can still work without symbols */
}

void CallstackAnalyzer::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_symbolsInitialized) {
        SymCleanup(GetCurrentProcess());
        m_symbolsInitialized = false;
    }

    m_moduleCache.clear();
}

void CallstackAnalyzer::LoadModulesForProcess(DWORD pid, ProcessModuleCache& cache) {
    cache.Modules.clear();

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    HMODULE modules[1024];
    DWORD needed = 0;

    if (EnumProcessModulesEx(hProcess, modules, sizeof(modules), &needed,
                              LIST_MODULES_ALL))
    {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            MODULEINFO mi = {};
            WCHAR moduleName[MAX_PATH] = {};
            WCHAR modulePath[MAX_PATH] = {};

            if (GetModuleInformation(hProcess, modules[i], &mi, sizeof(mi)) &&
                GetModuleBaseNameW(hProcess, modules[i], moduleName, MAX_PATH) &&
                GetModuleFileNameExW(hProcess, modules[i], modulePath, MAX_PATH))
            {
                ModuleInfo info;
                info.BaseAddress = mi.lpBaseOfDll;
                info.Size = mi.SizeOfImage;
                info.Name = moduleName;
                info.Path = modulePath;
                cache.Modules.push_back(std::move(info));
            }
        }
    }

    CloseHandle(hProcess);
    cache.LastRefreshTick = GetTickCount64();
}

void CallstackAnalyzer::RefreshModuleCache(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& cache = m_moduleCache[pid];
    LoadModulesForProcess(pid, cache);
}

bool CallstackAnalyzer::IsAddressInModule(DWORD pid, PVOID address) {
    return GetModuleForAddress(pid, address) != nullptr;
}

const ModuleInfo* CallstackAnalyzer::GetModuleForAddress(DWORD pid, PVOID address) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto& cache = m_moduleCache[pid];

    /* Refresh if stale */
    ULONGLONG now = GetTickCount64();
    if (cache.Modules.empty() || (now - cache.LastRefreshTick) > MODULE_CACHE_TTL_MS) {
        LoadModulesForProcess(pid, cache);
    }

    uintptr_t addr = (uintptr_t)address;
    for (const auto& mod : cache.Modules) {
        uintptr_t modStart = (uintptr_t)mod.BaseAddress;
        uintptr_t modEnd = modStart + mod.Size;
        if (addr >= modStart && addr < modEnd) {
            return &mod;
        }
    }

    return nullptr;
}

CallstackAnalysis CallstackAnalyzer::AnalyzeCallstack(DWORD pid, PVOID* frames, ULONG frameCount) {
    CallstackAnalysis result;
    result.HasUnbackedFrames = false;
    result.IsSuspicious = false;

    if (!frames || frameCount == 0) return result;

    for (ULONG i = 0; i < frameCount; i++) {
        if (!frames[i]) continue;

        CallstackFrame frame;
        frame.Address = frames[i];
        frame.ReturnAddress = (i + 1 < frameCount) ? frames[i + 1] : nullptr;
        frame.Displacement = 0;
        frame.IsUnbacked = false;

        const ModuleInfo* mod = GetModuleForAddress(pid, frames[i]);
        if (mod) {
            frame.ModuleName = mod->Name;
        } else {
            frame.IsUnbacked = true;
            frame.ModuleName = L"<UNBACKED>";
            result.HasUnbackedFrames = true;
        }

        /* Try to resolve symbol name using DbgHelp */
        if (m_symbolsInitialized) {
            char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
            auto* symbol = reinterpret_cast<PSYMBOL_INFO>(symbolBuffer);
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            symbol->MaxNameLen = MAX_SYM_NAME;

            DWORD64 displacement64 = 0;
            /* Note: This resolves against our own process symbols.
               For remote process resolution, we'd need SymInitialize on hProcess. */
            if (SymFromAddr(GetCurrentProcess(), (DWORD64)frames[i], &displacement64, symbol)) {
                frame.SymbolName = symbol->Name;
                frame.Displacement = (DWORD)displacement64;
            }
        }

        result.Frames.push_back(std::move(frame));
    }

    /* Determine if suspicious */
    if (result.HasUnbackedFrames) {
        result.IsSuspicious = true;

        std::wostringstream ss;
        ss << L"Unbacked execution at: ";
        for (const auto& f : result.Frames) {
            if (f.IsUnbacked) {
                ss << L"0x" << std::hex << (uintptr_t)f.Address << L" ";
            }
        }
        result.Summary = ss.str();
    }

    return result;
}

CallstackAnalysis CallstackAnalyzer::WalkThread(DWORD pid, DWORD tid) {
    CallstackAnalysis result;
    result.HasUnbackedFrames = false;
    result.IsSuspicious = false;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return result;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                                 THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!hThread) {
        CloseHandle(hProcess);
        return result;
    }

    /* Suspend thread to capture context */
    if (SuspendThread(hThread) == (DWORD)-1) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return result;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    if (GetThreadContext(hThread, &ctx)) {
        /* Initialize StackWalk64 */
        STACKFRAME64 sf = {};
        sf.AddrPC.Offset = ctx.Rip;
        sf.AddrPC.Mode = AddrModeFlat;
        sf.AddrFrame.Offset = ctx.Rbp;
        sf.AddrFrame.Mode = AddrModeFlat;
        sf.AddrStack.Offset = ctx.Rsp;
        sf.AddrStack.Mode = AddrModeFlat;

        /* Initialize symbols for target process */
        SymInitialize(hProcess, nullptr, TRUE);

        PVOID frames[SENTINEL_MAX_CALLSTACK];
        ULONG frameCount = 0;

        for (ULONG i = 0; i < SENTINEL_MAX_CALLSTACK; i++) {
            if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread,
                           &sf, &ctx, nullptr,
                           SymFunctionTableAccess64, SymGetModuleBase64, nullptr))
            {
                break;
            }

            if (sf.AddrPC.Offset == 0) break;

            frames[i] = (PVOID)sf.AddrPC.Offset;
            frameCount++;
        }

        SymCleanup(hProcess);

        /* Analyze the captured frames */
        result = AnalyzeCallstack(pid, frames, frameCount);
    }

    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return result;
}

} // namespace blud
