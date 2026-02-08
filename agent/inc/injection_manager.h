/*
 * BludEDR - injection_manager.h
 * DLL injection manager for hook DLL deployment
 */

#pragma once

#include <windows.h>
#include <string>
#include <unordered_set>
#include <mutex>
#include <functional>

namespace blud {

class InjectionManager {
public:
    InjectionManager();
    ~InjectionManager();

    bool Initialize(const std::wstring& dllPath);
    void Shutdown();

    /* Inject hook DLL into target process. Called on EVENT_PROCESS_CREATE. */
    bool InjectIntoProcess(DWORD targetPid, const std::wstring& imageName);

    /* Confirm injection succeeded (called on EVENT_IMAGE_LOAD for our DLL) */
    void ConfirmInjection(DWORD pid);

    /* Check if process is already injected */
    bool IsInjected(DWORD pid) const;

    /* Remove process from tracking (on termination) */
    void OnProcessTerminate(DWORD pid);

    /* Get injection stats */
    size_t GetInjectedCount() const;
    size_t GetFailedCount() const;

private:
    /* Injection methods */
    bool InjectViaApc(HANDLE hProcess, DWORD pid);
    bool InjectViaRemoteThread(HANDLE hProcess);

    /* Check if process should be skipped */
    bool ShouldSkip(DWORD pid, const std::wstring& imageName) const;

    std::wstring                    m_dllPath;
    mutable std::mutex              m_mutex;
    std::unordered_set<DWORD>       m_injectedPids;
    std::unordered_set<DWORD>       m_pendingPids;      /* Injected but not confirmed */
    std::unordered_set<DWORD>       m_failedPids;
    std::unordered_set<std::wstring> m_whitelist;
    bool                            m_initialized = false;
    size_t                          m_failCount = 0;
};

} // namespace blud
