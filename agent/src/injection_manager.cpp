/*
 * BludEDR - injection_manager.cpp
 * DLL injection via APC (preferred) or NtCreateThreadEx (fallback)
 */

#include "../inc/injection_manager.h"
#include "../../shared/sentinel_shared.h"
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>

/* NtCreateThreadEx typedef for fallback injection */
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(
    PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaxStackSize, PVOID AttributeList
);

namespace blud {

static std::wstring ToLower(const std::wstring& s) {
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::towlower);
    return out;
}

static std::wstring GetBaseName(const std::wstring& path) {
    auto pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
}

InjectionManager::InjectionManager() {
    /* System processes we should never inject into */
    m_whitelist = {
        L"system", L"smss.exe", L"csrss.exe", L"wininit.exe",
        L"services.exe", L"lsass.exe", L"svchost.exe", L"winlogon.exe",
        L"dwm.exe", L"fontdrvhost.exe", L"conhost.exe",
        L"registry", L"memcompression", L"idle",
        L"bludagent.exe", L"wmiprvse.exe", L"taskhostw.exe",
        L"runtimebroker.exe", L"searchindexer.exe",
        L"securityhealthservice.exe", L"msmpeng.exe",
        L"nissrv.exe", L"audiodg.exe"
    };
}

InjectionManager::~InjectionManager() {
    Shutdown();
}

bool InjectionManager::Initialize(const std::wstring& dllPath) {
    std::lock_guard<std::mutex> lock(m_mutex);

    /* Verify DLL exists */
    DWORD attrs = GetFileAttributesW(dllPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    m_dllPath = dllPath;
    m_initialized = true;
    return true;
}

void InjectionManager::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_initialized = false;
    m_injectedPids.clear();
    m_pendingPids.clear();
    m_failedPids.clear();
}

bool InjectionManager::ShouldSkip(DWORD pid, const std::wstring& imageName) const {
    /* Skip PID 0 and 4 (System) */
    if (pid <= 4) return true;

    /* Skip our own process */
    if (pid == GetCurrentProcessId()) return true;

    /* Skip whitelisted processes */
    std::wstring baseName = ToLower(GetBaseName(imageName));
    if (m_whitelist.count(baseName) > 0) return true;

    /* Skip already injected or failed */
    if (m_injectedPids.count(pid) > 0) return true;
    if (m_pendingPids.count(pid) > 0) return true;

    return false;
}

bool InjectionManager::InjectIntoProcess(DWORD targetPid, const std::wstring& imageName) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized) return false;
    if (ShouldSkip(targetPid, imageName)) return false;

    /* Open target process */
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, targetPid
    );
    if (!hProcess) {
        m_failedPids.insert(targetPid);
        m_failCount++;
        return false;
    }

    /* Try APC injection first, fallback to remote thread */
    bool success = InjectViaApc(hProcess, targetPid);
    if (!success) {
        success = InjectViaRemoteThread(hProcess);
    }

    CloseHandle(hProcess);

    if (success) {
        m_pendingPids.insert(targetPid);
    } else {
        m_failedPids.insert(targetPid);
        m_failCount++;
    }

    return success;
}

bool InjectionManager::InjectViaApc(HANDLE hProcess, DWORD pid) {
    /* Allocate memory in target for DLL path */
    SIZE_T pathSize = (m_dllPath.size() + 1) * sizeof(WCHAR);
    PVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;

    /* Write DLL path */
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, m_dllPath.c_str(), pathSize, &written)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    /* Get LoadLibraryW address */
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    /* Find a thread in the target to queue APC to */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    bool queued = false;
    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                           FALSE, te.th32ThreadID);
                if (hThread) {
                    DWORD result = QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)remoteMem);
                    CloseHandle(hThread);
                    if (result != 0) {
                        queued = true;
                        break;
                    }
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);

    if (!queued) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    }

    return queued;
}

bool InjectionManager::InjectViaRemoteThread(HANDLE hProcess) {
    /* Allocate memory in target for DLL path */
    SIZE_T pathSize = (m_dllPath.size() + 1) * sizeof(WCHAR);
    PVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, m_dllPath.c_str(), pathSize, &written)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    /* Try NtCreateThreadEx first for better stealth */
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto pNtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
        if (pNtCreateThreadEx) {
            HANDLE hThread = nullptr;
            NTSTATUS status = pNtCreateThreadEx(
                &hThread, THREAD_ALL_ACCESS, nullptr, hProcess,
                (PVOID)pLoadLibrary, remoteMem,
                0, 0, 0, 0, nullptr
            );
            if (status >= 0 && hThread) {
                WaitForSingleObject(hThread, 5000);
                CloseHandle(hThread);
                return true;
            }
        }
    }

    /* Fallback to CreateRemoteThread */
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        remoteMem, 0, nullptr
    );
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    return true;
}

void InjectionManager::ConfirmInjection(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pendingPids.erase(pid) > 0) {
        m_injectedPids.insert(pid);
    }
}

bool InjectionManager::IsInjected(DWORD pid) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_injectedPids.count(pid) > 0;
}

void InjectionManager::OnProcessTerminate(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_injectedPids.erase(pid);
    m_pendingPids.erase(pid);
    m_failedPids.erase(pid);
}

size_t InjectionManager::GetInjectedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_injectedPids.size();
}

size_t InjectionManager::GetFailedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_failCount;
}

} // namespace blud
