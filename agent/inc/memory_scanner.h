/*
 * BludEDR - memory_scanner.h
 * Process memory scanner for shellcode, RWX regions, and anomalies
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace blud {

struct MemoryRegionInfo {
    PVOID   BaseAddress;
    SIZE_T  RegionSize;
    DWORD   Protect;
    DWORD   Type;           /* MEM_PRIVATE, MEM_IMAGE, MEM_MAPPED */
    bool    IsRWX;
    bool    HasShellcode;
    bool    HasAesSchedule;
    bool    HasSyscallStub;
    std::wstring Details;
};

struct ProtectTransition {
    PVOID       BaseAddress;
    DWORD       OldProtect;
    DWORD       NewProtect;
    LONGLONG    Timestamp;
};

class MemoryScanner {
public:
    MemoryScanner();
    ~MemoryScanner();

    bool Initialize();
    void Shutdown();

    /* Scan a specific process's memory */
    std::vector<MemoryRegionInfo> ScanProcess(DWORD pid);

    /* Track protect transitions for sleep obfuscation detection */
    void RecordProtectTransition(DWORD pid, PVOID base, DWORD oldProt, DWORD newProt);

    /* Check if a region shows sleep obfuscation patterns */
    bool CheckSleepObfuscation(DWORD pid, PVOID base);

    /* Get all RWX regions for a process */
    std::vector<MemoryRegionInfo> GetRWXRegions(DWORD pid);

private:
    /* Pattern scanners */
    bool ScanForShellcode(const BYTE* data, SIZE_T size);
    bool ScanForAesSchedule(const BYTE* data, SIZE_T size);
    bool ScanForSyscallStub(const BYTE* data, SIZE_T size);
    bool ScanForPebWalk(const BYTE* data, SIZE_T size);

    /* Boyer-Moore-Horspool pattern search */
    bool FindPattern(const BYTE* data, SIZE_T dataSize,
                     const BYTE* pattern, SIZE_T patternSize);

    std::mutex m_mutex;
    std::atomic<bool> m_running{false};

    /* Per-process protect transition history for sleep obfuscation detection */
    /* Key: PID, Value: map of base address -> vector of transitions */
    std::unordered_map<DWORD,
        std::unordered_map<uintptr_t, std::vector<ProtectTransition>>> m_transitions;
};

} // namespace blud
