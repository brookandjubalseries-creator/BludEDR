/*
 * BludEDR - memory_scanner.cpp
 * Process memory scanner for shellcode, RWX regions, and anomalies
 */

#include "../inc/memory_scanner.h"
#include "../../shared/sentinel_shared.h"

namespace blud {

/* Shellcode signature: CLD + CALL + POP (common shellcode decoder prologue) */
static const BYTE SIG_CLD_CALL_POP[] = { 0xFC, 0xE8 };

/* PEB walking via GS segment: mov rax, gs:[0x60] */
static const BYTE SIG_PEB_WALK_X64[] = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 };

/* PEB walking via FS segment (WoW64): mov eax, fs:[0x30] */
static const BYTE SIG_PEB_WALK_X86[] = { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00 };

/* Syscall instruction */
static const BYTE SIG_SYSCALL[] = { 0x0F, 0x05 };

/* AES S-Box first 16 bytes */
static const BYTE SIG_AES_SBOX[] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
};

/* INT 2D (anti-debug / kernel-mode interrupt) */
static const BYTE SIG_INT2D[] = { 0xCD, 0x2D };

/* Common shellcode: hash-based API resolution (ROR 13 pattern) */
static const BYTE SIG_ROR13_HASH[] = { 0xC1, 0xCF, 0x0D };  /* ror edi, 0x0d */

MemoryScanner::MemoryScanner() {}

MemoryScanner::~MemoryScanner() {
    Shutdown();
}

bool MemoryScanner::Initialize() {
    m_running = true;
    return true;
}

void MemoryScanner::Shutdown() {
    m_running = false;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_transitions.clear();
}

bool MemoryScanner::FindPattern(const BYTE* data, SIZE_T dataSize,
                                 const BYTE* pattern, SIZE_T patternSize) {
    if (dataSize < patternSize || patternSize == 0) return false;

    for (SIZE_T i = 0; i <= dataSize - patternSize; i++) {
        bool match = true;
        for (SIZE_T j = 0; j < patternSize; j++) {
            if (data[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

bool MemoryScanner::ScanForShellcode(const BYTE* data, SIZE_T size) {
    /* Check for CLD + CALL + POP pattern */
    if (FindPattern(data, size, SIG_CLD_CALL_POP, sizeof(SIG_CLD_CALL_POP))) {
        /* Verify there's a POP within 64 bytes of the CALL */
        for (SIZE_T i = 0; i < size - 6; i++) {
            if (data[i] == 0xFC && data[i + 1] == 0xE8) {
                /* Found CLD+CALL, check for POP reg (0x58-0x5F) within range */
                LONG offset;
                memcpy(&offset, &data[i + 2], sizeof(LONG));
                LONGLONG targetAddr = (LONGLONG)(i + 6) + offset;
                if (targetAddr < 0 || targetAddr >= (LONGLONG)size) continue;
                SIZE_T targetIdx = (SIZE_T)targetAddr;
                BYTE popByte = data[targetIdx];
                if (popByte >= 0x58 && popByte <= 0x5F) {
                    return true;
                }
            }
        }
    }

    /* Check for ROR 13 API hashing */
    if (FindPattern(data, size, SIG_ROR13_HASH, sizeof(SIG_ROR13_HASH))) {
        return true;
    }

    return false;
}

bool MemoryScanner::ScanForAesSchedule(const BYTE* data, SIZE_T size) {
    return FindPattern(data, size, SIG_AES_SBOX, sizeof(SIG_AES_SBOX));
}

bool MemoryScanner::ScanForSyscallStub(const BYTE* data, SIZE_T size) {
    /* Look for syscall instruction in non-ntdll memory */
    return FindPattern(data, size, SIG_SYSCALL, sizeof(SIG_SYSCALL));
}

bool MemoryScanner::ScanForPebWalk(const BYTE* data, SIZE_T size) {
    if (FindPattern(data, size, SIG_PEB_WALK_X64, sizeof(SIG_PEB_WALK_X64)))
        return true;
    if (FindPattern(data, size, SIG_PEB_WALK_X86, sizeof(SIG_PEB_WALK_X86)))
        return true;
    return false;
}

std::vector<MemoryRegionInfo> MemoryScanner::ScanProcess(DWORD pid) {
    std::vector<MemoryRegionInfo> results;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return results;

    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID addr = nullptr;
    BYTE readBuf[4096];

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        /* Only scan private committed regions */
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            bool isRWX = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
            bool isRX = (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            bool isRW = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0;

            if (isRWX || isRX) {
                MemoryRegionInfo info = {};
                info.BaseAddress = mbi.BaseAddress;
                info.RegionSize = mbi.RegionSize;
                info.Protect = mbi.Protect;
                info.Type = mbi.Type;
                info.IsRWX = isRWX;

                /* Read first 4096 bytes for signature scanning */
                SIZE_T bytesRead = 0;
                SIZE_T toRead = min(mbi.RegionSize, sizeof(readBuf));
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, readBuf, toRead, &bytesRead) && bytesRead > 0) {
                    info.HasShellcode = ScanForShellcode(readBuf, bytesRead) ||
                                        ScanForPebWalk(readBuf, bytesRead);
                    info.HasAesSchedule = ScanForAesSchedule(readBuf, bytesRead);
                    info.HasSyscallStub = ScanForSyscallStub(readBuf, bytesRead);

                    if (info.HasShellcode) info.Details += L"SHELLCODE ";
                    if (info.HasAesSchedule) info.Details += L"AES_SCHED ";
                    if (info.HasSyscallStub) info.Details += L"SYSCALL_STUB ";
                    if (isRWX) info.Details += L"RWX ";
                }

                /* Only report interesting regions */
                if (isRWX || info.HasShellcode || info.HasAesSchedule || info.HasSyscallStub) {
                    results.push_back(std::move(info));
                }
            }
        }

        /* Advance to next region */
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        if ((uintptr_t)addr < (uintptr_t)mbi.BaseAddress) break; /* Overflow check */
    }

    CloseHandle(hProcess);
    return results;
}

std::vector<MemoryRegionInfo> MemoryScanner::GetRWXRegions(DWORD pid) {
    std::vector<MemoryRegionInfo> all = ScanProcess(pid);
    std::vector<MemoryRegionInfo> rwx;
    for (auto& r : all) {
        if (r.IsRWX) rwx.push_back(std::move(r));
    }
    return rwx;
}

void MemoryScanner::RecordProtectTransition(DWORD pid, PVOID base, DWORD oldProt, DWORD newProt) {
    std::lock_guard<std::mutex> lock(m_mutex);

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    ProtectTransition pt;
    pt.BaseAddress = base;
    pt.OldProtect = oldProt;
    pt.NewProtect = newProt;
    pt.Timestamp = now.QuadPart;

    auto& processMap = m_transitions[pid];
    auto& regionVec = processMap[(uintptr_t)base];

    regionVec.push_back(pt);

    /* Keep only last 32 transitions per region */
    if (regionVec.size() > 32) {
        regionVec.erase(regionVec.begin());
    }
}

bool MemoryScanner::CheckSleepObfuscation(DWORD pid, PVOID base) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto pit = m_transitions.find(pid);
    if (pit == m_transitions.end()) return false;

    auto rit = pit->second.find((uintptr_t)base);
    if (rit == pit->second.end()) return false;

    const auto& transitions = rit->second;
    if (transitions.size() < 6) return false;  /* Need at least 3 cycles (6 transitions) */

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);

    /* Look for pattern: RX->RW->RX repeated 3+ times within 3 seconds */
    int cycleCount = 0;
    LONGLONG firstTimestamp = 0;

    for (size_t i = 1; i < transitions.size(); i++) {
        const auto& prev = transitions[i - 1];
        const auto& curr = transitions[i];

        bool prevToRW = (curr.NewProtect & PAGE_READWRITE) &&
                        (prev.NewProtect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
        bool rwToRX = (curr.NewProtect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                      (prev.NewProtect & PAGE_READWRITE);

        if (prevToRW || rwToRX) {
            if (cycleCount == 0) firstTimestamp = prev.Timestamp;
            cycleCount++;
        } else {
            cycleCount = 0;
        }

        /* 3 full cycles = 6 transitions (RX->RW, RW->RX, RX->RW, RW->RX, RX->RW, RW->RX) */
        if (cycleCount >= 6) {
            double elapsed = (double)(curr.Timestamp - firstTimestamp) / freq.QuadPart;
            if (elapsed < 3.0) {
                return true;  /* Sleep obfuscation detected */
            }
        }
    }

    return false;
}

} // namespace blud
