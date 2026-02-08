/*
 * BludEDR - hook_engine.cpp
 * Trampoline-based inline hooking engine for x86-64
 *
 * Strategy:
 *   1. Disassemble the target function prologue to find a safe instruction boundary
 *      that is >= 14 bytes (enough for an absolute JMP on x64).
 *   2. Allocate a trampoline within +/- 2GB of the target so we can use relative JMPs.
 *   3. Copy the original prologue bytes to the trampoline, append a JMP back to
 *      target + prologueLen.
 *   4. Overwrite the target prologue with JMP to our detour.
 *   5. Return the trampoline address as the "original" function pointer.
 */

#include "hook_engine.h"

/* ============================================================================
 * Globals
 * ============================================================================ */

static std::vector<HookEntry>   g_hooks;
static CRITICAL_SECTION         g_hookLock;
static BOOL                     g_engineInit = FALSE;

/* Minimum bytes to overwrite for an absolute x64 JMP (FF 25 00000000 + 8-byte addr) */
static constexpr DWORD ABSOLUTE_JMP_SIZE = 14;

/* ============================================================================
 * Simplified x86-64 Length Disassembler Engine (LDE)
 *
 * This handles the most common instruction patterns found in Windows NT
 * function prologues: MOV, SUB, PUSH, LEA, XOR, CMP, TEST, etc.
 * It is NOT a complete disassembler -- it covers the subset of instructions
 * that appear at the start of ntdll exports on Windows 10/11 x64.
 * ============================================================================ */

/* REX prefix detection */
static inline BOOL IsRexPrefix(BYTE b)
{
    return (b >= 0x40 && b <= 0x4F);
}

/* Does the ModRM byte indicate a SIB follows? */
static inline BOOL HasSIB(BYTE modrm)
{
    BYTE mod = (modrm >> 6) & 0x03;
    BYTE rm  = modrm & 0x07;
    return (mod != 3) && (rm == 4);
}

/* Displacement size from ModRM */
static DWORD GetDisplacementSize(BYTE modrm)
{
    BYTE mod = (modrm >> 6) & 0x03;
    BYTE rm  = modrm & 0x07;

    switch (mod) {
    case 0:
        if (rm == 5) return 4; /* RIP-relative or disp32 */
        return 0;
    case 1:
        return 1;
    case 2:
        return 4;
    case 3:
    default:
        return 0;
    }
}

DWORD LDE_GetInstructionLength(const BYTE* pCode)
{
    const BYTE* p = pCode;
    BOOL hasRex = FALSE;
    BOOL has66  = FALSE;
    BOOL hasF0  = FALSE;  /* LOCK */
    BOOL hasF2  = FALSE;  /* REPNE */
    BOOL hasF3  = FALSE;  /* REP */
    BOOL has67  = FALSE;  /* Address-size override */
    BOOL has2E  = FALSE;  /* CS override / branch hint */
    BOOL has3E  = FALSE;  /* DS override / branch hint */
    BYTE rex    = 0;

    /* Parse prefixes */
    for (;;) {
        BYTE b = *p;
        if (b == 0x66) { has66 = TRUE; p++; continue; }
        if (b == 0x67) { has67 = TRUE; p++; continue; }
        if (b == 0xF0) { hasF0 = TRUE; p++; continue; }
        if (b == 0xF2) { hasF2 = TRUE; p++; continue; }
        if (b == 0xF3) { hasF3 = TRUE; p++; continue; }
        if (b == 0x2E) { has2E = TRUE; p++; continue; }
        if (b == 0x3E) { has3E = TRUE; p++; continue; }
        if (b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65) { p++; continue; }
        if (IsRexPrefix(b)) { hasRex = TRUE; rex = b; p++; continue; }
        break;
    }

    BYTE opcode = *p++;

    /* 2-byte opcode escape */
    if (opcode == 0x0F) {
        BYTE op2 = *p++;

        /* 3-byte escape: 0F 38 xx or 0F 3A xx */
        if (op2 == 0x38) {
            p++; /* third opcode byte */
            /* ModRM follows */
            BYTE modrm = *p++;
            if (HasSIB(modrm)) p++;
            p += GetDisplacementSize(modrm);
            return (DWORD)(p - pCode);
        }
        if (op2 == 0x3A) {
            p++; /* third opcode byte */
            BYTE modrm = *p++;
            if (HasSIB(modrm)) p++;
            p += GetDisplacementSize(modrm);
            p++; /* immediate byte */
            return (DWORD)(p - pCode);
        }

        /* Conditional jumps Jcc rel32 (0F 80 - 0F 8F) */
        if (op2 >= 0x80 && op2 <= 0x8F) {
            p += 4; /* rel32 */
            return (DWORD)(p - pCode);
        }

        /* SETcc (0F 90 - 0F 9F): ModRM, no imm */
        if (op2 >= 0x90 && op2 <= 0x9F) {
            BYTE modrm = *p++;
            if (HasSIB(modrm)) p++;
            p += GetDisplacementSize(modrm);
            return (DWORD)(p - pCode);
        }

        /* CMOVcc (0F 40 - 0F 4F): ModRM */
        if (op2 >= 0x40 && op2 <= 0x4F) {
            BYTE modrm = *p++;
            if (HasSIB(modrm)) p++;
            p += GetDisplacementSize(modrm);
            return (DWORD)(p - pCode);
        }

        /* MOVZX / MOVSX (0F B6, B7, BE, BF): ModRM */
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) {
            BYTE modrm = *p++;
            if (HasSIB(modrm)) p++;
            p += GetDisplacementSize(modrm);
            return (DWORD)(p - pCode);
        }

        /* NOP with ModRM: 0F 1F (multi-byte NOP) */
        if (op2 == 0x1F) {
            BYTE modrm = *p++;
            if (HasSIB(modrm)) p++;
            p += GetDisplacementSize(modrm);
            return (DWORD)(p - pCode);
        }

        /* SYSCALL: 0F 05 */
        if (op2 == 0x05) {
            return (DWORD)(p - pCode);
        }

        /* Generic 2-byte with ModRM */
        /* Many 0F xx instructions have ModRM. Catch common ones. */
        {
            BYTE modrm = *p++;
            if (HasSIB(modrm)) p++;
            p += GetDisplacementSize(modrm);
            return (DWORD)(p - pCode);
        }
    }

    /* ============================================================================
     * Single-byte opcodes
     * ============================================================================ */

    /* NOP */
    if (opcode == 0x90) {
        return (DWORD)(p - pCode);
    }

    /* INT3 (CC) */
    if (opcode == 0xCC) {
        return (DWORD)(p - pCode);
    }

    /* RET near (C3) */
    if (opcode == 0xC3) {
        return (DWORD)(p - pCode);
    }

    /* RET near imm16 (C2) */
    if (opcode == 0xC2) {
        p += 2;
        return (DWORD)(p - pCode);
    }

    /* PUSH r64 (50-57) */
    if (opcode >= 0x50 && opcode <= 0x57) {
        return (DWORD)(p - pCode);
    }

    /* POP r64 (58-5F) */
    if (opcode >= 0x58 && opcode <= 0x5F) {
        return (DWORD)(p - pCode);
    }

    /* MOV r64, imm64 (48 B8-BF) -- REX.W + MOV r, imm64 */
    if (opcode >= 0xB8 && opcode <= 0xBF) {
        if (hasRex && (rex & 0x08)) {
            p += 8; /* 64-bit immediate */
        } else {
            p += 4; /* 32-bit immediate */
        }
        return (DWORD)(p - pCode);
    }

    /* MOV r8, imm8 (B0-B7) */
    if (opcode >= 0xB0 && opcode <= 0xB7) {
        p += 1;
        return (DWORD)(p - pCode);
    }

    /* Short JMP (EB) */
    if (opcode == 0xEB) {
        p += 1; /* rel8 */
        return (DWORD)(p - pCode);
    }

    /* Near JMP (E9) */
    if (opcode == 0xE9) {
        p += 4; /* rel32 */
        return (DWORD)(p - pCode);
    }

    /* CALL rel32 (E8) */
    if (opcode == 0xE8) {
        p += 4;
        return (DWORD)(p - pCode);
    }

    /* Short conditional jumps (70-7F): rel8 */
    if (opcode >= 0x70 && opcode <= 0x7F) {
        p += 1;
        return (DWORD)(p - pCode);
    }

    /* XCHG EAX, r32 (91-97) */
    if (opcode >= 0x91 && opcode <= 0x97) {
        return (DWORD)(p - pCode);
    }

    /* CLD (FC), STD (FD), CLI (FA), STI (FB) */
    if (opcode == 0xFC || opcode == 0xFD || opcode == 0xFA || opcode == 0xFB) {
        return (DWORD)(p - pCode);
    }

    /* LEAVE (C9) */
    if (opcode == 0xC9) {
        return (DWORD)(p - pCode);
    }

    /* CBW/CWDE/CDQE (98), CWD/CDQ/CQO (99) */
    if (opcode == 0x98 || opcode == 0x99) {
        return (DWORD)(p - pCode);
    }

    /* ============================================================================
     * Opcodes with ModRM byte
     * ============================================================================ */

    /* Group: opcodes that take ModRM and possibly immediate */
    auto handleModRM = [&](DWORD immSize) -> DWORD {
        BYTE modrm = *p++;
        if (HasSIB(modrm)) p++;
        p += GetDisplacementSize(modrm);
        p += immSize;
        return (DWORD)(p - pCode);
    };

    /* ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, r (00-03, 08-0B, 10-13, 18-1B, 20-23, 28-2B, 30-33, 38-3B) */
    if ((opcode & 0xC4) == 0x00 && (opcode & 0x03) <= 0x03) {
        /* This covers the base ALU instructions in their reg,r/m and r/m,reg forms */
        return handleModRM(0);
    }

    /* ADD/OR/ADC/SBB/AND/SUB/XOR/CMP AL/AX/EAX/RAX, imm (04/05, 0C/0D, 14/15, 1C/1D, 24/25, 2C/2D, 34/35, 3C/3D) */
    if ((opcode & 0x06) == 0x04 && opcode < 0x40) {
        if (opcode & 0x01) {
            /* imm32 (or imm16 with 66 prefix) */
            p += has66 ? 2 : 4;
        } else {
            p += 1; /* imm8 */
        }
        return (DWORD)(p - pCode);
    }

    /* 80: r/m8, imm8 */
    if (opcode == 0x80) return handleModRM(1);
    /* 81: r/m32, imm32 */
    if (opcode == 0x81) return handleModRM(has66 ? 2 : 4);
    /* 83: r/m32, imm8 */
    if (opcode == 0x83) return handleModRM(1);

    /* TEST r/m, r (84/85) */
    if (opcode == 0x84 || opcode == 0x85) return handleModRM(0);

    /* XCHG r/m, r (86/87) */
    if (opcode == 0x86 || opcode == 0x87) return handleModRM(0);

    /* MOV r/m, r (88/89) and MOV r, r/m (8A/8B) */
    if (opcode >= 0x88 && opcode <= 0x8B) return handleModRM(0);

    /* MOV r/m, Sreg (8C) / LEA (8D) / MOV Sreg, r/m (8E) */
    if (opcode == 0x8C || opcode == 0x8D || opcode == 0x8E) return handleModRM(0);

    /* TEST AL, imm8 (A8) */
    if (opcode == 0xA8) { p += 1; return (DWORD)(p - pCode); }
    /* TEST EAX, imm32 (A9) */
    if (opcode == 0xA9) { p += has66 ? 2 : 4; return (DWORD)(p - pCode); }

    /* MOV r/m, imm (C6: r/m8, imm8; C7: r/m32, imm32) */
    if (opcode == 0xC6) return handleModRM(1);
    if (opcode == 0xC7) return handleModRM(has66 ? 2 : 4);

    /* Shift group (C0: r/m8, imm8; C1: r/m32, imm8) */
    if (opcode == 0xC0) return handleModRM(1);
    if (opcode == 0xC1) return handleModRM(1);
    /* Shift by 1 (D0, D1) and by CL (D2, D3) */
    if (opcode >= 0xD0 && opcode <= 0xD3) return handleModRM(0);

    /* PUSH imm8 (6A) */
    if (opcode == 0x6A) { p += 1; return (DWORD)(p - pCode); }
    /* PUSH imm32 (68) */
    if (opcode == 0x68) { p += 4; return (DWORD)(p - pCode); }

    /* IMUL r, r/m, imm8 (6B) */
    if (opcode == 0x6B) return handleModRM(1);
    /* IMUL r, r/m, imm32 (69) */
    if (opcode == 0x69) return handleModRM(has66 ? 2 : 4);

    /* INC/DEC r/m (FE: 8-bit, FF: 32/64-bit) */
    if (opcode == 0xFE || opcode == 0xFF) return handleModRM(0);

    /* F6: TEST/NOT/NEG/MUL/DIV/IDIV r/m8 */
    if (opcode == 0xF6) {
        BYTE modrm = p[0];
        BYTE regField = (modrm >> 3) & 0x07;
        if (regField == 0 || regField == 1) {
            /* TEST r/m8, imm8 */
            return handleModRM(1);
        }
        return handleModRM(0);
    }
    /* F7: TEST/NOT/NEG/MUL/DIV/IDIV r/m32 */
    if (opcode == 0xF7) {
        BYTE modrm = p[0];
        BYTE regField = (modrm >> 3) & 0x07;
        if (regField == 0 || regField == 1) {
            return handleModRM(has66 ? 2 : 4);
        }
        return handleModRM(0);
    }

    /* MOVS/STOS/LODS/SCAS (A4-AF) - single byte */
    if (opcode >= 0xA4 && opcode <= 0xAF) {
        return (DWORD)(p - pCode);
    }

    /* LOOP/LOOPE/LOOPNE/JCXZ (E0-E3) */
    if (opcode >= 0xE0 && opcode <= 0xE3) {
        p += 1;
        return (DWORD)(p - pCode);
    }

    /* IN/OUT (E4-E7, EC-EF) */
    if (opcode == 0xE4 || opcode == 0xE5) { p += 1; return (DWORD)(p - pCode); }
    if (opcode == 0xE6 || opcode == 0xE7) { p += 1; return (DWORD)(p - pCode); }
    if (opcode >= 0xEC && opcode <= 0xEF) { return (DWORD)(p - pCode); }

    /* Fallback: assume 1-byte instruction */
    return (DWORD)(p - pCode);
}

/* ============================================================================
 * AllocateTrampoline - allocate memory within +/- 2GB of target
 * ============================================================================ */
PVOID AllocateTrampoline(PVOID pNearAddress, SIZE_T size)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    ULONG_PTR target = reinterpret_cast<ULONG_PTR>(pNearAddress);
    ULONG_PTR minAddr = (target > 0x7FFE0000ULL) ? (target - 0x7FFE0000ULL) : reinterpret_cast<ULONG_PTR>(si.lpMinimumApplicationAddress);
    ULONG_PTR maxAddr = (target < (ULONG_PTR(-1) - 0x7FFE0000ULL)) ? (target + 0x7FFE0000ULL) : reinterpret_cast<ULONG_PTR>(si.lpMaximumApplicationAddress);

    /* Align to allocation granularity */
    ULONG_PTR allocGran = si.dwAllocationGranularity;

    /* Try allocating starting near the target, scanning outward */
    ULONG_PTR addr = (target / allocGran) * allocGran;

    /* Search upward first */
    for (ULONG_PTR probe = addr; probe < maxAddr; probe += allocGran) {
        PVOID pAlloc = VirtualAlloc(
            reinterpret_cast<PVOID>(probe),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (pAlloc) return pAlloc;
    }

    /* Search downward */
    for (ULONG_PTR probe = addr - allocGran; probe >= minAddr && probe < addr; probe -= allocGran) {
        PVOID pAlloc = VirtualAlloc(
            reinterpret_cast<PVOID>(probe),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (pAlloc) return pAlloc;
    }

    return nullptr;
}

/* ============================================================================
 * Write an absolute x64 JMP to a buffer
 * FF 25 00 00 00 00     jmp [rip+0]
 * <8-byte address>
 * Total: 14 bytes
 * ============================================================================ */
static void WriteAbsoluteJmp(BYTE* pDest, PVOID pTarget)
{
    pDest[0] = 0xFF;
    pDest[1] = 0x25;
    *reinterpret_cast<DWORD*>(pDest + 2) = 0; /* RIP+0 offset */
    *reinterpret_cast<UINT64*>(pDest + 6) = reinterpret_cast<UINT64>(pTarget);
}

/* ============================================================================
 * HookEngine_Initialize
 * ============================================================================ */
BOOL HookEngine_Initialize()
{
    if (g_engineInit) return TRUE;
    InitializeCriticalSection(&g_hookLock);
    g_hooks.reserve(32);
    g_engineInit = TRUE;
    return TRUE;
}

/* ============================================================================
 * HookEngine_Shutdown
 * ============================================================================ */
void HookEngine_Shutdown()
{
    if (!g_engineInit) return;
    HookEngine_RemoveAllHooks();
    DeleteCriticalSection(&g_hookLock);
    g_engineInit = FALSE;
}

/* ============================================================================
 * SEH-safe helper: does the dangerous memory patching without C++ objects
 * ============================================================================ */
static BOOL InstallHookSEH(
    PVOID pTarget, PVOID pDetour, PVOID* ppOriginal,
    HookEntry* pEntryOut)
{
    __try {
        /* Step 1: Find instruction boundary >= ABSOLUTE_JMP_SIZE bytes */
        DWORD prologueLen = 0;
        const BYTE* pCode = (const BYTE*)pTarget;
        while (prologueLen < ABSOLUTE_JMP_SIZE) {
            DWORD instrLen = LDE_GetInstructionLength(pCode + prologueLen);
            if (instrLen == 0) return FALSE;
            prologueLen += instrLen;
            if (prologueLen > 30) return FALSE;
        }

        /* Step 2: Allocate trampoline (prologue + absolute JMP = prologueLen + 14) */
        SIZE_T trampolineSize = prologueLen + ABSOLUTE_JMP_SIZE;
        PVOID pTrampoline = AllocateTrampoline(pTarget, trampolineSize);
        if (!pTrampoline) return FALSE;

        /* Step 3: Build the trampoline */
        BYTE* pTrampolineBytes = (BYTE*)pTrampoline;
        memcpy(pTrampolineBytes, pTarget, prologueLen);
        WriteAbsoluteJmp(pTrampolineBytes + prologueLen,
                         (BYTE*)pTarget + prologueLen);
        FlushInstructionCache(GetCurrentProcess(), pTrampoline, trampolineSize);

        /* Step 4: Save original bytes and overwrite target with JMP to detour */
        pEntryOut->pTarget = pTarget;
        pEntryOut->pDetour = pDetour;
        pEntryOut->pTrampoline = pTrampoline;
        pEntryOut->OriginalBytesLen = prologueLen;
        memcpy(pEntryOut->OriginalBytes, pTarget, prologueLen);

        DWORD oldProtect = 0;
        if (!VirtualProtect(pTarget, prologueLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            VirtualFree(pTrampoline, 0, MEM_RELEASE);
            return FALSE;
        }
        pEntryOut->OldProtect = oldProtect;

        WriteAbsoluteJmp((BYTE*)pTarget, pDetour);
        for (DWORD i = ABSOLUTE_JMP_SIZE; i < prologueLen; i++) {
            ((BYTE*)pTarget)[i] = 0x90;
        }

        DWORD dummy = 0;
        VirtualProtect(pTarget, prologueLen, oldProtect, &dummy);
        FlushInstructionCache(GetCurrentProcess(), pTarget, prologueLen);

        *ppOriginal = pTrampoline;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

/* ============================================================================
 * HookEngine_InstallHook
 * ============================================================================ */
BOOL HookEngine_InstallHook(PVOID pTarget, PVOID pDetour, PVOID* ppOriginal)
{
    if (!g_engineInit || !pTarget || !pDetour || !ppOriginal) return FALSE;

    EnterCriticalSection(&g_hookLock);

    /* Check if already hooked */
    for (const auto& entry : g_hooks) {
        if (entry.pTarget == pTarget) {
            LeaveCriticalSection(&g_hookLock);
            return FALSE;
        }
    }

    HookEntry newEntry = {};
    BOOL result = InstallHookSEH(pTarget, pDetour, ppOriginal, &newEntry);
    if (result) {
        g_hooks.push_back(newEntry);
    }

    LeaveCriticalSection(&g_hookLock);
    return result;
}

/* ============================================================================
 * SEH-safe helper: restore original bytes and free trampoline
 * ============================================================================ */
static void RestoreHookSEH(const HookEntry* pEntry)
{
    __try {
        DWORD oldProtect = 0;
        if (VirtualProtect(pEntry->pTarget, pEntry->OriginalBytesLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(pEntry->pTarget, pEntry->OriginalBytes, pEntry->OriginalBytesLen);
            DWORD dummy = 0;
            VirtualProtect(pEntry->pTarget, pEntry->OriginalBytesLen, oldProtect, &dummy);
            FlushInstructionCache(GetCurrentProcess(), pEntry->pTarget, pEntry->OriginalBytesLen);
        }
        if (pEntry->pTrampoline) {
            VirtualFree(pEntry->pTrampoline, 0, MEM_RELEASE);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Best effort - don't crash */
    }
}

/* ============================================================================
 * HookEngine_RemoveHook
 * ============================================================================ */
BOOL HookEngine_RemoveHook(PVOID pTarget)
{
    if (!g_engineInit || !pTarget) return FALSE;

    EnterCriticalSection(&g_hookLock);

    for (auto it = g_hooks.begin(); it != g_hooks.end(); ++it) {
        if (it->pTarget == pTarget) {
            RestoreHookSEH(&(*it));
            g_hooks.erase(it);
            LeaveCriticalSection(&g_hookLock);
            return TRUE;
        }
    }

    LeaveCriticalSection(&g_hookLock);
    return FALSE;
}

/* ============================================================================
 * HookEngine_RemoveAllHooks
 * ============================================================================ */
void HookEngine_RemoveAllHooks()
{
    if (!g_engineInit) return;

    EnterCriticalSection(&g_hookLock);

    for (auto& entry : g_hooks) {
        RestoreHookSEH(&entry);
    }

    g_hooks.clear();
    LeaveCriticalSection(&g_hookLock);
}
