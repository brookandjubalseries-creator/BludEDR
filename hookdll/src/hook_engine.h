/*
 * BludEDR - hook_engine.h
 * Trampoline-based inline hooking engine for x86-64
 */

#pragma once

#include "../inc/hookdll.h"

/* ============================================================================
 * HookEntry - tracks a single installed hook for cleanup
 * ============================================================================ */
struct HookEntry {
    PVOID   pTarget;                /* Original function address */
    PVOID   pDetour;                /* Our detour function */
    PVOID   pTrampoline;            /* Allocated trampoline */
    BYTE    OriginalBytes[32];      /* Saved original prologue bytes */
    DWORD   OriginalBytesLen;       /* Length of saved bytes */
    DWORD   OldProtect;             /* Original page protection */
};

/* ============================================================================
 * x86-64 instruction length disassembler (simplified)
 * Returns the length of the instruction at the given address.
 * Handles the common instruction forms found in NT function prologues.
 * ============================================================================ */
DWORD   LDE_GetInstructionLength(const BYTE* pCode);

/* Trampoline allocation within 2GB of a target address */
PVOID   AllocateTrampoline(PVOID pNearAddress, SIZE_T size);
