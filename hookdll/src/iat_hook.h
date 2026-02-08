/*
 * BludEDR - iat_hook.h
 * IAT/EAT patching utilities
 */

#pragma once

#include "../inc/hookdll.h"

/* ============================================================================
 * IAT Hook Entry for tracking installed IAT patches
 * ============================================================================ */
struct IATHookEntry {
    HMODULE     hModule;
    std::string targetDll;
    std::string targetFunc;
    PVOID       pOriginal;
    PVOID*      pThunkLocation;     /* Address of the IAT entry that was patched */
};
