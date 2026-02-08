/*
 * BludEDR - iat_hook.cpp
 * IAT/EAT patching utilities for alternative hooking
 */

#include "iat_hook.h"

static std::vector<IATHookEntry>    g_iatHooks;
static CRITICAL_SECTION             g_iatLock;
static BOOL                         g_iatInit = FALSE;

/* ============================================================================
 * Internal: Ensure IAT hook system is initialized
 * ============================================================================ */
static void EnsureInit()
{
    if (!g_iatInit) {
        InitializeCriticalSection(&g_iatLock);
        g_iatHooks.reserve(16);
        g_iatInit = TRUE;
    }
}

/* ============================================================================
 * IAT_HookFunction
 * Walks the PE import directory of hModule, finds the IAT entry for
 * pszTargetDll!pszTargetFunc, and patches it with pDetour.
 * ============================================================================ */
BOOL IAT_HookFunction(HMODULE hModule, const char* pszTargetDll, const char* pszTargetFunc,
                       PVOID pDetour, PVOID* ppOriginal)
{
    if (!hModule || !pszTargetDll || !pszTargetFunc || !pDetour || !ppOriginal)
        return FALSE;

    EnsureInit();

    __try {
        BYTE* pBase = reinterpret_cast<BYTE*>(hModule);

        /* Get DOS header */
        auto* pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
            return FALSE;

        /* Get NT headers */
        auto* pNt = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE)
            return FALSE;

        /* Get import directory */
        auto& importDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress == 0 || importDir.Size == 0)
            return FALSE;

        auto* pImport = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + importDir.VirtualAddress);

        /* Walk import descriptors */
        for (; pImport->Name != 0; pImport++) {
            const char* dllName = reinterpret_cast<const char*>(pBase + pImport->Name);

            /* Case-insensitive DLL name comparison */
            if (_stricmp(dllName, pszTargetDll) != 0)
                continue;

            /* Walk the thunk arrays */
            auto* pOrigThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(pBase + pImport->OriginalFirstThunk);
            auto* pFirstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(pBase + pImport->FirstThunk);

            for (; pOrigThunk->u1.AddressOfData != 0; pOrigThunk++, pFirstThunk++) {
                /* Skip ordinal imports */
                if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal))
                    continue;

                auto* pImportByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                    pBase + pOrigThunk->u1.AddressOfData);

                if (strcmp(pImportByName->Name, pszTargetFunc) != 0)
                    continue;

                /* Found it - patch the IAT entry */
                PVOID* pThunkAddr = reinterpret_cast<PVOID*>(&pFirstThunk->u1.Function);
                PVOID pOldFunc = *pThunkAddr;

                DWORD oldProtect = 0;
                if (!VirtualProtect(pThunkAddr, sizeof(PVOID), PAGE_READWRITE, &oldProtect))
                    return FALSE;

                *pThunkAddr = pDetour;

                DWORD dummy = 0;
                VirtualProtect(pThunkAddr, sizeof(PVOID), oldProtect, &dummy);

                *ppOriginal = pOldFunc;

                /* Record for later unhooking */
                EnterCriticalSection(&g_iatLock);
                IATHookEntry entry;
                entry.hModule = hModule;
                entry.targetDll = pszTargetDll;
                entry.targetFunc = pszTargetFunc;
                entry.pOriginal = pOldFunc;
                entry.pThunkLocation = pThunkAddr;
                g_iatHooks.push_back(entry);
                LeaveCriticalSection(&g_iatLock);

                return TRUE;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return FALSE;
}

/* ============================================================================
 * IAT_UnhookFunction
 * Restores the original IAT entry.
 * ============================================================================ */
BOOL IAT_UnhookFunction(HMODULE hModule, const char* pszTargetDll, const char* pszTargetFunc,
                         PVOID pOriginal)
{
    if (!g_iatInit) return FALSE;

    EnterCriticalSection(&g_iatLock);

    for (auto it = g_iatHooks.begin(); it != g_iatHooks.end(); ++it) {
        if (it->hModule == hModule &&
            _stricmp(it->targetDll.c_str(), pszTargetDll) == 0 &&
            strcmp(it->targetFunc.c_str(), pszTargetFunc) == 0) {

            __try {
                DWORD oldProtect = 0;
                if (VirtualProtect(it->pThunkLocation, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
                    *it->pThunkLocation = pOriginal ? pOriginal : it->pOriginal;
                    DWORD dummy = 0;
                    VirtualProtect(it->pThunkLocation, sizeof(PVOID), oldProtect, &dummy);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                LeaveCriticalSection(&g_iatLock);
                return FALSE;
            }

            g_iatHooks.erase(it);
            LeaveCriticalSection(&g_iatLock);
            return TRUE;
        }
    }

    LeaveCriticalSection(&g_iatLock);
    return FALSE;
}
