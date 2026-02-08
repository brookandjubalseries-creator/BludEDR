/*
 * BludEDR - iat_hook.cpp
 * IAT/EAT patching utilities for alternative hooking
 */

#include "iat_hook.h"

static std::vector<IATHookEntry>    g_iatHooks;
static CRITICAL_SECTION             g_iatLock;
static BOOL                         g_iatInit = FALSE;
static INIT_ONCE                    g_iatInitOnce = INIT_ONCE_STATIC_INIT;

/* ============================================================================
 * Internal: Ensure IAT hook system is initialized (thread-safe via INIT_ONCE)
 * ============================================================================ */
static BOOL CALLBACK IatInitCallback(PINIT_ONCE, PVOID, PVOID*)
{
    InitializeCriticalSection(&g_iatLock);
    g_iatHooks.reserve(16);
    g_iatInit = TRUE;
    return TRUE;
}

static void EnsureInit()
{
    InitOnceExecuteOnce(&g_iatInitOnce, IatInitCallback, nullptr, nullptr);
}

/* ============================================================================
 * SEH-safe helper: walks IAT and patches. No C++ objects in this function.
 * Returns the thunk address and original function via out params.
 * ============================================================================ */
static BOOL WalkIATAndPatch(HMODULE hModule, const char* pszTargetDll, const char* pszTargetFunc,
                             PVOID pDetour, PVOID* ppOriginal, PVOID** ppThunkOut)
{
    __try {
        BYTE* pBase = (BYTE*)hModule;

        IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
            return FALSE;

        IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE)
            return FALSE;

        IMAGE_DATA_DIRECTORY* pImportDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (pImportDir->VirtualAddress == 0 || pImportDir->Size == 0)
            return FALSE;

        IMAGE_IMPORT_DESCRIPTOR* pImport = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pImportDir->VirtualAddress);

        for (; pImport->Name != 0; pImport++) {
            const char* dllName = (const char*)(pBase + pImport->Name);
            if (_stricmp(dllName, pszTargetDll) != 0)
                continue;

            IMAGE_THUNK_DATA* pOrigThunk = (IMAGE_THUNK_DATA*)(pBase + pImport->OriginalFirstThunk);
            IMAGE_THUNK_DATA* pFirstThunk = (IMAGE_THUNK_DATA*)(pBase + pImport->FirstThunk);

            for (; pOrigThunk->u1.AddressOfData != 0; pOrigThunk++, pFirstThunk++) {
                if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal))
                    continue;

                IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)(
                    pBase + pOrigThunk->u1.AddressOfData);

                if (strcmp(pImportByName->Name, pszTargetFunc) != 0)
                    continue;

                PVOID* pThunkAddr = (PVOID*)&pFirstThunk->u1.Function;
                PVOID pOldFunc = *pThunkAddr;

                DWORD oldProtect = 0;
                if (!VirtualProtect(pThunkAddr, sizeof(PVOID), PAGE_READWRITE, &oldProtect))
                    return FALSE;

                *pThunkAddr = pDetour;

                DWORD dummy = 0;
                VirtualProtect(pThunkAddr, sizeof(PVOID), oldProtect, &dummy);

                *ppOriginal = pOldFunc;
                *ppThunkOut = pThunkAddr;
                return TRUE;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return FALSE;
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

    PVOID* pThunkAddr = nullptr;
    BOOL result = WalkIATAndPatch(hModule, pszTargetDll, pszTargetFunc,
                                   pDetour, ppOriginal, &pThunkAddr);
    if (result && pThunkAddr) {
        EnterCriticalSection(&g_iatLock);
        IATHookEntry entry;
        entry.hModule = hModule;
        entry.targetDll = pszTargetDll;
        entry.targetFunc = pszTargetFunc;
        entry.pOriginal = *ppOriginal;
        entry.pThunkLocation = pThunkAddr;
        g_iatHooks.push_back(entry);
        LeaveCriticalSection(&g_iatLock);
    }

    return result;
}

/* ============================================================================
 * IAT_UnhookFunction
 * Restores the original IAT entry.
 * ============================================================================ */
/* SEH-safe helper: restore a single IAT entry */
static BOOL RestoreIATEntrySEH(PVOID* pThunkLocation, PVOID pOriginal)
{
    __try {
        DWORD oldProtect = 0;
        if (VirtualProtect(pThunkLocation, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
            *pThunkLocation = pOriginal;
            DWORD dummy = 0;
            VirtualProtect(pThunkLocation, sizeof(PVOID), oldProtect, &dummy);
            return TRUE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return FALSE;
}

BOOL IAT_UnhookFunction(HMODULE hModule, const char* pszTargetDll, const char* pszTargetFunc,
                         PVOID pOriginal)
{
    if (!g_iatInit) return FALSE;

    EnterCriticalSection(&g_iatLock);

    for (auto it = g_iatHooks.begin(); it != g_iatHooks.end(); ++it) {
        if (it->hModule == hModule &&
            _stricmp(it->targetDll.c_str(), pszTargetDll) == 0 &&
            strcmp(it->targetFunc.c_str(), pszTargetFunc) == 0) {

            PVOID restoreVal = pOriginal ? pOriginal : it->pOriginal;
            if (!RestoreIATEntrySEH(it->pThunkLocation, restoreVal)) {
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
