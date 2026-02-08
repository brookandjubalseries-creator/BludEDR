/*
 * BludEDR - pe_utils.cpp
 * PE parsing utilities for module inspection.
 */

#include "pe_utils.h"

/* ============================================================================
 * PeUtils_GetModuleFromAddress
 * Find which loaded module contains the given address.
 * Returns the module base or NULL.
 * ============================================================================ */
HMODULE PeUtils_GetModuleFromAddress(PVOID addr)
{
    if (!addr) return nullptr;

    HMODULE hMods[1024];
    DWORD cbNeeded = 0;

    HANDLE hProcess = GetCurrentProcess();
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return nullptr;

    DWORD modCount = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < modCount; i++) {
        MODULEINFO mi = {};
        if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
            ULONG_PTR base = reinterpret_cast<ULONG_PTR>(mi.lpBaseOfDll);
            ULONG_PTR end  = base + mi.SizeOfImage;
            ULONG_PTR target = reinterpret_cast<ULONG_PTR>(addr);
            if (target >= base && target < end) {
                return hMods[i];
            }
        }
    }

    return nullptr;
}

/* ============================================================================
 * PeUtils_IsAddressInModule
 * Returns TRUE if the address is within any loaded module.
 * ============================================================================ */
BOOL PeUtils_IsAddressInModule(PVOID addr)
{
    return (PeUtils_GetModuleFromAddress(addr) != nullptr) ? TRUE : FALSE;
}

/* ============================================================================
 * PeUtils_GetExportAddress
 * Manually walks the PE export directory to find an exported function.
 * This is our own GetProcAddress to avoid IAT dependencies.
 * ============================================================================ */
PVOID PeUtils_GetExportAddress(HMODULE hMod, const char* pszName)
{
    if (!hMod || !pszName) return nullptr;

    __try {
        BYTE* pBase = reinterpret_cast<BYTE*>(hMod);

        auto* pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        auto* pNt = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        auto& exportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0) return nullptr;

        auto* pExport = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pBase + exportDir.VirtualAddress);

        DWORD* pNames      = reinterpret_cast<DWORD*>(pBase + pExport->AddressOfNames);
        WORD*  pOrdinals   = reinterpret_cast<WORD*>(pBase + pExport->AddressOfNameOrdinals);
        DWORD* pFunctions  = reinterpret_cast<DWORD*>(pBase + pExport->AddressOfFunctions);

        for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
            const char* name = reinterpret_cast<const char*>(pBase + pNames[i]);
            if (strcmp(name, pszName) == 0) {
                WORD ordinal = pOrdinals[i];
                DWORD funcRva = pFunctions[ordinal];

                /* Check for forwarded export */
                ULONG_PTR funcAddr = reinterpret_cast<ULONG_PTR>(pBase + funcRva);
                ULONG_PTR exportStart = reinterpret_cast<ULONG_PTR>(pBase + exportDir.VirtualAddress);
                ULONG_PTR exportEnd   = exportStart + exportDir.Size;

                if (funcAddr >= exportStart && funcAddr < exportEnd) {
                    /* Forwarded export - parse "DLL.Function" format */
                    const char* fwd = reinterpret_cast<const char*>(funcAddr);
                    char dllName[256] = {};
                    char funcName[256] = {};
                    const char* dot = strchr(fwd, '.');
                    if (!dot) return nullptr;

                    size_t dllLen = dot - fwd;
                    if (dllLen >= sizeof(dllName)) return nullptr;
                    memcpy(dllName, fwd, dllLen);
                    dllName[dllLen] = '\0';
                    strcat_s(dllName, ".dll");
                    strcpy_s(funcName, dot + 1);

                    HMODULE hFwdMod = GetModuleHandleA(dllName);
                    if (!hFwdMod) return nullptr;

                    return PeUtils_GetExportAddress(hFwdMod, funcName);
                }

                return reinterpret_cast<PVOID>(funcAddr);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }

    return nullptr;
}

/* ============================================================================
 * PeUtils_ValidateModuleIntegrity
 * Compare the .text section of a loaded module against its on-disk copy.
 * Returns TRUE if integrity check passes, FALSE if tampering is detected.
 * ============================================================================ */
BOOL PeUtils_ValidateModuleIntegrity(HMODULE hMod)
{
    if (!hMod) return FALSE;

    __try {
        WCHAR modulePath[MAX_PATH] = {};
        if (GetModuleFileNameW(hMod, modulePath, MAX_PATH) == 0)
            return FALSE;

        BYTE* pBase = reinterpret_cast<BYTE*>(hMod);

        auto* pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

        auto* pNt = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

        /* Find .text section */
        auto* pSection = IMAGE_FIRST_SECTION(pNt);
        IMAGE_SECTION_HEADER* pTextSection = nullptr;

        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            if (memcmp(pSection[i].Name, ".text", 5) == 0) {
                pTextSection = &pSection[i];
                break;
            }
        }

        if (!pTextSection) return FALSE;

        /* Map the file from disk */
        HANDLE hFile = CreateFileW(modulePath, GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return FALSE;

        HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMapping) {
            CloseHandle(hFile);
            return FALSE;
        }

        BYTE* pFileBase = static_cast<BYTE*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
        if (!pFileBase) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return FALSE;
        }

        /* Parse the disk PE to find .text section */
        auto* pFileDos = reinterpret_cast<IMAGE_DOS_HEADER*>(pFileBase);
        auto* pFileNt  = reinterpret_cast<IMAGE_NT_HEADERS*>(pFileBase + pFileDos->e_lfanew);
        auto* pFileSec = IMAGE_FIRST_SECTION(pFileNt);
        IMAGE_SECTION_HEADER* pFileTextSection = nullptr;

        for (WORD i = 0; i < pFileNt->FileHeader.NumberOfSections; i++) {
            if (memcmp(pFileSec[i].Name, ".text", 5) == 0) {
                pFileTextSection = &pFileSec[i];
                break;
            }
        }

        BOOL integrity = TRUE;

        if (pFileTextSection) {
            BYTE* pMemText  = pBase + pTextSection->VirtualAddress;
            BYTE* pDiskText = pFileBase + pFileTextSection->PointerToRawData;

            /* Compare the smaller of the two sizes */
            DWORD compareSize = min(pTextSection->Misc.VirtualSize,
                                    pFileTextSection->SizeOfRawData);

            if (memcmp(pMemText, pDiskText, compareSize) != 0) {
                integrity = FALSE;
            }
        }

        UnmapViewOfFile(pFileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);

        return integrity;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}
