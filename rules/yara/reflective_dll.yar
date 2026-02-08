/*
 * BludEDR - reflective_dll.yar
 * Reflective DLL injection and process hollowing detection
 */

rule Reflective_DLL_Loader
{
    meta:
        description = "Reflective DLL loading pattern"
        author = "BludEDR"
        severity = "critical"
        score = 95

    strings:
        $export1 = "ReflectiveLoader" ascii
        $export2 = "_ReflectiveLoader@4" ascii
        $export3 = "reflective_dll" ascii nocase

        /* Manual PE loading patterns */
        $pe_sig = "This program cannot be run in DOS mode" ascii
        $reloc = ".reloc" ascii
        $manual1 = "VirtualAlloc" ascii
        $manual2 = "GetProcAddress" ascii
        $manual3 = "LoadLibraryA" ascii
        $manual4 = "NtFlushInstructionCache" ascii

    condition:
        (any of ($export*)) or
        ($pe_sig and $reloc and 3 of ($manual*))
}

rule Process_Hollowing_Strings
{
    meta:
        description = "Process hollowing API sequence"
        author = "BludEDR"
        severity = "critical"
        score = 90

    strings:
        $api1 = "NtUnmapViewOfSection" ascii
        $api2 = "ZwUnmapViewOfSection" ascii
        $api3 = "NtMapViewOfSection" ascii
        $api4 = "NtCreateSection" ascii
        $api5 = "WriteProcessMemory" ascii
        $api6 = "NtWriteVirtualMemory" ascii
        $api7 = "ResumeThread" ascii
        $api8 = "NtResumeThread" ascii
        $api9 = "CreateProcessA" ascii
        $api10 = "CreateProcessW" ascii
        $api11 = "SetThreadContext" ascii
        $api12 = "NtSetContextThread" ascii

    condition:
        ($api1 or $api2) and ($api5 or $api6) and ($api7 or $api8) and ($api9 or $api10)
}

rule PE_Injection_RunPE
{
    meta:
        description = "RunPE / Process injection technique"
        author = "BludEDR"
        severity = "very_high"
        score = 85

    strings:
        $create = "CreateProcess" ascii
        $suspend = "CREATE_SUSPENDED" ascii
        $ctx1 = "GetThreadContext" ascii
        $ctx2 = "SetThreadContext" ascii
        $write = "WriteProcessMemory" ascii
        $resume = "ResumeThread" ascii
        $alloc = "VirtualAllocEx" ascii

    condition:
        $create and ($ctx1 or $ctx2) and $write and $resume
}

rule DLL_Side_Loading
{
    meta:
        description = "DLL side-loading / search order hijacking indicators"
        author = "BludEDR"
        severity = "high"
        score = 70

    strings:
        $export1 = "DllMain" ascii
        $export2 = "DllRegisterServer" ascii
        $proxy1 = "GetFileVersionInfoW" ascii
        $proxy2 = "GetFileVersionInfoSizeW" ascii
        $proxy3 = "VerQueryValueW" ascii
        $load = "LoadLibrary" ascii

    condition:
        uint16(0) == 0x5A4D and
        $export1 and $load and 2 of ($proxy*)
}

rule AMSI_Bypass_Strings
{
    meta:
        description = "AMSI bypass technique strings"
        author = "BludEDR"
        severity = "very_high"
        score = 90

    strings:
        $amsi1 = "AmsiScanBuffer" ascii
        $amsi2 = "AmsiInitialize" ascii
        $amsi3 = "AmsiOpenSession" ascii
        $amsi4 = "amsi.dll" ascii nocase
        $patch1 = "VirtualProtect" ascii
        $patch2 = "WriteProcessMemory" ascii
        $patch3 = { B8 57 00 07 80 }  /* mov eax, 0x80070057 (AMSI_RESULT_CLEAN) */
        $patch4 = { C3 }              /* ret */

    condition:
        2 of ($amsi*) and ($patch1 or $patch2) and ($patch3 or $patch4)
}

rule ETW_Bypass_Strings
{
    meta:
        description = "ETW bypass technique strings"
        author = "BludEDR"
        severity = "very_high"
        score = 85

    strings:
        $etw1 = "EtwEventWrite" ascii
        $etw2 = "NtTraceEvent" ascii
        $etw3 = "EtwEventWriteFull" ascii
        $ntdll = "ntdll.dll" ascii nocase
        $patch1 = "VirtualProtect" ascii
        $patch2 = { C3 } /* ret - single byte patch */

    condition:
        ($etw1 or $etw2 or $etw3) and $ntdll and $patch1
}
