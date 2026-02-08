/*
 * BludEDR - shellcode_patterns.yar
 * Shellcode and code injection signatures
 */

rule Shellcode_x64_PEB_Walk
{
    meta:
        description = "x64 shellcode PEB walking pattern (gs:[0x60])"
        author = "BludEDR"
        severity = "very_high"
        score = 85

    strings:
        /* mov rax, gs:[0x60] - PEB access */
        $peb1 = { 65 48 8B 04 25 60 00 00 00 }
        /* mov rax, [rax+0x18] - PEB->Ldr */
        $ldr1 = { 48 8B 40 18 }
        /* mov rax, [rax+0x20] - Ldr->InMemoryOrderModuleList */
        $ldr2 = { 48 8B 40 20 }

    condition:
        $peb1 and ($ldr1 or $ldr2)
}

rule Shellcode_x86_PEB_Walk
{
    meta:
        description = "x86 shellcode PEB walking pattern (fs:[0x30])"
        author = "BludEDR"
        severity = "very_high"
        score = 85

    strings:
        /* mov eax, fs:[0x30] - PEB access */
        $peb1 = { 64 A1 30 00 00 00 }
        /* mov eax, [eax+0x0C] - PEB->Ldr */
        $ldr1 = { 8B 40 0C }
        /* mov eax, [eax+0x14] - InMemoryOrderModuleList */
        $ldr2 = { 8B 40 14 }

    condition:
        $peb1 and ($ldr1 or $ldr2)
}

rule Shellcode_ROR13_Hash
{
    meta:
        description = "API hashing via ROR13 (common in shellcode)"
        author = "BludEDR"
        severity = "very_high"
        score = 90

    strings:
        /* ror edi, 0xd (ROR13 API hash) */
        $ror13_1 = { C1 CF 0D }
        /* ror edx, 0xd */
        $ror13_2 = { C1 CA 0D }
        /* Hash values for common APIs */
        $hash_loadlib = { 72 6F 6E 00 }   /* Common LoadLibrary hash fragment */

    condition:
        ($ror13_1 or $ror13_2) and filesize < 1MB
}

rule Shellcode_CLD_CALL_POP
{
    meta:
        description = "Classic shellcode decoder prologue (CLD + CALL + POP)"
        author = "BludEDR"
        severity = "high"
        score = 80

    strings:
        /* FC E8 xx xx xx xx 58-5F (CLD; CALL $+5; POP reg) */
        $cld_call = { FC E8 ?? 00 00 00 (58|59|5A|5B|5E|5F) }

    condition:
        $cld_call
}

rule Shellcode_Syscall_Direct
{
    meta:
        description = "Direct syscall invocation (syscall/sysenter stubs)"
        author = "BludEDR"
        severity = "very_high"
        score = 90

    strings:
        /* mov r10, rcx; mov eax, SSN; syscall */
        $syscall_x64 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 }
        /* Classic int 2e syscall */
        $int2e = { CD 2E C3 }
        /* syscall; ret */
        $syscall_ret = { 0F 05 C3 }

    condition:
        any of them
}

rule Shellcode_Egg_Hunter
{
    meta:
        description = "Egg hunter shellcode pattern"
        author = "BludEDR"
        severity = "high"
        score = 75

    strings:
        /* NtAccessCheckAndAuditAlarm egg hunter */
        $egg1 = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 5A 74 }
        /* SEH-based egg hunter */
        $egg2 = { EB 21 59 B8 ?? ?? ?? ?? 51 6A FF }

    condition:
        any of them
}

rule Shellcode_Meterpreter_Reverse
{
    meta:
        description = "Meterpreter reverse shell pattern"
        author = "BludEDR"
        severity = "critical"
        score = 95

    strings:
        /* Meterpreter stage pattern */
        $stage = { 6A 00 53 56 57 68 02 D9 C8 5F }
        /* ws2_32 loading */
        $ws2 = "ws2_32" ascii
        /* Socket operations */
        $socket = { 6A 06 6A 01 6A 02 }

    condition:
        $stage or ($ws2 and $socket)
}
