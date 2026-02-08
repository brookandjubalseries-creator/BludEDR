/*
 * BludEDR - encryption_patterns.yar
 * Encryption and sleep obfuscation detection
 */

rule AES_SBox_Constants
{
    meta:
        description = "AES S-Box lookup table found in memory"
        author = "BludEDR"
        severity = "medium"
        score = 45

    strings:
        /* AES Forward S-Box first 32 bytes */
        $sbox = {
            63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
            CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
        }
        /* AES Inverse S-Box first 16 bytes */
        $inv_sbox = {
            52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB
        }
        /* AES round constants */
        $rcon = { 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 }

    condition:
        any of them
}

rule RC4_KSA_Pattern
{
    meta:
        description = "RC4 Key Scheduling Algorithm pattern"
        author = "BludEDR"
        severity = "low"
        score = 30

    strings:
        /* RC4 initialization loop (256 iterations) */
        $ksa_x64 = { 48 FF C? 48 3D 00 01 00 00 7? }
        $ksa_x86 = { (40|41|42|43) 3D 00 01 00 00 7? }

    condition:
        any of them and filesize < 5MB
}

rule XOR_Decode_Loop
{
    meta:
        description = "XOR decoding loop common in malware"
        author = "BludEDR"
        severity = "medium"
        score = 40

    strings:
        /* xor [reg], byte/dword; inc/add reg; cmp/loop */
        $xor_loop1 = { 30 (0?|1?|2?|3?) (40|41|42|43|FE C?|FF C?) (3?|7?) }
        $xor_loop2 = { 31 (0?|1?|2?|3?) (83 C? 04) (3?|7?) }
        /* XOR with single-byte key pattern */
        $xor_byte = { 80 3? ?? (40|41|42|43|48 FF C?) (3D|39|48 3D|48 39) }

    condition:
        any of them and filesize < 5MB
}

rule Sleep_Obfuscation_Ekko
{
    meta:
        description = "Ekko sleep obfuscation technique markers"
        author = "BludEDR"
        severity = "high"
        score = 70

    strings:
        $api1 = "NtContinue" ascii
        $api2 = "RtlCreateTimerQueue" ascii
        $api3 = "RtlCreateTimer" ascii
        $api4 = "RtlDeleteTimerQueue" ascii
        $api5 = "SystemFunction032" ascii
        $api6 = "NtWaitForSingleObject" ascii

    condition:
        4 of them
}

rule Sleep_Obfuscation_Cronos
{
    meta:
        description = "Cronos/Foliage sleep obfuscation technique"
        author = "BludEDR"
        severity = "high"
        score = 70

    strings:
        $api1 = "NtSetContextThread" ascii
        $api2 = "NtGetContextThread" ascii
        $api3 = "SetThreadContext" ascii
        $api4 = "GetThreadContext" ascii
        $api5 = "VirtualProtect" ascii
        $api6 = "CreateTimerQueueTimer" ascii
        $api7 = "NtContinue" ascii

    condition:
        5 of them
}

rule Memory_Encryption_Generic
{
    meta:
        description = "Generic memory encryption patterns"
        author = "BludEDR"
        severity = "medium"
        score = 50

    strings:
        $api1 = "SystemFunction032" ascii
        $api2 = "SystemFunction033" ascii
        $api3 = "BCryptEncrypt" ascii
        $api4 = "BCryptDecrypt" ascii
        $api5 = "VirtualProtect" ascii
        $timer1 = "CreateTimerQueueTimer" ascii
        $timer2 = "NtCreateTimer" ascii

    condition:
        ($api1 or $api2 or $api3 or $api4) and $api5 and ($timer1 or $timer2)
}
