/*
 * BludEDR - sleep_obfuscation_detect.h
 * Detects Ekko/Cronos/Foliage sleep obfuscation patterns
 */

#pragma once

#include "../inc/hookdll.h"

#define SLEEP_DETECT_WINDOW_MS      1000    /* Time window for pattern matching */
#define SLEEP_DETECT_THRESHOLD      3       /* Number of pattern repeats to trigger */
#define SLEEP_DETECT_MAX_REGIONS    128     /* Max tracked regions */
#define SLEEP_DETECT_HISTORY_SIZE   8       /* Circular buffer size per region */

struct ProtectRecord {
    ULONG       newProtect;
    ULONGLONG   timestampMs;
};

struct RegionTracker {
    PVOID           baseAddress;
    ProtectRecord   history[SLEEP_DETECT_HISTORY_SIZE];
    ULONG           writeIndex;
    ULONG           count;
};
