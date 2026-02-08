/*
 * BludEDR - callstack_capture.h
 * Callstack capture and analysis utilities
 */

#pragma once

#include "../inc/hookdll.h"

#define CALLSTACK_MODULE_CACHE_INTERVAL  5000  /* ms - refresh interval */

struct ModuleRange {
    PVOID   baseAddress;
    SIZE_T  size;
};
