/*
 * BludEDR - etw_monitor.h
 * Periodic integrity checker for ETW functions
 */

#pragma once

#include "../inc/hookdll.h"

#define ETW_PROLOGUE_SIZE   16
#define ETW_CHECK_INTERVAL  500  /* ms */
