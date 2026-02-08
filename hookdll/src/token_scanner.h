/*
 * BludEDR - token_scanner.h
 * Memory scanner for credential material (tokens, API keys, JWTs)
 */

#pragma once

#include "../inc/hookdll.h"

#define TOKEN_SCAN_INTERVAL  10000  /* ms */
#define TOKEN_MAX_MATCH_LEN  64     /* Truncated match length for event */
