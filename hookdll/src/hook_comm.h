/*
 * BludEDR - hook_comm.h
 * Named pipe client for communicating events to the agent
 */

#pragma once

#include "../inc/hookdll.h"

#define HOOK_COMM_RING_BUFFER_SIZE  256
#define HOOK_COMM_MAX_RETRIES       5
#define HOOK_COMM_BASE_BACKOFF_MS   100
