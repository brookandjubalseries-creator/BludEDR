/*
 * BludEDR - sentinel_events.h
 * Event type definitions for kernel-to-userspace communication
 *
 * Made by @tarry
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Event type ranges:
 *   0x0100 - Process events
 *   0x0200 - Thread events
 *   0x0300 - Image/module events
 *   0x0400 - File events
 *   0x0500 - Registry events
 *   0x0600 - Object/handle events
 *   0x0700 - Memory events (from hook DLL)
 *   0x0800 - Network events
 *   0x0900 - Detection/alert events
 */

typedef enum _SENTINEL_EVENT_TYPE {
    /* Process events (0x0100) */
    EVENT_PROCESS_CREATE        = 0x0100,
    EVENT_PROCESS_TERMINATE     = 0x0101,

    /* Thread events (0x0200) */
    EVENT_THREAD_CREATE         = 0x0200,
    EVENT_THREAD_TERMINATE      = 0x0201,

    /* Image/module events (0x0300) */
    EVENT_IMAGE_LOAD            = 0x0300,

    /* File events (0x0400) */
    EVENT_FILE_CREATE           = 0x0400,
    EVENT_FILE_WRITE            = 0x0401,
    EVENT_FILE_DELETE            = 0x0402,
    EVENT_FILE_RENAME           = 0x0403,

    /* Registry events (0x0500) */
    EVENT_REGISTRY_SET_VALUE    = 0x0500,
    EVENT_REGISTRY_CREATE_KEY   = 0x0501,
    EVENT_REGISTRY_DELETE_VALUE = 0x0502,
    EVENT_REGISTRY_DELETE_KEY   = 0x0503,

    /* Object/handle events (0x0600) */
    EVENT_OBJECT_HANDLE_CREATE  = 0x0600,
    EVENT_OBJECT_HANDLE_DUP     = 0x0601,

    /* Memory events - from hook DLL (0x0700) */
    EVENT_MEMORY_ALLOC          = 0x0700,
    EVENT_MEMORY_PROTECT        = 0x0701,
    EVENT_MEMORY_WRITE          = 0x0702,
    EVENT_MEMORY_MAP            = 0x0703,
    EVENT_REMOTE_THREAD         = 0x0704,
    EVENT_APC_QUEUE             = 0x0705,
    EVENT_AMSI_BYPASS           = 0x0706,
    EVENT_ETW_BYPASS            = 0x0707,
    EVENT_VEH_INSTALL           = 0x0708,
    EVENT_SLEEP_OBFUSCATION     = 0x0709,
    EVENT_TOKEN_FOUND           = 0x070A,

    /* Network events (0x0800) */
    EVENT_NETWORK_CONNECT       = 0x0800,
    EVENT_NETWORK_ACCEPT        = 0x0801,
    EVENT_DNS_QUERY             = 0x0802,

    /* Detection/alert events (0x0900) */
    EVENT_IOC_ALERT             = 0x0900,
    EVENT_YARA_MATCH            = 0x0901,
    EVENT_CORRELATION_MATCH     = 0x0902,

} SENTINEL_EVENT_TYPE;

/* Command types for agent->driver communication */
typedef enum _SENTINEL_COMMAND_TYPE {
    CMD_SUSPEND_PROCESS         = 0x0001,
    CMD_TERMINATE_PROCESS       = 0x0002,
    CMD_QUERY_PROCESS_INFO      = 0x0003,
    CMD_SET_PROTECTION          = 0x0004,
    CMD_INJECT_DLL              = 0x0005,
    CMD_PING                    = 0x00FF,
} SENTINEL_COMMAND_TYPE;

#ifdef __cplusplus
}
#endif
