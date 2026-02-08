/*
 * BludEDR - sentinel_ioc.h
 * IoC (Indicator of Compromise) scoring definitions
 *
 * Made by @tarry
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* IoC severity levels */
typedef enum _IOC_SEVERITY {
    IOC_SEVERITY_INFO       = 0,    /* Informational only */
    IOC_SEVERITY_LOW        = 1,    /* Score 1-24 */
    IOC_SEVERITY_MEDIUM     = 2,    /* Score 25-49 */
    IOC_SEVERITY_HIGH       = 3,    /* Score 50-74 */
    IOC_SEVERITY_VERY_HIGH  = 4,    /* Score 75-89 */
    IOC_SEVERITY_CRITICAL   = 5,    /* Score 90-100 */
} IOC_SEVERITY;

/* IoC categories mapped to MITRE ATT&CK tactics */
typedef enum _IOC_CATEGORY {
    IOC_CAT_PROCESS_LINEAGE     = 0,
    IOC_CAT_COMMAND_LINE        = 1,
    IOC_CAT_FILE_DROP           = 2,
    IOC_CAT_DEFENSE_EVASION     = 3,
    IOC_CAT_PROCESS_INJECTION   = 4,
    IOC_CAT_CREDENTIAL_ACCESS   = 5,
    IOC_CAT_PERSISTENCE         = 6,
    IOC_CAT_EXECUTION           = 7,
    IOC_CAT_LATERAL_MOVEMENT    = 8,
    IOC_CAT_EXFILTRATION        = 9,
    IOC_CAT_MEMORY_TAMPERING    = 10,
    IOC_CAT_NETWORK_ANOMALY     = 11,
    IOC_CAT_COUNT               = 12,
} IOC_CATEGORY;

/* Alert action thresholds */
typedef enum _ALERT_ACTION {
    ACTION_LOG          = 0,    /* Score < 50: log only */
    ACTION_ALERT        = 1,    /* Score 50-79: generate alert */
    ACTION_SUSPEND      = 2,    /* Score 80-89: suspend process */
    ACTION_TERMINATE    = 3,    /* Score 90-100: terminate process */
} ALERT_ACTION;

/* Individual IoC score entry */
typedef struct _IOC_SCORE_ENTRY {
    unsigned long   RuleId;
    unsigned long   Score;
    IOC_SEVERITY    Severity;
    IOC_CATEGORY    Category;
    unsigned long   ProcessId;
    long long       Timestamp;      /* FILETIME */
} IOC_SCORE_ENTRY;

/* Built-in rule IDs */
#define RULE_CMD_SPAWNS_POWERSHELL          1001
#define RULE_POWERSHELL_ENCODED             1002
#define RULE_SCRIPT_FILE_DROP               1003
#define RULE_LOLBAS_SUSPICIOUS_ARGS         1004
#define RULE_SUSPICIOUS_PARENT_CHILD        1005
#define RULE_UNSIGNED_MODULE_LOAD           1006
#define RULE_REMOTE_THREAD_CREATION         1007
#define RULE_LSASS_ACCESS                   1008
#define RULE_AMSI_BYPASS                    1009
#define RULE_ETW_BYPASS                     1010
#define RULE_RWX_ALLOCATION                 1011
#define RULE_RW_TO_RX_TRANSITION            1012
#define RULE_REGISTRY_PERSISTENCE           1013
#define RULE_SLEEP_OBFUSCATION              1014
#define RULE_VEH_SUSPICIOUS                 1015
#define RULE_PROCESS_HOLLOWING              1016
#define RULE_APC_INJECTION                  1017
#define RULE_CROSS_PROCESS_WRITE            1018
#define RULE_TOKEN_IN_MEMORY                1019
#define RULE_HIGH_ENTROPY_DNS               1020
#define RULE_BEACONING                      1021
#define RULE_YARA_MATCH                     1022
#define RULE_CORRELATION_MATCH              1023

#ifdef __cplusplus
}
#endif
