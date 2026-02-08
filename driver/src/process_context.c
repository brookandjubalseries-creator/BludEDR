/*
 * BludEDR - process_context.c
 * Per-process context management using a hash table protected by a pushlock.
 * Tracks metadata like process flags, image path, and parent PID.
 *
 * Note: While the driver registers FLT_STREAMHANDLE_CONTEXT with the
 * minifilter, this module provides a standalone process context table
 * for tracking process-level metadata independently of file stream
 * handles. The minifilter context registration is available for
 * per-file-stream metadata if needed in the future.
 */

#include "../inc/driver.h"

/* ============================================================================
 * Hash table for process contexts
 * ============================================================================ */

#define PROCESS_CONTEXT_TABLE_SIZE  256  /* Must be power of 2 */
#define PROCESS_CONTEXT_TABLE_MASK  (PROCESS_CONTEXT_TABLE_SIZE - 1)

typedef struct _PROCESS_CONTEXT_ENTRY {
    LIST_ENTRY              ListEntry;
    BLUD_PROCESS_CONTEXT    Context;
} PROCESS_CONTEXT_ENTRY, *PPROCESS_CONTEXT_ENTRY;

typedef struct _PROCESS_CONTEXT_TABLE {
    LIST_ENTRY    Buckets[PROCESS_CONTEXT_TABLE_SIZE];
    EX_PUSH_LOCK  Locks[PROCESS_CONTEXT_TABLE_SIZE];
    BOOLEAN       Initialized;
} PROCESS_CONTEXT_TABLE, *PPROCESS_CONTEXT_TABLE;

static PROCESS_CONTEXT_TABLE g_ProcessTable = { 0 };

/* Simple hash: spread PID across buckets */
static __inline ULONG
BludpHashPid(
    _In_ ULONG Pid
    )
{
    /* Knuth multiplicative hash */
    return (Pid * 2654435761U) & PROCESS_CONTEXT_TABLE_MASK;
}

/* ============================================================================
 * BludProcessContextInitialize
 * ============================================================================ */
NTSTATUS
BludProcessContextInitialize(
    VOID
    )
{
    ULONG i;

    for (i = 0; i < PROCESS_CONTEXT_TABLE_SIZE; i++) {
        InitializeListHead(&g_ProcessTable.Buckets[i]);
        FltInitializePushLock(&g_ProcessTable.Locks[i]);
    }

    g_ProcessTable.Initialized = TRUE;

    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludProcessContextCleanup
 *
 * Frees all remaining process context entries. Called during driver unload.
 * ============================================================================ */
VOID
BludProcessContextCleanup(
    VOID
    )
{
    ULONG i;

    if (!g_ProcessTable.Initialized) {
        return;
    }

    for (i = 0; i < PROCESS_CONTEXT_TABLE_SIZE; i++) {
        FltAcquirePushLockExclusive(&g_ProcessTable.Locks[i]);

        while (!IsListEmpty(&g_ProcessTable.Buckets[i])) {
            PLIST_ENTRY listEntry = RemoveHeadList(&g_ProcessTable.Buckets[i]);
            PPROCESS_CONTEXT_ENTRY entry = CONTAINING_RECORD(
                listEntry, PROCESS_CONTEXT_ENTRY, ListEntry);
            ExFreePoolWithTag(entry, BLUD_POOL_TAG);
        }

        FltReleasePushLock(&g_ProcessTable.Locks[i]);
        FltDeletePushLock(&g_ProcessTable.Locks[i]);
    }

    g_ProcessTable.Initialized = FALSE;
}

/* ============================================================================
 * BludProcessContextCreate
 *
 * Creates and inserts a new process context entry.
 * ============================================================================ */
NTSTATUS
BludProcessContextCreate(
    _In_  ULONG               ProcessId,
    _In_  ULONG               ParentProcessId,
    _In_opt_ PUNICODE_STRING  ImagePath,
    _Out_ PBLUD_PROCESS_CONTEXT *Context
    )
{
    PPROCESS_CONTEXT_ENTRY  entry;
    ULONG                   bucket;

    *Context = NULL;

    if (!g_ProcessTable.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    entry = (PPROCESS_CONTEXT_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PROCESS_CONTEXT_ENTRY),
        BLUD_POOL_TAG
        );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(*entry));
    InitializeListHead(&entry->ListEntry);

    entry->Context.ProcessId       = ProcessId;
    entry->Context.ParentProcessId = ParentProcessId;
    entry->Context.Flags           = PROCESS_FLAG_MONITORED;
    KeQuerySystemTimePrecise(&entry->Context.CreateTime);

    if (ImagePath != NULL && ImagePath->Buffer != NULL && ImagePath->Length > 0) {
        USHORT copyLen = ImagePath->Length;
        if (copyLen > (SENTINEL_MAX_PATH - 1) * sizeof(WCHAR)) {
            copyLen = (SENTINEL_MAX_PATH - 1) * sizeof(WCHAR);
        }
        RtlCopyMemory(entry->Context.ImagePath, ImagePath->Buffer, copyLen);
    }

    bucket = BludpHashPid(ProcessId);

    FltAcquirePushLockExclusive(&g_ProcessTable.Locks[bucket]);
    InsertTailList(&g_ProcessTable.Buckets[bucket], &entry->ListEntry);
    FltReleasePushLock(&g_ProcessTable.Locks[bucket]);

    *Context = &entry->Context;
    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludProcessContextLookup
 *
 * Looks up a process context by PID. Returns NULL if not found.
 * The returned pointer is valid as long as the process context is not removed.
 * Caller should not hold the lock beyond immediate use.
 * ============================================================================ */
PBLUD_PROCESS_CONTEXT
BludProcessContextLookup(
    _In_ ULONG ProcessId
    )
{
    ULONG                   bucket;
    PLIST_ENTRY             listEntry;
    PPROCESS_CONTEXT_ENTRY  entry;
    PBLUD_PROCESS_CONTEXT   result = NULL;

    if (!g_ProcessTable.Initialized) {
        return NULL;
    }

    bucket = BludpHashPid(ProcessId);

    FltAcquirePushLockShared(&g_ProcessTable.Locks[bucket]);

    for (listEntry = g_ProcessTable.Buckets[bucket].Flink;
         listEntry != &g_ProcessTable.Buckets[bucket];
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, PROCESS_CONTEXT_ENTRY, ListEntry);
        if (entry->Context.ProcessId == ProcessId) {
            result = &entry->Context;
            break;
        }
    }

    FltReleasePushLock(&g_ProcessTable.Locks[bucket]);

    return result;
}

/* ============================================================================
 * BludProcessContextRemove
 *
 * Removes and frees a process context entry by PID.
 * ============================================================================ */
VOID
BludProcessContextRemove(
    _In_ ULONG ProcessId
    )
{
    ULONG                   bucket;
    PLIST_ENTRY             listEntry;
    PPROCESS_CONTEXT_ENTRY  entry;
    PPROCESS_CONTEXT_ENTRY  found = NULL;

    if (!g_ProcessTable.Initialized) {
        return;
    }

    bucket = BludpHashPid(ProcessId);

    FltAcquirePushLockExclusive(&g_ProcessTable.Locks[bucket]);

    for (listEntry = g_ProcessTable.Buckets[bucket].Flink;
         listEntry != &g_ProcessTable.Buckets[bucket];
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, PROCESS_CONTEXT_ENTRY, ListEntry);
        if (entry->Context.ProcessId == ProcessId) {
            found = entry;
            RemoveEntryList(&entry->ListEntry);
            break;
        }
    }

    FltReleasePushLock(&g_ProcessTable.Locks[bucket]);

    if (found != NULL) {
        ExFreePoolWithTag(found, BLUD_POOL_TAG);
    }
}
