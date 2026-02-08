/*
 * BludEDR - event_queue.c
 * Lock-free ring buffer with 4096 slots using InterlockedCompareExchange
 * for head/tail management. KEVENT for signaling.
 * EnqueueEvent and DequeueEvent functions.
 */

#include "../inc/driver.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, BludEventQueueInitialize)
#pragma alloc_text(PAGE, BludEventQueueDestroy)
#endif

/* ============================================================================
 * BludEventQueueInitialize
 *
 * Allocates the ring buffer array and initializes synchronization.
 * ============================================================================ */
NTSTATUS
BludEventQueueInitialize(
    _Out_ PBLUD_EVENT_QUEUE Queue,
    _In_  ULONG             Capacity
    )
{
    SIZE_T allocationSize;

    PAGED_CODE();

    RtlZeroMemory(Queue, sizeof(*Queue));

    /*
     * Capacity must be a power of two for efficient modular arithmetic.
     * If it is not, round up to the next power of two.
     */
    {
        ULONG c = Capacity;
        if (c == 0) c = 1;
        c--;
        c |= c >> 1;
        c |= c >> 2;
        c |= c >> 4;
        c |= c >> 8;
        c |= c >> 16;
        c++;
        Capacity = c;
    }

    allocationSize = (SIZE_T)Capacity * sizeof(SENTINEL_QUEUE_ENTRY);

    Queue->Entries = (PSENTINEL_QUEUE_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        allocationSize,
        BLUD_POOL_TAG
        );

    if (Queue->Entries == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Queue->Entries, allocationSize);

    Queue->Head     = 0;
    Queue->Tail     = 0;
    Queue->Capacity = Capacity;
    Queue->DroppedCount = 0;

    /* Initialize the event as auto-reset (SynchronizationEvent) */
    KeInitializeEvent(&Queue->DataReadyEvent, SynchronizationEvent, FALSE);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BludEDR: Event queue initialized, capacity=%lu, entry_size=%lu\n",
        Capacity, (ULONG)sizeof(SENTINEL_QUEUE_ENTRY)));

    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludEventQueueDestroy
 *
 * Frees the ring buffer array.
 * ============================================================================ */
VOID
BludEventQueueDestroy(
    _Inout_ PBLUD_EVENT_QUEUE Queue
    )
{
    PAGED_CODE();

    if (Queue->Entries != NULL) {
        ExFreePoolWithTag(Queue->Entries, BLUD_POOL_TAG);
        Queue->Entries = NULL;
    }

    Queue->Head     = 0;
    Queue->Tail     = 0;
    Queue->Capacity = 0;
}

/* ============================================================================
 * BludEnqueueEvent
 *
 * Lock-free producer. Claims a slot by atomically advancing Head.
 * Uses the three-state protocol: SLOT_FREE -> SLOT_WRITING -> SLOT_READY.
 *
 * Can be called at IRQL <= DISPATCH_LEVEL.
 *
 * Returns TRUE if the event was enqueued, FALSE if the queue is full.
 * ============================================================================ */
BOOLEAN
BludEnqueueEvent(
    _Inout_ PBLUD_EVENT_QUEUE Queue,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_    ULONG             DataSize
    )
{
    LONG    head;
    LONG    tail;
    LONG    nextHead;
    LONG    mask;
    PSENTINEL_QUEUE_ENTRY slot;

    if (Queue->Entries == NULL || DataSize == 0) {
        return FALSE;
    }

    if (DataSize > sizeof(((PSENTINEL_QUEUE_ENTRY)0)->Data)) {
        /* Event too large for a slot */
        InterlockedIncrement(&Queue->DroppedCount);
        return FALSE;
    }

    mask = (LONG)(Queue->Capacity - 1);

    /*
     * Try to claim the next slot. We use a CAS loop on Head.
     */
    for (;;) {
        head = Queue->Head;
        tail = Queue->Tail;
        nextHead = (head + 1) & mask;

        /*
         * If advancing Head would land on Tail, the buffer is full.
         * We lose one slot to distinguish full from empty, which is
         * the standard approach for lock-free ring buffers.
         */
        if (nextHead == tail) {
            InterlockedIncrement(&Queue->DroppedCount);
            return FALSE;
        }

        /* Try to claim this slot */
        if (InterlockedCompareExchange(&Queue->Head, nextHead, head) == head) {
            /* We own slot at index 'head' */
            slot = &Queue->Entries[head];

            /*
             * Transition SLOT_FREE -> SLOT_WRITING.
             * If the slot is not FREE, a previous entry has not been consumed yet.
             * This should not happen in a correctly sized buffer, but handle it
             * gracefully.
             */
            if (InterlockedCompareExchange(&slot->InUse, SLOT_WRITING, SLOT_FREE) != SLOT_FREE) {
                /* Slot was not free -- another producer or stale entry */
                InterlockedIncrement(&Queue->DroppedCount);
                return FALSE;
            }

            /* Write the data */
            slot->DataSize = DataSize;
            RtlCopyMemory(slot->Data, Data, DataSize);

            /* Transition SLOT_WRITING -> SLOT_READY */
            InterlockedExchange(&slot->InUse, SLOT_READY);

            /* Signal the consumer */
            KeSetEvent(&Queue->DataReadyEvent, IO_NO_INCREMENT, FALSE);

            return TRUE;
        }

        /* CAS failed, another producer won -- retry */
        YieldProcessor();
    }
}

/* ============================================================================
 * BludDequeueEvent
 *
 * Lock-free consumer. Claims the slot at Tail by atomically advancing Tail.
 * Waits for SLOT_READY state before reading.
 *
 * Must be called at IRQL <= APC_LEVEL (due to potential waits).
 *
 * Returns TRUE if an event was dequeued, FALSE if the queue is empty.
 * ============================================================================ */
BOOLEAN
BludDequeueEvent(
    _Inout_ PBLUD_EVENT_QUEUE Queue,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_    ULONG             BufferSize,
    _Out_   PULONG            BytesCopied
    )
{
    LONG    head;
    LONG    tail;
    LONG    nextTail;
    LONG    mask;
    PSENTINEL_QUEUE_ENTRY slot;
    LONG    spinCount = 0;

    *BytesCopied = 0;

    if (Queue->Entries == NULL) {
        return FALSE;
    }

    mask = (LONG)(Queue->Capacity - 1);

    /*
     * Try to claim the next slot to consume. CAS loop on Tail.
     */
    for (;;) {
        tail = Queue->Tail;
        head = Queue->Head;

        if (tail == head) {
            /* Queue is empty */
            return FALSE;
        }

        nextTail = (tail + 1) & mask;

        if (InterlockedCompareExchange(&Queue->Tail, nextTail, tail) == tail) {
            /* We own slot at index 'tail' */
            slot = &Queue->Entries[tail];

            /*
             * Wait for the slot to become READY. The producer transitions
             * from WRITING to READY. Spin briefly.
             */
            spinCount = 0;
            while (InterlockedCompareExchange(&slot->InUse, SLOT_READY, SLOT_READY) != SLOT_READY) {
                YieldProcessor();
                spinCount++;
                if (spinCount > 100000) {
                    /*
                     * Safety: if we spin too long, the producer may have
                     * encountered an error. Mark the slot as free and skip.
                     */
                    InterlockedExchange(&slot->InUse, SLOT_FREE);
                    return FALSE;
                }
            }

            /* Copy the data out */
            if (slot->DataSize <= BufferSize && slot->DataSize > 0) {
                RtlCopyMemory(Buffer, slot->Data, slot->DataSize);
                *BytesCopied = slot->DataSize;
            }

            /* Transition SLOT_READY -> SLOT_FREE */
            slot->DataSize = 0;
            InterlockedExchange(&slot->InUse, SLOT_FREE);

            return TRUE;
        }

        /* CAS failed, another consumer won -- retry */
        YieldProcessor();
    }
}
