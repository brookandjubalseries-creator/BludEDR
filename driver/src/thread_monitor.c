/*
 * BludEDR - thread_monitor.c
 * Thread creation callback (PsSetCreateThreadNotifyRoutineEx).
 * Flags cross-process thread creation (where creator PID != target PID).
 * Sends SENTINEL_THREAD_EVENT via the event queue.
 */

#include "../inc/driver.h"

/* ============================================================================
 * BludThreadNotifyRoutine
 * ============================================================================ */
VOID
BludThreadNotifyRoutine(
    _In_ HANDLE  ProcessId,
    _In_ HANDLE  ThreadId,
    _In_ BOOLEAN Create
    )
{
    SENTINEL_THREAD_EVENT threadEvent;
    ULONG                 callerPid;
    ULONG                 targetPid;

    /*
     * This callback runs at PASSIVE_LEVEL for thread creation
     * and at APC_LEVEL or below for thread termination.
     */

    targetPid = (ULONG)(ULONG_PTR)ProcessId;
    callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    RtlZeroMemory(&threadEvent, sizeof(threadEvent));

    if (Create) {
        BludFillEventHeader(&threadEvent.Header, EVENT_THREAD_CREATE, sizeof(threadEvent));
    } else {
        BludFillEventHeader(&threadEvent.Header, EVENT_THREAD_TERMINATE, sizeof(threadEvent));
    }

    threadEvent.TargetProcessId = targetPid;
    threadEvent.TargetThreadId  = (ULONG)(ULONG_PTR)ThreadId;
    /*
     * Only evaluate IsRemoteThread for creation events. During termination,
     * the calling context may be the System process during teardown, which
     * would falsely flag as a remote thread.
     */
    if (Create) {
        threadEvent.IsRemoteThread = (callerPid != targetPid) ? TRUE : FALSE;
    } else {
        threadEvent.IsRemoteThread = FALSE;
    }
    threadEvent.StartAddress    = NULL;

    /*
     * For thread creation, try to get the start address.
     * We use NtQueryInformationThread with ThreadQuerySetWin32StartAddress.
     * However, since we may be at elevated IRQL during termination,
     * only attempt this for creation events.
     */
    if (Create) {
        PETHREAD  threadObject = NULL;
        NTSTATUS  status;

        status = PsLookupThreadByThreadId(ThreadId, &threadObject);
        if (NT_SUCCESS(status)) {
            /*
             * The Win32StartAddress is stored in the ETHREAD.
             * We use the documented PsGetThreadStartAddress API
             * if available, otherwise leave it as NULL.
             */
            threadEvent.StartAddress = PsGetThreadStartAddress(threadObject);
            ObDereferenceObject(threadObject);
        }
    }

    /*
     * Only enqueue remote thread events or creation events.
     * Thread terminations that are not remote are low-value telemetry
     * and would flood the queue.
     */
    if (Create || threadEvent.IsRemoteThread) {
        BludEnqueueEvent(&g_Globals.EventQueue, &threadEvent, sizeof(threadEvent));
    }
}
