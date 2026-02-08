/*
 * BludEDR - process_monitor.c
 * Process create/terminate callback (PsSetCreateProcessNotifyRoutineEx).
 * Captures parent PID, creator PID/TID, command line, image path.
 * Sends SENTINEL_PROCESS_EVENT via the event queue.
 */

#include "../inc/driver.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, BludProcessNotifyRoutineEx)
#endif

/* ============================================================================
 * Local helpers
 * ============================================================================ */
static VOID
BludpCopyUnicodeStringToBuffer(
    _Out_writes_(MaxChars) PWCHAR     Destination,
    _In_                   ULONG      MaxChars,
    _In_                   PCUNICODE_STRING Source
    )
{
    ULONG copyChars;

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        Destination[0] = L'\0';
        return;
    }

    copyChars = Source->Length / sizeof(WCHAR);
    if (copyChars >= MaxChars) {
        copyChars = MaxChars - 1;
    }

    RtlCopyMemory(Destination, Source->Buffer, copyChars * sizeof(WCHAR));
    Destination[copyChars] = L'\0';
}

/*
 * Check if the image path ends with "lsass.exe" and update the global
 * LSASS PID cache.
 */
static VOID
BludpCheckLsass(
    _In_ HANDLE          ProcessId,
    _In_ PUNICODE_STRING ImageFileName
    )
{
    UNICODE_STRING lsassName = RTL_CONSTANT_STRING(L"lsass.exe");

    if (ImageFileName == NULL || ImageFileName->Buffer == NULL) {
        return;
    }

    /* Quick suffix check */
    if (ImageFileName->Length >= lsassName.Length) {
        UNICODE_STRING suffix;
        suffix.Length = lsassName.Length;
        suffix.MaximumLength = lsassName.Length;
        suffix.Buffer = (PWCH)((ULONG_PTR)ImageFileName->Buffer +
                        ImageFileName->Length - lsassName.Length);

        if (RtlEqualUnicodeString(&suffix, &lsassName, TRUE)) {
            g_Globals.LsassPid = (ULONG)(ULONG_PTR)ProcessId;
        }
    }
}

/* ============================================================================
 * BludProcessNotifyRoutineEx
 * ============================================================================ */
VOID
BludProcessNotifyRoutineEx(
    _Inout_  PEPROCESS                  Process,
    _In_     HANDLE                     ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO  CreateInfo
    )
{
    SENTINEL_PROCESS_EVENT procEvent;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Process);

    RtlZeroMemory(&procEvent, sizeof(procEvent));

    if (CreateInfo != NULL) {
        /* ---- Process Creation ---- */
        BludFillEventHeader(&procEvent.Header, EVENT_PROCESS_CREATE, sizeof(procEvent));

        procEvent.ParentProcessId  = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
        procEvent.CreatorProcessId = (ULONG)(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess;
        procEvent.CreatorThreadId  = (ULONG)(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread;
        procEvent.IsTermination    = FALSE;
        procEvent.ExitCode         = 0;

        /* Capture image path */
        if (CreateInfo->ImageFileName != NULL) {
            BludpCopyUnicodeStringToBuffer(
                procEvent.ImagePath,
                SENTINEL_MAX_PATH,
                CreateInfo->ImageFileName
                );

            /* Update LSASS PID if this is lsass */
            BludpCheckLsass(ProcessId, CreateInfo->ImageFileName);
        }

        /* Capture command line */
        if (CreateInfo->CommandLine != NULL) {
            BludpCopyUnicodeStringToBuffer(
                procEvent.CommandLine,
                SENTINEL_MAX_COMMAND_LINE,
                CreateInfo->CommandLine
                );
        }

        /* Override the header PID with the actual new process PID */
        procEvent.Header.ProcessId = (ULONG)(ULONG_PTR)ProcessId;

        /* Create a process context entry for tracking */
        {
            PBLUD_PROCESS_CONTEXT ctx = NULL;
            BludProcessContextCreate(
                (ULONG)(ULONG_PTR)ProcessId,
                (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId,
                CreateInfo->ImageFileName,
                &ctx
                );
            /* ctx may be NULL if allocation failed -- non-fatal */
        }

    } else {
        /* ---- Process Termination ---- */
        BludFillEventHeader(&procEvent.Header, EVENT_PROCESS_TERMINATE, sizeof(procEvent));

        procEvent.Header.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
        procEvent.IsTermination    = TRUE;

        /* Retrieve exit code */
        {
            NTSTATUS exitStatus;
            PEPROCESS targetProcess;
            NTSTATUS lookupStatus;

            lookupStatus = PsLookupProcessByProcessId(ProcessId, &targetProcess);
            if (NT_SUCCESS(lookupStatus)) {
                /*
                 * PsGetProcessExitStatus returns the exit status.
                 * We cast NTSTATUS to ULONG for the event.
                 */
                exitStatus = PsGetProcessExitStatus(targetProcess);
                procEvent.ExitCode = (ULONG)exitStatus;
                ObDereferenceObject(targetProcess);
            }
        }

        /* Clear LSASS PID if it is terminating */
        if ((ULONG)(ULONG_PTR)ProcessId == g_Globals.LsassPid) {
            g_Globals.LsassPid = 0;
        }

        /* Remove process context */
        BludProcessContextRemove((ULONG)(ULONG_PTR)ProcessId);
    }

    /* Enqueue the event */
    BludEnqueueEvent(&g_Globals.EventQueue, &procEvent, sizeof(procEvent));
}
