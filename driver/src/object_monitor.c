/*
 * BludEDR - object_monitor.c
 * ObRegisterCallbacks for process handle creation.
 * LSASS protection: strips PROCESS_VM_READ/WRITE from unauthorized callers.
 * Sends SENTINEL_OBJECT_EVENT via the event queue.
 */

#include "../inc/driver.h"

/* Access masks we strip from unauthorized LSASS accessors */
#define LSASS_STRIP_MASK  (PROCESS_VM_READ | PROCESS_VM_WRITE | \
                           PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | \
                           PROCESS_DUP_HANDLE)

/*
 * Whitelist: PIDs belonging to known-good system processes.
 * In a production implementation this would be a dynamic list
 * validated by signature/certificate checks.
 */
static BOOLEAN
BludpIsWhitelistedCaller(
    _In_ ULONG CallerPid
    )
{
    /* Always allow the System process (PID 4) */
    if (CallerPid == 4) {
        return TRUE;
    }

    /* Allow csrss.exe (PID is not fixed, but typically very low) */
    /* In production, check the process image against a signed allowlist */

    return FALSE;
}

/*
 * Retrieve image name for a process by PID for event reporting.
 */
static VOID
BludpGetProcessImageName(
    _In_  PEPROCESS Process,
    _Out_writes_(MaxChars) PWCHAR Buffer,
    _In_  ULONG     MaxChars
    )
{
    NTSTATUS status;
    PUNICODE_STRING imageName = NULL;

    Buffer[0] = L'\0';

    status = SeLocateProcessImageName(Process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL && imageName->Buffer != NULL) {
        ULONG copyChars = imageName->Length / sizeof(WCHAR);
        if (copyChars >= MaxChars) {
            copyChars = MaxChars - 1;
        }
        RtlCopyMemory(Buffer, imageName->Buffer, copyChars * sizeof(WCHAR));
        Buffer[copyChars] = L'\0';
        ExFreePool(imageName);
    }
}

/* ============================================================================
 * BludObPreOperationCallback
 * ============================================================================ */
OB_PREOP_CALLBACK_STATUS
BludObPreOperationCallback(
    _In_ PVOID                          RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PEPROCESS           targetProcess;
    ULONG               targetPid;
    ULONG               callerPid;
    ACCESS_MASK         originalAccess;
    ACCESS_MASK         strippedBits;
    SENTINEL_OBJECT_EVENT objEvent;

    UNREFERENCED_PARAMETER(RegistrationContext);

    /*
     * Only handle process objects.
     */
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    targetProcess = (PEPROCESS)OperationInformation->Object;
    targetPid     = (ULONG)(ULONG_PTR)PsGetProcessId(targetProcess);
    callerPid     = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    /*
     * Only protect LSASS. Skip if LSASS PID has not been resolved yet.
     */
    if (g_Globals.LsassPid == 0 || targetPid != g_Globals.LsassPid) {
        return OB_PREOP_SUCCESS;
    }

    /* Do not modify handles opened by the same process (self-access) */
    if (callerPid == targetPid) {
        return OB_PREOP_SUCCESS;
    }

    /* Allow whitelisted callers */
    if (BludpIsWhitelistedCaller(callerPid)) {
        return OB_PREOP_SUCCESS;
    }

    /*
     * Skip kernel-mode requests. The KernelHandle flag indicates
     * the handle was opened from kernel mode.
     */
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    /*
     * Defensive IRQL check: SeLocateProcessImageName (called via
     * BludpGetProcessImageName) accesses paged pool and cannot safely
     * run above APC_LEVEL.
     */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return OB_PREOP_SUCCESS;
    }

    /*
     * Determine which bits to strip.
     */
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        originalAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        strippedBits   = originalAccess & LSASS_STRIP_MASK;

        if (strippedBits != 0) {
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                ~LSASS_STRIP_MASK;
        }
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        originalAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        strippedBits   = originalAccess & LSASS_STRIP_MASK;

        if (strippedBits != 0) {
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &=
                ~LSASS_STRIP_MASK;
        }
    } else {
        return OB_PREOP_SUCCESS;
    }

    /*
     * If we stripped access bits, generate an event.
     */
    if (strippedBits != 0) {
        RtlZeroMemory(&objEvent, sizeof(objEvent));
        BludFillEventHeader(&objEvent.Header, EVENT_OBJECT_HANDLE_CREATE, sizeof(objEvent));

        objEvent.TargetProcessId = targetPid;
        objEvent.DesiredAccess   = originalAccess;
        objEvent.GrantedAccess   = originalAccess & ~LSASS_STRIP_MASK;
        objEvent.StrippedAccess  = strippedBits;

        /* Get the target image name (should be lsass.exe) */
        BludpGetProcessImageName(targetProcess,
                                  objEvent.TargetImageName,
                                  SENTINEL_MAX_PATH);

        BludEnqueueEvent(&g_Globals.EventQueue, &objEvent, sizeof(objEvent));

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "BludEDR: LSASS access blocked from PID %lu, stripped 0x%08X\n",
            callerPid, strippedBits));
    }

    return OB_PREOP_SUCCESS;
}

/* ============================================================================
 * BludObPostOperationCallback
 * ============================================================================ */
VOID
BludObPostOperationCallback(
    _In_ PVOID                            RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION   OperationInformation
    )
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);

    /*
     * Post-operation callback is required by ObRegisterCallbacks
     * but we do not need to perform any post-processing.
     */
}
