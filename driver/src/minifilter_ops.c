/*
 * BludEDR - minifilter_ops.c
 * IRP_MJ_CREATE pre-callback for file create/drop detection.
 * Monitors suspicious file extensions (.bat, .vbs, .ps1, .js, .wsf, .hta, .cmd, .scr)
 * using FltGetFileNameInformation and generates SENTINEL_FILE_EVENT.
 */

#include "../inc/driver.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, BludPreCreate)
#endif

/* ============================================================================
 * BludPreCreate - Pre-operation callback for IRP_MJ_CREATE
 * ============================================================================ */
FLT_PREOP_CALLBACK_STATUS
BludPreCreate(
    _Inout_ PFLT_CALLBACK_DATA         Data,
    _In_    PCFLT_RELATED_OBJECTS       FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION  nameInfo = NULL;
    NTSTATUS                    status;
    SENTINEL_FILE_EVENT         fileEvent;
    BOOLEAN                     isSuspicious;
    ULONG                       createDisposition;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    /*
     * Skip kernel-mode requestors and paging I/O to reduce noise.
     */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * We only care about creates that might write new files
     * (FILE_CREATE, FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF,
     *  FILE_OPEN_IF) or explicit opens to suspicious file types.
     */
    createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

    /*
     * Get the file name information.
     */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
        );
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * Check if the extension is suspicious.
     */
    if (nameInfo->Extension.Length == 0) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    isSuspicious = BludCompareExtension(&nameInfo->Extension,
                                         BLUD_SUSPICIOUS_EXTENSIONS);

    if (!isSuspicious) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * Build the file event.
     */
    RtlZeroMemory(&fileEvent, sizeof(fileEvent));
    BludFillEventHeader(&fileEvent.Header, EVENT_FILE_CREATE, sizeof(fileEvent));

    fileEvent.DesiredAccess      = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    fileEvent.CreateDisposition  = createDisposition;
    fileEvent.IsSuspiciousExtension = TRUE;

    /* Copy extension */
    if (nameInfo->Extension.Length > 0) {
        USHORT copyLen = nameInfo->Extension.Length;
        if (copyLen > (SENTINEL_MAX_EXTENSION - 1) * sizeof(WCHAR)) {
            copyLen = (SENTINEL_MAX_EXTENSION - 1) * sizeof(WCHAR);
        }
        RtlCopyMemory(fileEvent.Extension,
                       nameInfo->Extension.Buffer,
                       copyLen);
    }

    /* Copy full file name */
    if (nameInfo->Name.Length > 0) {
        USHORT copyLen = nameInfo->Name.Length;
        if (copyLen > (SENTINEL_MAX_PATH - 1) * sizeof(WCHAR)) {
            copyLen = (SENTINEL_MAX_PATH - 1) * sizeof(WCHAR);
        }
        RtlCopyMemory(fileEvent.FileName,
                       nameInfo->Name.Buffer,
                       copyLen);
    }

    FltReleaseFileNameInformation(nameInfo);

    /*
     * Enqueue the event for the agent.
     */
    BludEnqueueEvent(&g_Globals.EventQueue, &fileEvent, sizeof(fileEvent));

    /*
     * We do not block the operation -- the agent decides on response actions.
     */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
