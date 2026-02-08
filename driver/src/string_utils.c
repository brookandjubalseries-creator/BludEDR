/*
 * BludEDR - string_utils.c
 * Safe UNICODE_STRING helpers:
 *   BludAllocateUnicodeString
 *   BludFreeUnicodeString
 *   BludCopyUnicodeString
 *   BludCompareExtension
 */

#include "../inc/driver.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, BludAllocateUnicodeString)
#pragma alloc_text(PAGE, BludFreeUnicodeString)
#pragma alloc_text(PAGE, BludCopyUnicodeString)
#pragma alloc_text(PAGE, BludCompareExtension)
#endif

/* ============================================================================
 * BludAllocateUnicodeString
 *
 * Allocates a buffer for a UNICODE_STRING from nonpaged pool.
 * The Length is set to 0; MaximumLength is set to the requested size.
 * ============================================================================ */
NTSTATUS
BludAllocateUnicodeString(
    _Out_ PUNICODE_STRING String,
    _In_  USHORT          MaximumLength
    )
{
    PAGED_CODE();

    String->Buffer        = NULL;
    String->Length         = 0;
    String->MaximumLength = 0;

    if (MaximumLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    String->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        MaximumLength,
        BLUD_POOL_TAG
        );

    if (String->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(String->Buffer, MaximumLength);
    String->MaximumLength = MaximumLength;
    String->Length         = 0;

    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludFreeUnicodeString
 *
 * Frees a UNICODE_STRING buffer previously allocated by BludAllocateUnicodeString.
 * ============================================================================ */
VOID
BludFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    )
{
    PAGED_CODE();

    if (String->Buffer != NULL) {
        ExFreePoolWithTag(String->Buffer, BLUD_POOL_TAG);
        String->Buffer = NULL;
    }

    String->Length         = 0;
    String->MaximumLength = 0;
}

/* ============================================================================
 * BludCopyUnicodeString
 *
 * Allocates a new buffer for Destination and copies Source into it.
 * If Destination already has a buffer, it is freed first.
 * ============================================================================ */
NTSTATUS
BludCopyUnicodeString(
    _Out_ PUNICODE_STRING Destination,
    _In_  PCUNICODE_STRING Source
    )
{
    NTSTATUS status;
    USHORT   allocSize;

    PAGED_CODE();

    /* Free any existing buffer */
    if (Destination->Buffer != NULL) {
        BludFreeUnicodeString(Destination);
    }

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        Destination->Buffer        = NULL;
        Destination->Length         = 0;
        Destination->MaximumLength = 0;
        return STATUS_SUCCESS;
    }

    /* Allocate enough space for the string plus a null terminator */
    allocSize = Source->Length + sizeof(WCHAR);

    status = BludAllocateUnicodeString(Destination, allocSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(Destination->Buffer, Source->Buffer, Source->Length);
    Destination->Length = Source->Length;

    /* Null-terminate for safety (buffer is zero-initialized, but be explicit) */
    Destination->Buffer[Source->Length / sizeof(WCHAR)] = L'\0';

    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludCompareExtension
 *
 * Checks whether the file extension from FileName matches any extension in
 * the provided ExtensionList. The ExtensionList is a dot-separated concatenation
 * of extensions, e.g. L".bat.vbs.ps1.js.wsf.hta.cmd.scr".
 *
 * FileName can be either a full file name or just the extension component
 * (as returned by FltParseFileNameInformation in the Extension field).
 *
 * The comparison is case-insensitive.
 *
 * Returns TRUE if a match is found.
 * ============================================================================ */
BOOLEAN
BludCompareExtension(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCWSTR           ExtensionList
    )
{
    UNICODE_STRING extension = { 0, 0, NULL };
    UNICODE_STRING candidate = { 0, 0, NULL };
    PCWSTR         listPtr;
    PCWSTR         extStart;

    PAGED_CODE();

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    if (ExtensionList == NULL) {
        return FALSE;
    }

    /*
     * Extract the extension from FileName.
     * If the FileName already is just the extension (no dot), wrap it.
     * If it contains a dot, find the last one.
     */
    {
        USHORT  charCount = FileName->Length / sizeof(WCHAR);
        LONG    i;
        BOOLEAN foundDot = FALSE;

        for (i = (LONG)charCount - 1; i >= 0; i--) {
            if (FileName->Buffer[i] == L'.') {
                /* Extension starts after the dot */
                extension.Buffer = &FileName->Buffer[i + 1];
                extension.Length = (USHORT)((charCount - i - 1) * sizeof(WCHAR));
                extension.MaximumLength = extension.Length;
                foundDot = TRUE;
                break;
            }
            if (FileName->Buffer[i] == L'\\' || FileName->Buffer[i] == L'/') {
                break;
            }
        }

        if (!foundDot) {
            /*
             * No dot found -- treat the entire FileName as the extension.
             * This handles the case where FltParseFileNameInformation returns
             * just "bat" without a leading dot.
             */
            extension = *FileName;
        }
    }

    if (extension.Length == 0) {
        return FALSE;
    }

    /*
     * Walk the extension list. Each extension starts with a dot.
     * For example: ".bat.vbs.ps1"
     * We extract each segment between dots and compare.
     */
    listPtr = ExtensionList;

    while (*listPtr != L'\0') {
        /* Skip the leading dot */
        if (*listPtr == L'.') {
            listPtr++;
        }

        /* Find the end of this extension (next dot or end of string) */
        extStart = listPtr;
        while (*listPtr != L'\0' && *listPtr != L'.') {
            listPtr++;
        }

        if (listPtr > extStart) {
            candidate.Buffer = (PWCH)extStart;
            candidate.Length = (USHORT)((listPtr - extStart) * sizeof(WCHAR));
            candidate.MaximumLength = candidate.Length;

            if (RtlEqualUnicodeString(&extension, &candidate, TRUE)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}
