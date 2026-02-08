/*
 * BludEDR - registry_monitor.c
 * CmRegisterCallbackEx callback.
 * Monitors RegNtPreSetValueKey for Run keys, services, scheduled tasks
 * persistence paths. Sends SENTINEL_REGISTRY_EVENT via the event queue.
 */

#include "../inc/driver.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, BludRegistryCallback)
#endif

/* ============================================================================
 * Persistence path patterns to monitor
 * ============================================================================ */
static const PCWSTR g_PersistencePaths[] = {
    /* Standard Run keys */
    L"\\CurrentVersion\\Run",
    L"\\CurrentVersion\\RunOnce",
    L"\\CurrentVersion\\RunOnceEx",
    L"\\CurrentVersion\\RunServices",
    L"\\CurrentVersion\\RunServicesOnce",

    /* Startup approved */
    L"\\CurrentVersion\\Explorer\\StartupApproved",

    /* Services */
    L"\\CurrentControlSet\\Services",

    /* Scheduled tasks */
    L"\\Schedule\\TaskCache",

    /* Winlogon (userinit, shell, notify) */
    L"\\CurrentVersion\\Winlogon",

    /* Image File Execution Options (debugger persistence) */
    L"\\CurrentVersion\\Image File Execution Options",

    /* AppInit_DLLs */
    L"\\CurrentVersion\\Windows",

    /* Shell extensions */
    L"\\CurrentVersion\\ShellServiceObjectDelayLoad",

    /* COM objects (can be abused for persistence) */
    L"\\Classes\\CLSID",

    /* Boot Execute */
    L"\\Session Manager",

    /* WMI persistence */
    L"\\CurrentVersion\\WMI\\Autologger",

    /* LSA providers */
    L"\\CurrentControlSet\\Control\\Lsa",

    /* Security providers */
    L"\\CurrentControlSet\\Control\\SecurityProviders",

    /* Print monitors */
    L"\\CurrentControlSet\\Control\\Print\\Monitors",

    /* Winsock providers */
    L"\\CurrentControlSet\\Services\\WinSock2",

    /* Explorer browser helper objects */
    L"\\Explorer\\Browser Helper Objects",

    NULL  /* Sentinel */
};

/* ============================================================================
 * Local helpers
 * ============================================================================ */

/*
 * Check if a registry key path matches any of the known persistence locations.
 */
static BOOLEAN
BludpIsPersistenceKey(
    _In_ PCUNICODE_STRING KeyName
    )
{
    const PCWSTR *pattern;

    if (KeyName == NULL || KeyName->Buffer == NULL || KeyName->Length == 0) {
        return FALSE;
    }

    for (pattern = g_PersistencePaths; *pattern != NULL; pattern++) {
        UNICODE_STRING patternString;
        RtlInitUnicodeString(&patternString, *pattern);

        /*
         * Use a substring search: check if the persistence path fragment
         * appears anywhere in the key name. This handles fully-qualified
         * registry paths like \REGISTRY\MACHINE\SOFTWARE\Microsoft\...
         */
        if (KeyName->Length >= patternString.Length) {
            USHORT maxOffset = (KeyName->Length - patternString.Length) / sizeof(WCHAR);
            for (USHORT i = 0; i <= maxOffset; i++) {
                UNICODE_STRING sub;
                sub.Buffer = KeyName->Buffer + i;
                sub.Length = patternString.Length;
                sub.MaximumLength = patternString.Length;

                if (RtlEqualUnicodeString(&sub, &patternString, TRUE)) {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

/*
 * Retrieve the full registry key name from a registry object.
 */
static NTSTATUS
BludpGetObjectName(
    _In_  PVOID            Object,
    _Out_ PUNICODE_STRING  Name,
    _Out_ PVOID            *FreeBuffer
    )
{
    NTSTATUS status;
    ULONG    returnLength = 0;
    POBJECT_NAME_INFORMATION nameInfo = NULL;

    *FreeBuffer = NULL;
    RtlInitUnicodeString(Name, NULL);

    /* First call to determine size */
    status = ObQueryNameString(Object, NULL, 0, &returnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) {
        return status;
    }

    if (returnLength == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(
        POOL_FLAG_PAGED, returnLength, BLUD_POOL_TAG);
    if (nameInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ObQueryNameString(Object, nameInfo, returnLength, &returnLength);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(nameInfo, BLUD_POOL_TAG);
        return status;
    }

    *Name = nameInfo->Name;
    *FreeBuffer = nameInfo;
    return STATUS_SUCCESS;
}

/* ============================================================================
 * BludRegistryCallback
 * ============================================================================ */
NTSTATUS
BludRegistryCallback(
    _In_ PVOID  CallbackContext,
    _In_ PVOID  Argument1,
    _In_ PVOID  Argument2
    )
{
    REG_NOTIFY_CLASS        notifyClass;
    PREG_SET_VALUE_KEY_INFORMATION setValueInfo;
    UNICODE_STRING          keyName;
    PVOID                   freeBuffer = NULL;
    SENTINEL_REGISTRY_EVENT regEvent;
    NTSTATUS                status;
    BOOLEAN                 isPersistence;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(CallbackContext);

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    /*
     * We focus on RegNtPreSetValueKey as the primary persistence detection point.
     * Registry key creation (RegNtPreCreateKeyEx) can also be monitored for
     * completeness, but value setting is where the actual persistence payload
     * is written.
     */
    if (notifyClass != RegNtPreSetValueKey) {
        return STATUS_SUCCESS;
    }

    setValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
    if (setValueInfo == NULL || setValueInfo->Object == NULL) {
        return STATUS_SUCCESS;
    }

    /* Get the full key path */
    status = BludpGetObjectName(setValueInfo->Object, &keyName, &freeBuffer);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }

    /* Check if this is a persistence-relevant key */
    isPersistence = BludpIsPersistenceKey(&keyName);

    if (!isPersistence) {
        if (freeBuffer != NULL) {
            ExFreePoolWithTag(freeBuffer, BLUD_POOL_TAG);
        }
        return STATUS_SUCCESS;
    }

    /* Build registry event */
    RtlZeroMemory(&regEvent, sizeof(regEvent));
    BludFillEventHeader(&regEvent.Header, EVENT_REGISTRY_SET_VALUE, sizeof(regEvent));

    regEvent.Operation        = (ULONG)notifyClass;
    regEvent.IsPersistenceKey = TRUE;

    /* Copy key name */
    {
        USHORT copyLen = keyName.Length;
        if (copyLen > (SENTINEL_MAX_REGKEY - 1) * sizeof(WCHAR)) {
            copyLen = (SENTINEL_MAX_REGKEY - 1) * sizeof(WCHAR);
        }
        RtlCopyMemory(regEvent.KeyName, keyName.Buffer, copyLen);
    }

    /* Copy value name */
    if (setValueInfo->ValueName != NULL &&
        setValueInfo->ValueName->Buffer != NULL &&
        setValueInfo->ValueName->Length > 0) {
        USHORT copyLen = setValueInfo->ValueName->Length;
        if (copyLen > (SENTINEL_MAX_REGVALUE - 1) * sizeof(WCHAR)) {
            copyLen = (SENTINEL_MAX_REGVALUE - 1) * sizeof(WCHAR);
        }
        RtlCopyMemory(regEvent.ValueName,
                       setValueInfo->ValueName->Buffer,
                       copyLen);
    }

    /* Copy value data */
    if (setValueInfo->Data != NULL && setValueInfo->DataSize > 0) {
        ULONG copySize = setValueInfo->DataSize;
        if (copySize > SENTINEL_MAX_REGDATA) {
            copySize = SENTINEL_MAX_REGDATA;
        }
        RtlCopyMemory(regEvent.Data, setValueInfo->Data, copySize);
        regEvent.DataSize = copySize;
    }

    regEvent.DataType = setValueInfo->Type;

    if (freeBuffer != NULL) {
        ExFreePoolWithTag(freeBuffer, BLUD_POOL_TAG);
    }

    /* Enqueue the event */
    BludEnqueueEvent(&g_Globals.EventQueue, &regEvent, sizeof(regEvent));

    return STATUS_SUCCESS;
}
