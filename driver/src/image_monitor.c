/*
 * BludEDR - image_monitor.c
 * Image load callback (PsSetLoadImageNotifyRoutine).
 * Tracks DLL loads and sends SENTINEL_IMAGE_EVENT via the event queue.
 */

#include "../inc/driver.h"

/* ============================================================================
 * BludImageLoadNotifyRoutine
 * ============================================================================ */
VOID
BludImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING  FullImageName,
    _In_     HANDLE           ProcessId,
    _In_     PIMAGE_INFO      ImageInfo
    )
{
    SENTINEL_IMAGE_EVENT imageEvent;
    ULONG                pid;

    /*
     * Called at PASSIVE_LEVEL in the context of the thread that is loading
     * the image. ProcessId == 0 means this is a kernel-mode image load.
     */

    pid = (ULONG)(ULONG_PTR)ProcessId;

    /*
     * Skip kernel-mode image loads (drivers) to reduce noise.
     * The agent is primarily interested in usermode module loads.
     * Uncomment the following to also track kernel images.
     */
    /*
    if (pid == 0) {
        return;
    }
    */

    RtlZeroMemory(&imageEvent, sizeof(imageEvent));
    BludFillEventHeader(&imageEvent.Header, EVENT_IMAGE_LOAD, sizeof(imageEvent));

    /* Override PID with the target process that is loading the image */
    imageEvent.Header.ProcessId = pid;

    imageEvent.ImageBase    = ImageInfo->ImageBase;
    imageEvent.ImageSize    = ImageInfo->ImageSize;
    imageEvent.IsSystemImage = (pid == 0) ? TRUE : FALSE;

    /*
     * Also mark as system image if ImageInfo indicates the image
     * is from the system directory.
     */
    if (ImageInfo->SystemModeImage) {
        imageEvent.IsSystemImage = TRUE;
    }

    /* Copy image name */
    if (FullImageName != NULL && FullImageName->Buffer != NULL && FullImageName->Length > 0) {
        USHORT copyLen = FullImageName->Length;
        if (copyLen > (SENTINEL_MAX_PATH - 1) * sizeof(WCHAR)) {
            copyLen = (SENTINEL_MAX_PATH - 1) * sizeof(WCHAR);
        }
        RtlCopyMemory(imageEvent.ImageName,
                       FullImageName->Buffer,
                       copyLen);
    }

    /* Enqueue the event */
    BludEnqueueEvent(&g_Globals.EventQueue, &imageEvent, sizeof(imageEvent));
}
