/*
 * BludEDR - hook_comm.cpp
 * Named pipe client for communicating hook events to the BludEDR agent.
 *
 * Connects to \\.\pipe\BludHook_{PID}
 * Thread-safe via CRITICAL_SECTION.
 * Buffers events in a ring buffer (256 entries) when pipe is disconnected.
 */

#include "hook_comm.h"

/* ============================================================================
 * Static state
 * ============================================================================ */

static HANDLE               g_hPipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION     g_commLock;
static BOOL                 g_commInit = FALSE;
static DWORD                g_targetPid = 0;
static WCHAR                g_pipeName[128] = {};

/* Ring buffer for events when pipe is disconnected */
struct RingBufferEntry {
    BOOL                    inUse;
    SENTINEL_MEMORY_EVENT   event;
};

static RingBufferEntry      g_ringBuffer[HOOK_COMM_RING_BUFFER_SIZE] = {};
static ULONG                g_ringWriteIndex = 0;
static ULONG                g_ringReadIndex  = 0;
static ULONG                g_ringCount      = 0;

/* ============================================================================
 * Internal: try to connect to the pipe
 * ============================================================================ */
static BOOL TryConnect()
{
    if (g_hPipe != INVALID_HANDLE_VALUE)
        return TRUE;

    g_hPipe = CreateFileW(
        g_pipeName,
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (g_hPipe == INVALID_HANDLE_VALUE)
        return FALSE;

    /* Set pipe to message mode */
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(g_hPipe, &mode, nullptr, nullptr);

    return TRUE;
}

/* ============================================================================
 * Internal: disconnect from pipe
 * ============================================================================ */
static void Disconnect()
{
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
}

/* ============================================================================
 * Internal: write a single event to the pipe (assumes lock is held)
 * ============================================================================ */
static BOOL WriteEventToPipe(const SENTINEL_MEMORY_EVENT* pEvent)
{
    if (g_hPipe == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD bytesWritten = 0;
    BOOL result = WriteFile(
        g_hPipe,
        pEvent,
        sizeof(SENTINEL_MEMORY_EVENT),
        &bytesWritten,
        nullptr
    );

    if (!result || bytesWritten != sizeof(SENTINEL_MEMORY_EVENT)) {
        /* Pipe broken */
        Disconnect();
        return FALSE;
    }

    return TRUE;
}

/* ============================================================================
 * Internal: flush buffered events
 * ============================================================================ */
static void FlushRingBuffer()
{
    while (g_ringCount > 0) {
        RingBufferEntry* entry = &g_ringBuffer[g_ringReadIndex];
        if (!entry->inUse) break;

        if (!WriteEventToPipe(&entry->event)) {
            /* Pipe broken again; stop flushing */
            return;
        }

        entry->inUse = FALSE;
        g_ringReadIndex = (g_ringReadIndex + 1) % HOOK_COMM_RING_BUFFER_SIZE;
        g_ringCount--;
    }
}

/* ============================================================================
 * Internal: buffer an event in the ring buffer
 * ============================================================================ */
static void BufferEvent(const SENTINEL_MEMORY_EVENT* pEvent)
{
    /* If ring buffer is full, overwrite oldest entry */
    if (g_ringCount >= HOOK_COMM_RING_BUFFER_SIZE) {
        /* Advance read pointer to drop oldest */
        g_ringBuffer[g_ringReadIndex].inUse = FALSE;
        g_ringReadIndex = (g_ringReadIndex + 1) % HOOK_COMM_RING_BUFFER_SIZE;
        g_ringCount--;
    }

    RingBufferEntry* entry = &g_ringBuffer[g_ringWriteIndex];
    memcpy(&entry->event, pEvent, sizeof(SENTINEL_MEMORY_EVENT));
    entry->inUse = TRUE;
    g_ringWriteIndex = (g_ringWriteIndex + 1) % HOOK_COMM_RING_BUFFER_SIZE;
    g_ringCount++;
}

/* ============================================================================
 * HookComm_Initialize
 * ============================================================================ */
BOOL HookComm_Initialize(DWORD pid)
{
    if (g_commInit) return TRUE;

    InitializeCriticalSection(&g_commLock);

    g_targetPid = pid;
    _snwprintf_s(g_pipeName, _countof(g_pipeName), _TRUNCATE,
                 L"%s%lu", BLUD_HOOK_PIPE_PREFIX, pid);

    /* Zero ring buffer */
    ZeroMemory(g_ringBuffer, sizeof(g_ringBuffer));
    g_ringWriteIndex = 0;
    g_ringReadIndex = 0;
    g_ringCount = 0;

    g_commInit = TRUE;

    /* Try initial connection (non-fatal if fails) */
    EnterCriticalSection(&g_commLock);
    TryConnect();
    LeaveCriticalSection(&g_commLock);

    return TRUE;
}

/* ============================================================================
 * HookComm_Shutdown
 * ============================================================================ */
void HookComm_Shutdown()
{
    if (!g_commInit) return;

    EnterCriticalSection(&g_commLock);
    Disconnect();
    ZeroMemory(g_ringBuffer, sizeof(g_ringBuffer));
    g_ringCount = 0;
    LeaveCriticalSection(&g_commLock);

    DeleteCriticalSection(&g_commLock);
    g_commInit = FALSE;
}

/* ============================================================================
 * HookComm_SendEvent
 * Thread-safe event sender with reconnect logic and buffering.
 * ============================================================================ */
BOOL HookComm_SendEvent(const SENTINEL_MEMORY_EVENT* pEvent)
{
    if (!g_commInit || !pEvent) return FALSE;

    EnterCriticalSection(&g_commLock);

    /* Try to connect if not connected */
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        DWORD backoffMs = HOOK_COMM_BASE_BACKOFF_MS;
        for (DWORD retry = 0; retry < HOOK_COMM_MAX_RETRIES; retry++) {
            if (TryConnect()) break;
            /* Brief sleep with backoff - but don't hold the lock too long */
            LeaveCriticalSection(&g_commLock);
            Sleep(backoffMs);
            EnterCriticalSection(&g_commLock);
            backoffMs = min(backoffMs * 2, 1000);
        }
    }

    /* If connected, flush any buffered events first */
    if (g_hPipe != INVALID_HANDLE_VALUE && g_ringCount > 0) {
        FlushRingBuffer();
    }

    /* Try to write the current event */
    BOOL sent = FALSE;
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        sent = WriteEventToPipe(pEvent);
    }

    /* If send failed, buffer the event */
    if (!sent) {
        BufferEvent(pEvent);
    }

    LeaveCriticalSection(&g_commLock);
    return sent;
}
