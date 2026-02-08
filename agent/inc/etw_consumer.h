/*
 * BludEDR - etw_consumer.h
 * ETW (Event Tracing for Windows) real-time consumer
 */

#pragma once

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <string>
#include <functional>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <deque>

namespace blud {

/* ETW event callback */
struct EtwEvent {
    GUID        ProviderId;
    USHORT      EventId;
    UCHAR       Opcode;
    DWORD       ProcessId;
    DWORD       ThreadId;
    LONGLONG    Timestamp;
    std::vector<BYTE> UserData;
};

using EtwCallback = std::function<void(const EtwEvent&)>;

/* Per-process ETW event ring buffer */
struct ProcessEtwBuffer {
    std::deque<EtwEvent>    Events;
    static constexpr size_t MAX_EVENTS = 1024;

    void Push(const EtwEvent& evt) {
        if (Events.size() >= MAX_EVENTS) Events.pop_front();
        Events.push_back(evt);
    }
};

class EtwConsumer {
public:
    EtwConsumer();
    ~EtwConsumer();

    bool Initialize();
    void Shutdown();

    /* Register callback for ETW events */
    void SetCallback(EtwCallback cb);

    /* Get per-process event buffer */
    const ProcessEtwBuffer* GetProcessBuffer(DWORD pid);

    /* Stats */
    ULONGLONG GetTotalEventsProcessed() const { return m_totalEvents; }

private:
    /* Session management */
    bool StartSession();
    bool EnableProvider(const GUID& providerId, UCHAR level, ULONGLONG matchAnyKeyword);
    void StopSession();

    /* Consumer thread */
    void ConsumerThreadProc();

    /* Static callback for ETW */
    static void WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord);
    void HandleEvent(PEVENT_RECORD pEventRecord);

    /* Session properties */
    TRACEHANDLE     m_sessionHandle = 0;
    TRACEHANDLE     m_consumerHandle = 0;
    std::wstring    m_sessionName;

    /* Threading */
    std::thread     m_consumerThread;
    std::atomic<bool> m_running{false};

    /* Callback */
    EtwCallback     m_callback;

    /* Per-process buffers */
    std::unordered_map<DWORD, ProcessEtwBuffer> m_processBuffers;
    std::mutex      m_bufferMutex;

    /* Stats */
    std::atomic<ULONGLONG> m_totalEvents{0};

    /* Static instance for callback routing */
    static EtwConsumer* s_instance;
};

} // namespace blud
