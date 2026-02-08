/*
 * BludEDR - etw_consumer.cpp
 * ETW real-time consumer for kernel and .NET runtime events
 */

#include "../inc/etw_consumer.h"
#include <tdh.h>
#include <cstring>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace blud {

/* Provider GUIDs */
/* Microsoft-Windows-Kernel-Process */
static const GUID GUID_KernelProcess = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 }
};

/* Microsoft-Windows-DotNETRuntime */
static const GUID GUID_DotNetRuntime = {
    0xE13C0D23, 0xCCBC, 0x4E12,
    { 0x93, 0x1B, 0xD9, 0xCC, 0x2E, 0xEE, 0x27, 0xE4 }
};

/* Microsoft-Windows-Threat-Intelligence (requires PPL) */
static const GUID GUID_ThreatIntel = {
    0xF4E1897C, 0xBB5D, 0x5668,
    { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 }
};

EtwConsumer* EtwConsumer::s_instance = nullptr;

EtwConsumer::EtwConsumer() {
    m_sessionName = L"BludEDR_ETW_Session";
}

EtwConsumer::~EtwConsumer() {
    Shutdown();
}

bool EtwConsumer::Initialize() {
    s_instance = this;
    m_running = true;

    if (!StartSession()) {
        return false;
    }

    /* Enable providers */
    EnableProvider(GUID_KernelProcess, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF);
    EnableProvider(GUID_DotNetRuntime, TRACE_LEVEL_INFORMATION,
                   0x8098  /* AssemblyLoader | JitKeyword | LoaderKeyword */);

    /* Try Threat Intelligence - will fail without PPL, that's OK */
    EnableProvider(GUID_ThreatIntel, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF);

    /* Start consumer thread */
    m_consumerThread = std::thread(&EtwConsumer::ConsumerThreadProc, this);

    return true;
}

void EtwConsumer::Shutdown() {
    m_running = false;
    StopSession();

    if (m_consumerThread.joinable()) {
        m_consumerThread.join();
    }

    s_instance = nullptr;
}

bool EtwConsumer::StartSession() {
    /* Calculate properties buffer size */
    SIZE_T sessionNameSize = (m_sessionName.size() + 1) * sizeof(WCHAR);
    SIZE_T bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sessionNameSize;

    std::vector<BYTE> buffer(bufferSize, 0);
    auto* props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());

    props->Wnode.BufferSize = (ULONG)bufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; /* QPC clock */
    props->BufferSize = 1024;       /* 1MB buffer */
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 16;
    props->FlushTimer = 1;          /* 1 second flush */
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    /* Stop any existing session with this name */
    ULONG status = ControlTraceW(0, m_sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);

    /* Reset and start fresh */
    memset(buffer.data(), 0, bufferSize);
    props->Wnode.BufferSize = (ULONG)bufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->BufferSize = 1024;
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 16;
    props->FlushTimer = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    status = StartTraceW(&m_sessionHandle, m_sessionName.c_str(), props);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        return false;
    }

    return true;
}

bool EtwConsumer::EnableProvider(const GUID& providerId, UCHAR level, ULONGLONG matchAnyKeyword) {
    ULONG status = EnableTraceEx2(
        m_sessionHandle,
        &providerId,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        level,
        matchAnyKeyword,
        0,              /* MatchAllKeyword */
        0,              /* Timeout */
        nullptr         /* EnableParameters */
    );

    return (status == ERROR_SUCCESS);
}

void EtwConsumer::StopSession() {
    if (m_consumerHandle) {
        CloseTrace(m_consumerHandle);
        m_consumerHandle = 0;
    }

    if (m_sessionHandle) {
        SIZE_T sessionNameSize = (m_sessionName.size() + 1) * sizeof(WCHAR);
        SIZE_T bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sessionNameSize;
        std::vector<BYTE> buffer(bufferSize, 0);
        auto* props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());

        props->Wnode.BufferSize = (ULONG)bufferSize;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ControlTraceW(m_sessionHandle, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = 0;
    }
}

void EtwConsumer::ConsumerThreadProc() {
    EVENT_TRACE_LOGFILEW trace = {};
    trace.LoggerName = const_cast<LPWSTR>(m_sessionName.c_str());
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = EventRecordCallback;

    m_consumerHandle = OpenTraceW(&trace);
    if (m_consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        return;
    }

    /* ProcessTrace blocks until session is stopped or CloseTrace is called */
    ProcessTrace(&m_consumerHandle, 1, nullptr, nullptr);
}

void WINAPI EtwConsumer::EventRecordCallback(PEVENT_RECORD pEventRecord) {
    if (s_instance && s_instance->m_running) {
        s_instance->HandleEvent(pEventRecord);
    }
}

void EtwConsumer::HandleEvent(PEVENT_RECORD pEventRecord) {
    if (!pEventRecord) return;

    m_totalEvents++;

    EtwEvent evt;
    evt.ProviderId = pEventRecord->EventHeader.ProviderId;
    evt.EventId = pEventRecord->EventHeader.EventDescriptor.Id;
    evt.Opcode = pEventRecord->EventHeader.EventDescriptor.Opcode;
    evt.ProcessId = pEventRecord->EventHeader.ProcessId;
    evt.ThreadId = pEventRecord->EventHeader.ThreadId;
    evt.Timestamp = pEventRecord->EventHeader.TimeStamp.QuadPart;

    if (pEventRecord->UserData && pEventRecord->UserDataLength > 0) {
        evt.UserData.assign(
            (BYTE*)pEventRecord->UserData,
            (BYTE*)pEventRecord->UserData + pEventRecord->UserDataLength
        );
    }

    /* Store in per-process buffer */
    {
        std::lock_guard<std::mutex> lock(m_bufferMutex);
        m_processBuffers[evt.ProcessId].Push(evt);
    }

    /* Notify callback */
    if (m_callback) {
        m_callback(evt);
    }
}

void EtwConsumer::SetCallback(EtwCallback cb) {
    m_callback = std::move(cb);
}

const ProcessEtwBuffer* EtwConsumer::GetProcessBuffer(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_bufferMutex);
    auto it = m_processBuffers.find(pid);
    if (it != m_processBuffers.end()) {
        return &it->second;
    }
    return nullptr;
}

} // namespace blud
