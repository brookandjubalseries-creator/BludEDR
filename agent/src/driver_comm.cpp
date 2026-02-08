/*
 * BludEDR - driver_comm.cpp
 * FilterConnectCommunicationPort to \\BludCommPort with 4 receiver threads
 */

#include "driver_comm.h"
#include "event_dispatcher.h"
#include "logger.h"

#pragma comment(lib, "fltLib.lib")

namespace blud {

DriverComm* DriverComm::s_Instance = nullptr;

DriverComm::DriverComm()
    : m_Port(INVALID_HANDLE_VALUE)
    , m_Connected(false)
    , m_Running(false)
    , m_MessagesReceived(0)
    , m_CommandsSent(0)
{
    InitializeSRWLock(&m_PortLock);
    ZeroMemory(m_ReceiverThreads, sizeof(m_ReceiverThreads));
    s_Instance = this;
}

DriverComm::~DriverComm()
{
    Disconnect();
    s_Instance = nullptr;
}

DriverComm& DriverComm::Instance()
{
    static DriverComm instance;
    return instance;
}

/* ============================================================================
 * Connect to the minifilter communication port
 * ============================================================================ */
bool DriverComm::Connect()
{
    if (m_Connected.load()) return true;

    HRESULT hr = FilterConnectCommunicationPort(
        BLUD_COMM_PORT_NAME,
        0,                          /* Options */
        nullptr,                    /* Context */
        0,                          /* Context size */
        nullptr,                    /* SecurityAttributes */
        &m_Port);

    if (!BLUD_SUCCEEDED(hr)) {
        LOG_ERROR("DriverComm",
            "FilterConnectCommunicationPort failed: 0x" +
            ([&]() { std::ostringstream o; o << std::hex << hr; return o.str(); })());
        m_Port = INVALID_HANDLE_VALUE;
        return false;
    }

    m_Connected.store(true, std::memory_order_release);
    LOG_INFO("DriverComm", "Connected to minifilter port " + WideToUtf8(BLUD_COMM_PORT_NAME));
    return true;
}

/* ============================================================================
 * Disconnect
 * ============================================================================ */
void DriverComm::Disconnect()
{
    m_Running.store(false, std::memory_order_release);
    m_Connected.store(false, std::memory_order_release);

    /* Wait for receiver threads to exit */
    for (int i = 0; i < BLUD_RECEIVER_THREADS; ++i) {
        if (m_ReceiverThreads[i]) {
            /* Cancel pending I/O on this thread so FilterGetMessage returns */
            CancelSynchronousIo(m_ReceiverThreads[i]);
            WaitForSingleObject(m_ReceiverThreads[i], 5000);
            CloseHandle(m_ReceiverThreads[i]);
            m_ReceiverThreads[i] = nullptr;
        }
    }

    {
        AcquireSRWLockExclusive(&m_PortLock);
        if (m_Port != INVALID_HANDLE_VALUE) {
            CloseHandle(m_Port);
            m_Port = INVALID_HANDLE_VALUE;
        }
        ReleaseSRWLockExclusive(&m_PortLock);
    }

    LOG_INFO("DriverComm", "Disconnected from driver");
}

/* ============================================================================
 * Start receiver threads
 * ============================================================================ */
void DriverComm::StartReceiverThreads()
{
    if (!m_Connected.load()) return;

    m_Running.store(true, std::memory_order_release);

    for (int i = 0; i < BLUD_RECEIVER_THREADS; ++i) {
        m_ReceiverThreads[i] = CreateThread(
            nullptr, 0, ReceiverThreadProc, this, 0, nullptr);

        if (!m_ReceiverThreads[i]) {
            LOG_ERROR("DriverComm", "Failed to create receiver thread " + std::to_string(i));
        }
    }

    LOG_INFO("DriverComm", "Started " + std::to_string(BLUD_RECEIVER_THREADS) + " receiver threads");
}

/* ============================================================================
 * Receiver thread procedure
 * ============================================================================ */
DWORD WINAPI DriverComm::ReceiverThreadProc(LPVOID param)
{
    auto* self = static_cast<DriverComm*>(param);
    if (self) self->ReceiverLoop();
    return 0;
}

void DriverComm::ReceiverLoop()
{
    /* Allocate message buffer on the heap to avoid stack overflow */
    auto msgBuf = std::make_unique<SENTINEL_MESSAGE>();

    while (m_Running.load(std::memory_order_acquire)) {
        ZeroMemory(msgBuf.get(), sizeof(SENTINEL_MESSAGE));

        HRESULT hr = FilterGetMessage(
            m_Port,
            &msgBuf->Header,
            sizeof(SENTINEL_MESSAGE),
            nullptr);      /* Overlapped = nullptr -> synchronous */

        if (!BLUD_SUCCEEDED(hr)) {
            DWORD err = HRESULT_CODE(hr);
            if (err == ERROR_OPERATION_ABORTED || err == ERROR_INVALID_HANDLE) {
                /* Port closed or I/O cancelled -- exit gracefully */
                break;
            }
            /* Transient error -- short sleep and retry */
            Sleep(10);
            continue;
        }

        m_MessagesReceived.fetch_add(1, std::memory_order_relaxed);

        /* Dispatch the event */
        EventDispatcher::Instance().DispatchEvent(*msgBuf);
    }
}

/* ============================================================================
 * Send command to driver
 * ============================================================================ */
bool DriverComm::SendCommand(const SENTINEL_COMMAND& cmd, SENTINEL_REPLY* reply)
{
    if (!m_Connected.load(std::memory_order_acquire)) {
        LOG_WARNING("DriverComm", "SendCommand called while disconnected");
        return false;
    }

    SENTINEL_REPLY_MESSAGE replyMsg = {};
    DWORD replySize = sizeof(SENTINEL_REPLY_MESSAGE);

    AcquireSRWLockShared(&m_PortLock);
    HANDLE port = m_Port;
    if (port == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockShared(&m_PortLock);
        LOG_WARNING("DriverComm", "SendCommand: port handle is invalid");
        return false;
    }

    HRESULT hr = FilterSendMessage(
        port,
        const_cast<SENTINEL_COMMAND*>(&cmd),
        sizeof(SENTINEL_COMMAND),
        &replyMsg,
        replySize,
        &replySize);
    ReleaseSRWLockShared(&m_PortLock);

    if (!BLUD_SUCCEEDED(hr)) {
        LOG_ERROR("DriverComm",
            "FilterSendMessage failed: 0x" +
            ([&]() { std::ostringstream o; o << std::hex << hr; return o.str(); })());
        return false;
    }

    m_CommandsSent.fetch_add(1, std::memory_order_relaxed);

    if (reply) {
        *reply = replyMsg.Reply;
    }

    return true;
}

} /* namespace blud */
