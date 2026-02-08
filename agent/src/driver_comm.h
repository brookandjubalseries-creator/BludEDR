/*
 * BludEDR - driver_comm.h
 * Communication with the minifilter driver via FilterCommunicationPort
 */

#pragma once
#include "../inc/agent.h"

namespace blud {

class DriverComm {
public:
    DriverComm();
    ~DriverComm();

    /* Connect to the minifilter communication port */
    bool Connect();

    /* Disconnect and clean up */
    void Disconnect();

    /* Start receiver threads that call FilterGetMessage in a loop */
    void StartReceiverThreads();

    /* Send a command from agent to driver */
    bool SendCommand(const SENTINEL_COMMAND& cmd, SENTINEL_REPLY* reply = nullptr);

    /* Check if connected */
    bool IsConnected() const { return m_Connected.load(std::memory_order_acquire); }

    /* Singleton */
    static DriverComm& Instance();

private:
    /* Receiver thread procedure */
    static DWORD WINAPI ReceiverThreadProc(LPVOID param);
    void ReceiverLoop();

    HANDLE              m_Port;
    std::atomic<bool>   m_Connected;
    std::atomic<bool>   m_Running;
    HANDLE              m_ReceiverThreads[BLUD_RECEIVER_THREADS];

    /* Stats */
    std::atomic<uint64_t>   m_MessagesReceived;
    std::atomic<uint64_t>   m_CommandsSent;

    static DriverComm* s_Instance;
};

} /* namespace blud */
