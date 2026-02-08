/*
 * BludEDR - service_controller.h
 * Windows Service lifecycle management
 */

#pragma once
#include "../inc/agent.h"

namespace blud {

class ServiceController {
public:
    ServiceController();
    ~ServiceController();

    /* Register and run the service dispatcher */
    bool RunAsService();

    /* Run in console mode (for debugging) */
    bool RunAsConsole();

    /* Trigger shutdown from any thread */
    void RequestShutdown();

    /* Wait for the shutdown event to be signalled */
    void WaitForShutdown();

    /* Get the shutdown event handle */
    HANDLE GetShutdownEvent() const { return m_ShutdownEvent; }

    /* Singleton access */
    static ServiceController& Instance();

private:
    /* Service control handler callback */
    static DWORD WINAPI ServiceCtrlHandlerEx(
        DWORD dwControl, DWORD dwEventType,
        LPVOID lpEventData, LPVOID lpContext);

    /* ServiceMain entry point */
    static VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv);

    /* Update service status */
    void SetServiceState(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0);

    /* Core initialization and run loop */
    bool InitializeComponents();
    void RunLoop();
    void ShutdownComponents();

    SERVICE_STATUS          m_ServiceStatus;
    SERVICE_STATUS_HANDLE   m_StatusHandle;
    HANDLE                  m_ShutdownEvent;

    static ServiceController* s_Instance;
};

/* Global service status accessible from ServiceMain */
extern SERVICE_STATUS g_ServiceStatus;

} /* namespace blud */
