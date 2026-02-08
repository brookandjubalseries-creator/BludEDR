/*
 * BludEDR - service_controller.cpp
 * Windows Service lifecycle: register, start, stop, pause, interrogate
 */

#include "service_controller.h"
#include "driver_comm.h"
#include "event_dispatcher.h"
#include "process_tree.h"
#include "ioc_scoring.h"
#include "detection_engine.h"
#include "lolbas_detector.h"
#include "alert_manager.h"
#include "config_manager.h"
#include "logger.h"
#include "console_dashboard.h"

namespace blud {

/* Globals */
SERVICE_STATUS g_ServiceStatus = {};
ServiceController* ServiceController::s_Instance = nullptr;

ServiceController::ServiceController()
    : m_StatusHandle(nullptr)
    , m_ShutdownEvent(nullptr)
{
    ZeroMemory(&m_ServiceStatus, sizeof(m_ServiceStatus));
    m_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    m_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;

    m_ShutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    s_Instance = this;
}

ServiceController::~ServiceController()
{
    BLUD_SAFE_CLOSE_HANDLE(m_ShutdownEvent);
    s_Instance = nullptr;
}

ServiceController& ServiceController::Instance()
{
    return *s_Instance;
}

/* ============================================================================
 * Run as Windows Service
 * ============================================================================ */
bool ServiceController::RunAsService()
{
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(BLUD_SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            /* Not running under SCM -- caller should fall back to console mode */
            return false;
        }
        return false;
    }
    return true;
}

/* ============================================================================
 * Run as console application (--console)
 * ============================================================================ */
bool ServiceController::RunAsConsole()
{
    LOG_INFO("Service", "Running in console mode");

    if (!InitializeComponents()) {
        LOG_ERROR("Service", "Failed to initialize components");
        return false;
    }

    /* Set up console ctrl handler for Ctrl+C */
    SetConsoleCtrlHandler([](DWORD ctrlType) -> BOOL {
        if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
            if (s_Instance) {
                s_Instance->RequestShutdown();
            }
            return TRUE;
        }
        return FALSE;
    }, TRUE);

    RunLoop();
    ShutdownComponents();
    return true;
}

/* ============================================================================
 * ServiceMain - called by SCM
 * ============================================================================ */
VOID WINAPI ServiceController::ServiceMain(DWORD argc, LPWSTR* argv)
{
    (void)argc;
    (void)argv;

    if (!s_Instance) return;

    s_Instance->m_StatusHandle = RegisterServiceCtrlHandlerExW(
        BLUD_SERVICE_NAME, ServiceCtrlHandlerEx, s_Instance);

    if (!s_Instance->m_StatusHandle) {
        return;
    }

    s_Instance->SetServiceState(SERVICE_START_PENDING, NO_ERROR, 5000);

    if (!s_Instance->InitializeComponents()) {
        s_Instance->SetServiceState(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    s_Instance->SetServiceState(SERVICE_RUNNING);
    LOG_INFO("Service", "BludEDR service started successfully");

    s_Instance->RunLoop();
    s_Instance->ShutdownComponents();

    s_Instance->SetServiceState(SERVICE_STOPPED);
    LOG_INFO("Service", "BludEDR service stopped");
}

/* ============================================================================
 * Service Control Handler
 * ============================================================================ */
DWORD WINAPI ServiceController::ServiceCtrlHandlerEx(
    DWORD dwControl, DWORD dwEventType,
    LPVOID lpEventData, LPVOID lpContext)
{
    (void)dwEventType;
    (void)lpEventData;

    auto* self = static_cast<ServiceController*>(lpContext);
    if (!self) return ERROR_CALL_NOT_IMPLEMENTED;

    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        LOG_INFO("Service", "Stop/Shutdown control received");
        self->SetServiceState(SERVICE_STOP_PENDING, NO_ERROR, 10000);
        self->RequestShutdown();
        return NO_ERROR;

    case SERVICE_CONTROL_PAUSE:
        LOG_INFO("Service", "Pause control received");
        self->SetServiceState(SERVICE_PAUSED);
        return NO_ERROR;

    case SERVICE_CONTROL_CONTINUE:
        LOG_INFO("Service", "Continue control received");
        self->SetServiceState(SERVICE_RUNNING);
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        /* Just return current status */
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/* ============================================================================
 * Update service status
 * ============================================================================ */
void ServiceController::SetServiceState(DWORD state, DWORD exitCode, DWORD waitHint)
{
    static DWORD checkPoint = 1;

    m_ServiceStatus.dwCurrentState = state;
    m_ServiceStatus.dwWin32ExitCode = exitCode;
    m_ServiceStatus.dwWaitHint = waitHint;

    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        m_ServiceStatus.dwControlsAccepted = 0;
        m_ServiceStatus.dwCheckPoint = checkPoint++;
    } else {
        m_ServiceStatus.dwControlsAccepted =
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
        m_ServiceStatus.dwCheckPoint = 0;
    }

    g_ServiceStatus = m_ServiceStatus;

    if (m_StatusHandle) {
        SetServiceStatus(m_StatusHandle, &m_ServiceStatus);
    }
}

/* ============================================================================
 * Component initialization
 * ============================================================================ */
bool ServiceController::InitializeComponents()
{
    try {
        /* Config first, so other components can read settings */
        ConfigManager::Instance().Load(BLUD_CONFIG_FILE);

        /* Logger */
        Logger::Instance().Initialize(
            ConfigManager::Instance().GetLogPath(),
            ConfigManager::Instance().GetLogLevel());

        LOG_INFO("Service", "Initializing BludEDR components...");

        /* Process tree */
        ProcessTree::Instance().Initialize();

        /* IoC scoring engine */
        IoCScoring::Instance().Initialize();

        /* LOLBAS detector (loads database) */
        LolbasDetector::Instance().Initialize();

        /* Detection engine (registers rules) */
        DetectionEngine::Instance().Initialize();

        /* Alert manager */
        AlertManager::Instance().Initialize();

        /* Event dispatcher */
        EventDispatcher::Instance().Initialize();

        /* Driver communication -- connect to minifilter port */
        if (!DriverComm::Instance().Connect()) {
            LOG_WARNING("Service", "Could not connect to driver port -- running in degraded mode");
            /* Not fatal: we can still receive events from pipe, etc. */
        } else {
            DriverComm::Instance().StartReceiverThreads();
        }

        LOG_INFO("Service", "All components initialized");
        return true;
    }
    catch (const std::exception& ex) {
        std::string msg = "Component init exception: ";
        msg += ex.what();
        LOG_ERROR("Service", msg);
        return false;
    }
}

/* ============================================================================
 * Main run loop - wait for shutdown
 * ============================================================================ */
void ServiceController::RunLoop()
{
    WaitForShutdown();
}

/* ============================================================================
 * Clean shutdown
 * ============================================================================ */
void ServiceController::ShutdownComponents()
{
    LOG_INFO("Service", "Shutting down components...");

    g_ShutdownRequested.store(true, std::memory_order_release);

    DriverComm::Instance().Disconnect();
    EventDispatcher::Instance().Shutdown();
    ConsoleDashboard::Instance().Stop();
    AlertManager::Instance().Shutdown();
    DetectionEngine::Instance().Shutdown();
    IoCScoring::Instance().Shutdown();
    ProcessTree::Instance().Shutdown();
    Logger::Instance().Shutdown();

    LOG_INFO("Service", "All components shut down");
}

void ServiceController::RequestShutdown()
{
    g_ShutdownRequested.store(true, std::memory_order_release);
    if (m_ShutdownEvent) {
        SetEvent(m_ShutdownEvent);
    }
}

void ServiceController::WaitForShutdown()
{
    if (m_ShutdownEvent) {
        WaitForSingleObject(m_ShutdownEvent, INFINITE);
    }
}

} /* namespace blud */
