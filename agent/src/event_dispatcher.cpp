/*
 * BludEDR - event_dispatcher.cpp
 * Routes events by SENTINEL_EVENT_TYPE to the appropriate subsystem handlers
 */

#include "event_dispatcher.h"
#include "process_tree.h"
#include "detection_engine.h"
#include "ioc_scoring.h"
#include "alert_manager.h"
#include "logger.h"

namespace blud {

EventDispatcher* EventDispatcher::s_Instance = nullptr;

EventDispatcher::EventDispatcher()
    : m_Running(false)
{
    s_Instance = this;
}

EventDispatcher::~EventDispatcher()
{
    s_Instance = nullptr;
}

EventDispatcher& EventDispatcher::Instance()
{
    static EventDispatcher instance;
    return instance;
}

void EventDispatcher::Initialize()
{
    m_Running.store(true, std::memory_order_release);
    LOG_INFO("EventDispatcher", "Initialized");
}

void EventDispatcher::Shutdown()
{
    m_Running.store(false, std::memory_order_release);
    LOG_INFO("EventDispatcher", "Shut down");
}

/* ============================================================================
 * Main dispatch entry point
 * ============================================================================ */
void EventDispatcher::DispatchEvent(const SENTINEL_MESSAGE& msg)
{
    if (!m_Running.load(std::memory_order_acquire)) return;

    m_Counters.totalEvents.fetch_add(1, std::memory_order_relaxed);

    SENTINEL_EVENT_TYPE eventType = msg.Event.EventHeader.Type;

    switch (eventType) {
    /* ------ Process Events ------ */
    case EVENT_PROCESS_CREATE:
    case EVENT_PROCESS_TERMINATE:
        m_Counters.processEvents.fetch_add(1, std::memory_order_relaxed);
        HandleProcessEvent(msg.Event.Process);
        break;

    /* ------ Thread Events ------ */
    case EVENT_THREAD_CREATE:
    case EVENT_THREAD_TERMINATE:
        m_Counters.threadEvents.fetch_add(1, std::memory_order_relaxed);
        HandleThreadEvent(msg.Event.Thread);
        break;

    /* ------ Image Load Events ------ */
    case EVENT_IMAGE_LOAD:
        m_Counters.imageEvents.fetch_add(1, std::memory_order_relaxed);
        HandleImageEvent(msg.Event.Image);
        break;

    /* ------ File Events ------ */
    case EVENT_FILE_CREATE:
    case EVENT_FILE_WRITE:
    case EVENT_FILE_DELETE:
    case EVENT_FILE_RENAME:
        m_Counters.fileEvents.fetch_add(1, std::memory_order_relaxed);
        HandleFileEvent(msg.Event.File);
        break;

    /* ------ Registry Events ------ */
    case EVENT_REGISTRY_SET_VALUE:
    case EVENT_REGISTRY_CREATE_KEY:
    case EVENT_REGISTRY_DELETE_VALUE:
    case EVENT_REGISTRY_DELETE_KEY:
        m_Counters.registryEvents.fetch_add(1, std::memory_order_relaxed);
        HandleRegistryEvent(msg.Event.Registry);
        break;

    /* ------ Object/Handle Events ------ */
    case EVENT_OBJECT_HANDLE_CREATE:
    case EVENT_OBJECT_HANDLE_DUP:
        m_Counters.objectEvents.fetch_add(1, std::memory_order_relaxed);
        HandleObjectEvent(msg.Event.Object);
        break;

    /* ------ Memory Events (from hook DLL) ------ */
    case EVENT_MEMORY_ALLOC:
    case EVENT_MEMORY_PROTECT:
    case EVENT_MEMORY_WRITE:
    case EVENT_MEMORY_MAP:
    case EVENT_REMOTE_THREAD:
    case EVENT_APC_QUEUE:
    case EVENT_AMSI_BYPASS:
    case EVENT_ETW_BYPASS:
    case EVENT_VEH_INSTALL:
    case EVENT_SLEEP_OBFUSCATION:
    case EVENT_TOKEN_FOUND:
        m_Counters.memoryEvents.fetch_add(1, std::memory_order_relaxed);
        HandleMemoryEvent(msg.Event.Memory);
        break;

    /* ------ Network Events ------ */
    case EVENT_NETWORK_CONNECT:
    case EVENT_NETWORK_ACCEPT:
    case EVENT_DNS_QUERY:
        m_Counters.networkEvents.fetch_add(1, std::memory_order_relaxed);
        HandleNetworkEvent(msg.Event.Network);
        break;

    default:
        LOG_WARNING("EventDispatcher",
            "Unknown event type: 0x" +
            ([&]() { std::ostringstream o; o << std::hex << (ULONG)eventType; return o.str(); })());
        break;
    }
}

/* ============================================================================
 * Process Event Handler
 * Route to ProcessTree and DetectionEngine
 * ============================================================================ */
void EventDispatcher::HandleProcessEvent(const SENTINEL_PROCESS_EVENT& evt)
{
    DWORD pid = evt.Header.ProcessId;

    if (!evt.IsTermination) {
        /* Process creation */
        ProcessTree::Instance().AddProcess(
            pid,
            evt.ParentProcessId,
            evt.ImagePath,
            evt.CommandLine,
            evt.Header.Timestamp);

        /* Run detection rules against this process event */
        DetectionEngine::Instance().EvaluateProcessEvent(evt);
    } else {
        /* Process termination */
        ProcessTree::Instance().RemoveProcess(pid);
    }
}

/* ============================================================================
 * Thread Event Handler
 * Route to DetectionEngine
 * ============================================================================ */
void EventDispatcher::HandleThreadEvent(const SENTINEL_THREAD_EVENT& evt)
{
    DetectionEngine::Instance().EvaluateThreadEvent(evt);
}

/* ============================================================================
 * Image Load Event Handler
 * Route to injection/detection analysis
 * ============================================================================ */
void EventDispatcher::HandleImageEvent(const SENTINEL_IMAGE_EVENT& evt)
{
    /* Image loads go to DetectionEngine for module analysis */
    DetectionEngine::Instance().EvaluateImageEvent(evt);
}

/* ============================================================================
 * File Event Handler
 * Route to DetectionEngine
 * ============================================================================ */
void EventDispatcher::HandleFileEvent(const SENTINEL_FILE_EVENT& evt)
{
    DetectionEngine::Instance().EvaluateFileEvent(evt);
}

/* ============================================================================
 * Registry Event Handler
 * Route to DetectionEngine
 * ============================================================================ */
void EventDispatcher::HandleRegistryEvent(const SENTINEL_REGISTRY_EVENT& evt)
{
    DetectionEngine::Instance().EvaluateRegistryEvent(evt);
}

/* ============================================================================
 * Object/Handle Event Handler
 * Route to DetectionEngine (LSASS protection, etc.)
 * ============================================================================ */
void EventDispatcher::HandleObjectEvent(const SENTINEL_OBJECT_EVENT& evt)
{
    DetectionEngine::Instance().EvaluateObjectEvent(evt);
}

/* ============================================================================
 * Memory Event Handler
 * Route to DetectionEngine and correlation
 * ============================================================================ */
void EventDispatcher::HandleMemoryEvent(const SENTINEL_MEMORY_EVENT& evt)
{
    DetectionEngine::Instance().EvaluateMemoryEvent(evt);
}

/* ============================================================================
 * Network Event Handler
 * Route to DetectionEngine
 * ============================================================================ */
void EventDispatcher::HandleNetworkEvent(const SENTINEL_NETWORK_EVENT& evt)
{
    /* Network events forwarded to detection engine for anomaly analysis */
    (void)evt;  /* Network rule evaluation can be extended here */
}

} /* namespace blud */
