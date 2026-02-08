/*
 * BludEDR - event_dispatcher.h
 * Demultiplexes incoming events by type and routes to handlers
 */

#pragma once
#include "../inc/agent.h"

namespace blud {

class EventDispatcher {
public:
    EventDispatcher();
    ~EventDispatcher();

    /* Initialize the dispatcher */
    void Initialize();

    /* Shut down */
    void Shutdown();

    /* Dispatch an incoming event to appropriate handlers */
    void DispatchEvent(const SENTINEL_MESSAGE& msg);

    /* Event counters for statistics */
    struct EventCounters {
        std::atomic<uint64_t> processEvents{ 0 };
        std::atomic<uint64_t> threadEvents{ 0 };
        std::atomic<uint64_t> imageEvents{ 0 };
        std::atomic<uint64_t> fileEvents{ 0 };
        std::atomic<uint64_t> registryEvents{ 0 };
        std::atomic<uint64_t> objectEvents{ 0 };
        std::atomic<uint64_t> memoryEvents{ 0 };
        std::atomic<uint64_t> networkEvents{ 0 };
        std::atomic<uint64_t> totalEvents{ 0 };
    };

    const EventCounters& GetCounters() const { return m_Counters; }

    /* Singleton */
    static EventDispatcher& Instance();

private:
    void HandleProcessEvent(const SENTINEL_PROCESS_EVENT& evt);
    void HandleThreadEvent(const SENTINEL_THREAD_EVENT& evt);
    void HandleImageEvent(const SENTINEL_IMAGE_EVENT& evt);
    void HandleFileEvent(const SENTINEL_FILE_EVENT& evt);
    void HandleRegistryEvent(const SENTINEL_REGISTRY_EVENT& evt);
    void HandleObjectEvent(const SENTINEL_OBJECT_EVENT& evt);
    void HandleMemoryEvent(const SENTINEL_MEMORY_EVENT& evt);
    void HandleNetworkEvent(const SENTINEL_NETWORK_EVENT& evt);

    EventCounters       m_Counters;
    std::atomic<bool>   m_Running;

    static EventDispatcher* s_Instance;
};

} /* namespace blud */
