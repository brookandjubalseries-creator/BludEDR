/*
 * BludEDR - wfp_monitor.h
 * Network monitoring via Windows Filtering Platform (WFP) events
 * and connection table enumeration
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>

namespace blud {

struct NetworkConnection {
    DWORD       ProcessId;
    ULONG       LocalAddress;       /* IPv4 in network byte order */
    USHORT      LocalPort;
    ULONG       RemoteAddress;
    USHORT      RemotePort;
    ULONG       Protocol;           /* IPPROTO_TCP / IPPROTO_UDP */
    bool        IsOutbound;
    LONGLONG    Timestamp;
    std::wstring ProcessName;
};

struct BeaconingInfo {
    DWORD       ProcessId;
    ULONG       RemoteAddress;
    USHORT      RemotePort;
    int         ConnectionCount;
    double      MeanIntervalMs;
    double      JitterPercent;      /* Low jitter = likely beacon */
    bool        IsSuspicious;
};

struct DnsInfo {
    DWORD       ProcessId;
    std::wstring QueryName;
    double      Entropy;            /* Shannon entropy of domain labels */
    bool        IsHighEntropy;      /* Likely DGA */
};

using NetworkCallback = std::function<void(const NetworkConnection&)>;
using BeaconCallback = std::function<void(const BeaconingInfo&)>;
using DnsCallback = std::function<void(const DnsInfo&)>;

class WfpMonitor {
public:
    WfpMonitor();
    ~WfpMonitor();

    bool Initialize();
    void Shutdown();

    /* Callbacks */
    void SetConnectionCallback(NetworkCallback cb);
    void SetBeaconCallback(BeaconCallback cb);
    void SetDnsCallback(DnsCallback cb);

    /* Get recent connections for a process */
    std::vector<NetworkConnection> GetProcessConnections(DWORD pid) const;

    /* Stats */
    ULONGLONG GetTotalConnections() const { return m_totalConnections; }
    ULONGLONG GetBeaconAlerts() const { return m_beaconAlerts; }

private:
    /* Polling-based monitoring (TCP table enumeration) */
    void MonitorThread();

    /* Beaconing analysis */
    void AnalyzeBeaconing();

    /* DNS entropy calculation */
    double CalculateEntropy(const std::wstring& domain) const;

    /* Connection history per process */
    struct ProcessConnHistory {
        std::deque<NetworkConnection> Connections;
        static constexpr size_t MAX = 512;
        void Push(const NetworkConnection& c) {
            if (Connections.size() >= MAX) Connections.pop_front();
            Connections.push_back(c);
        }
    };

    /* Per (pid, remote_addr, remote_port) beacon tracking */
    struct BeaconTracker {
        std::deque<LONGLONG> Timestamps;
        static constexpr size_t MAX = 64;
        void Push(LONGLONG ts) {
            if (Timestamps.size() >= MAX) Timestamps.pop_front();
            Timestamps.push_back(ts);
        }
    };

    std::unordered_map<DWORD, ProcessConnHistory>       m_processConns;
    std::unordered_map<ULONGLONG, BeaconTracker>        m_beaconTrackers;

    NetworkCallback     m_connCallback;
    BeaconCallback      m_beaconCallback;
    DnsCallback         m_dnsCallback;

    std::thread         m_monitorThread;
    mutable std::mutex  m_mutex;
    std::atomic<bool>   m_running{false};

    std::atomic<ULONGLONG> m_totalConnections{0};
    std::atomic<ULONGLONG> m_beaconAlerts{0};

    LARGE_INTEGER m_perfFreq;
};

} // namespace blud
