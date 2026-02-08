/*
 * BludEDR - wfp_monitor.cpp
 * Network monitoring via TCP/UDP table enumeration and beaconing analysis
 *
 * Uses GetExtendedTcpTable/GetExtendedUdpTable for connection monitoring
 * and statistical analysis for beaconing detection.
 */

#include "../inc/wfp_monitor.h"
#include <iphlpapi.h>
#include <tcpmib.h>
#include <cmath>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace blud {

WfpMonitor::WfpMonitor() {}

WfpMonitor::~WfpMonitor() {
    Shutdown();
}

bool WfpMonitor::Initialize() {
    QueryPerformanceFrequency(&m_perfFreq);
    m_running = true;
    m_monitorThread = std::thread(&WfpMonitor::MonitorThread, this);
    return true;
}

void WfpMonitor::Shutdown() {
    m_running = false;
    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_processConns.clear();
    m_beaconTrackers.clear();
}

void WfpMonitor::MonitorThread() {
    /* Track known connections to detect new ones */
    std::unordered_map<ULONGLONG, bool> knownConns;
    DWORD pollCount = 0;

    while (m_running) {
        Sleep(1000); /* Poll every second */

        std::unordered_map<ULONGLONG, bool> currentConns;

        /* Enumerate TCP connections */
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size > 0) {
            std::vector<BYTE> buffer(size);
            if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET,
                                     TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            {
                auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; i++) {
                    auto& row = table->table[i];

                    /* Only track established connections or SYN_SENT (new outbound) */
                    if (row.dwState != MIB_TCP_STATE_ESTAB &&
                        row.dwState != MIB_TCP_STATE_SYN_SENT) {
                        continue;
                    }

                    /* Skip loopback */
                    if (row.dwRemoteAddr == htonl(INADDR_LOOPBACK)) continue;

                    /* Create unique connection ID */
                    ULONGLONG connId = ((ULONGLONG)row.dwOwningPid << 48) |
                                       ((ULONGLONG)row.dwRemoteAddr << 16) |
                                       (ULONGLONG)ntohs((USHORT)row.dwRemotePort);
                    currentConns[connId] = true;

                    /* Check if this is a new connection */
                    if (knownConns.find(connId) == knownConns.end()) {
                        LARGE_INTEGER now;
                        QueryPerformanceCounter(&now);

                        NetworkConnection conn;
                        conn.ProcessId = row.dwOwningPid;
                        conn.LocalAddress = row.dwLocalAddr;
                        conn.LocalPort = ntohs((USHORT)row.dwLocalPort);
                        conn.RemoteAddress = row.dwRemoteAddr;
                        conn.RemotePort = ntohs((USHORT)row.dwRemotePort);
                        conn.Protocol = IPPROTO_TCP;
                        conn.IsOutbound = (row.dwState == MIB_TCP_STATE_SYN_SENT ||
                                          row.dwState == MIB_TCP_STATE_ESTAB);
                        conn.Timestamp = now.QuadPart;

                        m_totalConnections++;

                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            m_processConns[conn.ProcessId].Push(conn);

                            /* Track for beaconing */
                            ULONGLONG beaconKey = ((ULONGLONG)conn.ProcessId << 32) |
                                                  ((ULONGLONG)conn.RemoteAddress);
                            m_beaconTrackers[beaconKey].Push(now.QuadPart);
                        }

                        if (m_connCallback) {
                            m_connCallback(conn);
                        }
                    }
                }
            }
        }

        knownConns = std::move(currentConns);

        /* Run beaconing analysis every 30 seconds */
        pollCount++;
        if (pollCount % 30 == 0) {
            AnalyzeBeaconing();
        }
    }
}

void WfpMonitor::AnalyzeBeaconing() {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto& [key, tracker] : m_beaconTrackers) {
        if (tracker.Timestamps.size() < 5) continue; /* Need enough samples */

        DWORD pid = (DWORD)(key >> 32);
        ULONG remoteAddr = (ULONG)(key & 0xFFFFFFFF);

        /* Calculate mean interval */
        std::vector<double> intervals;
        for (size_t i = 1; i < tracker.Timestamps.size(); i++) {
            double intervalMs = (double)(tracker.Timestamps[i] - tracker.Timestamps[i - 1])
                               * 1000.0 / m_perfFreq.QuadPart;
            intervals.push_back(intervalMs);
        }

        if (intervals.empty()) continue;

        double sum = 0;
        for (double d : intervals) sum += d;
        double mean = sum / intervals.size();

        /* Calculate standard deviation */
        double sqSum = 0;
        for (double d : intervals) sqSum += (d - mean) * (d - mean);
        double stddev = sqrt(sqSum / intervals.size());

        /* Jitter percentage */
        double jitter = (mean > 0) ? (stddev / mean) * 100.0 : 100.0;

        /* Beaconing heuristic:
           - Regular connections (jitter < 20%)
           - At least 5 connections
           - Interval between 1 second and 10 minutes */
        bool suspicious = (jitter < 20.0) &&
                          (intervals.size() >= 5) &&
                          (mean >= 1000.0) &&
                          (mean <= 600000.0);

        if (suspicious) {
            m_beaconAlerts++;

            if (m_beaconCallback) {
                BeaconingInfo info;
                info.ProcessId = pid;
                info.RemoteAddress = remoteAddr;
                info.RemotePort = 0; /* Not tracked in key */
                info.ConnectionCount = (int)tracker.Timestamps.size();
                info.MeanIntervalMs = mean;
                info.JitterPercent = jitter;
                info.IsSuspicious = true;
                m_beaconCallback(info);
            }
        }
    }
}

double WfpMonitor::CalculateEntropy(const std::wstring& domain) const {
    if (domain.empty()) return 0.0;

    /* Count character frequencies */
    std::unordered_map<wchar_t, int> freq;
    int total = 0;
    for (wchar_t c : domain) {
        if (c == L'.') continue; /* Skip dots */
        freq[c]++;
        total++;
    }

    if (total == 0) return 0.0;

    /* Shannon entropy */
    double entropy = 0.0;
    for (auto& [ch, count] : freq) {
        double p = (double)count / total;
        if (p > 0) {
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

void WfpMonitor::SetConnectionCallback(NetworkCallback cb) {
    m_connCallback = std::move(cb);
}

void WfpMonitor::SetBeaconCallback(BeaconCallback cb) {
    m_beaconCallback = std::move(cb);
}

void WfpMonitor::SetDnsCallback(DnsCallback cb) {
    m_dnsCallback = std::move(cb);
}

std::vector<NetworkConnection> WfpMonitor::GetProcessConnections(DWORD pid) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_processConns.find(pid);
    if (it != m_processConns.end()) {
        return std::vector<NetworkConnection>(
            it->second.Connections.begin(),
            it->second.Connections.end()
        );
    }
    return {};
}

} // namespace blud
