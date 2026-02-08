/*
 * BludEDR - agent.h
 * Main agent header: forward declarations, common includes, utility macros
 *
 * Made by @tarry
 */

#pragma once

/* ============================================================================
 * Standard and Windows includes
 * ============================================================================ */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fltUser.h>

#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <cctype>
#include <cwctype>

/* Shared protocol headers */
#include "../../shared/sentinel_shared.h"

/* ============================================================================
 * Utility macros
 * ============================================================================ */
#define BLUD_SAFE_DELETE(p)       do { if (p) { delete (p); (p) = nullptr; } } while(0)
#define BLUD_SAFE_CLOSE_HANDLE(h) do { if ((h) && (h) != INVALID_HANDLE_VALUE) { CloseHandle(h); (h) = nullptr; } } while(0)
#define BLUD_ARRAY_SIZE(a)       (sizeof(a) / sizeof((a)[0]))
#define BLUD_SUCCEEDED(hr)       (((HRESULT)(hr)) >= 0)

/* Log helper macros - route through the global logger */
#define LOG_DEBUG(comp, msg)     blud::Logger::Instance().Log(blud::LogLevel::DEBUG, comp, msg)
#define LOG_INFO(comp, msg)      blud::Logger::Instance().Log(blud::LogLevel::INFO, comp, msg)
#define LOG_WARNING(comp, msg)   blud::Logger::Instance().Log(blud::LogLevel::WARNING, comp, msg)
#define LOG_ERROR(comp, msg)     blud::Logger::Instance().Log(blud::LogLevel::ERR, comp, msg)
#define LOG_CRITICAL(comp, msg)  blud::Logger::Instance().Log(blud::LogLevel::CRITICAL, comp, msg)

/* Service name */
#define BLUD_SERVICE_NAME        L"BludEDR"
#define BLUD_SERVICE_DISPLAY     L"BludEDR Endpoint Detection and Response"

/* Receiver thread count */
#define BLUD_RECEIVER_THREADS    4

/* Default config file */
#define BLUD_CONFIG_FILE         L"blud_config.json"

/* ============================================================================
 * Namespace: blud
 * ============================================================================ */
namespace blud {

/* Forward declarations */
class ServiceController;
class DriverComm;
class EventDispatcher;
class ProcessTree;
class IoCScoring;
class DetectionEngine;
class LolbasDetector;
class AlertManager;
class ConfigManager;
class Logger;
class ConsoleDashboard;

/* ============================================================================
 * String utilities
 * ============================================================================ */
inline std::wstring ToLowerW(const std::wstring& s) {
    std::wstring result = s;
    for (auto& c : result) c = towlower(c);
    return result;
}

inline std::wstring ExtractFilename(const std::wstring& path) {
    auto pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
}

inline bool ContainsInsensitive(const std::wstring& haystack, const std::wstring& needle) {
    std::wstring h = ToLowerW(haystack);
    std::wstring n = ToLowerW(needle);
    return h.find(n) != std::wstring::npos;
}

inline std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
    std::string result(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), &result[0], sz, nullptr, nullptr);
    return result;
}

inline std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    std::wstring result(sz, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &result[0], sz);
    return result;
}

/* ============================================================================
 * Global shutdown signal
 * ============================================================================ */
extern std::atomic<bool> g_ShutdownRequested;

} /* namespace blud */
