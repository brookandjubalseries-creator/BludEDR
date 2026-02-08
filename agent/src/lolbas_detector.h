/*
 * BludEDR - lolbas_detector.h
 * Detection of Living-Off-The-Land Binaries and Scripts (LOLBAS) abuse
 */

#pragma once
#include "../inc/agent.h"

namespace blud {

/* ============================================================================
 * LOLBAS check result
 * ============================================================================ */
struct LolbasResult {
    bool                        isLolbas;
    std::vector<std::wstring>   suspiciousArgs;
    double                      score;

    LolbasResult() : isLolbas(false), score(0.0) {}
};

/* ============================================================================
 * LOLBAS entry in the database
 * ============================================================================ */
struct LolbasEntry {
    std::wstring                binaryName;     /* e.g., "certutil.exe" */
    std::vector<std::wstring>   suspiciousArgs; /* patterns to check in cmdline */
    double                      baseScore;
};

class LolbasDetector {
public:
    LolbasDetector();
    ~LolbasDetector();

    void Initialize();

    /* Check if a process is a LOLBAS binary with suspicious arguments */
    LolbasResult CheckProcess(const std::wstring& imageName,
                              const std::wstring& commandLine) const;

    /* Get all known LOLBAS binary names */
    std::vector<std::wstring> GetKnownBinaries() const;

    /* Singleton */
    static LolbasDetector& Instance();

private:
    void BuildDatabase();

    /* Key: lowercase binary name, Value: entry with suspicious arg patterns */
    std::unordered_map<std::wstring, LolbasEntry>   m_Database;

    static LolbasDetector* s_Instance;
};

} /* namespace blud */
