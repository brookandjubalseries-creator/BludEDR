/*
 * BludEDR - lolbas_detector.cpp
 * LOLBAS binary database with suspicious argument patterns
 */

#include "lolbas_detector.h"
#include "logger.h"

namespace blud {

LolbasDetector* LolbasDetector::s_Instance = nullptr;

LolbasDetector::LolbasDetector()
{
    s_Instance = this;
}

LolbasDetector::~LolbasDetector()
{
    s_Instance = nullptr;
}

LolbasDetector& LolbasDetector::Instance()
{
    static LolbasDetector instance;
    return instance;
}

void LolbasDetector::Initialize()
{
    BuildDatabase();
    LOG_INFO("LolbasDetector", "Initialized with " + std::to_string(m_Database.size()) + " LOLBAS entries");
}

/* ============================================================================
 * Build the LOLBAS database
 * ============================================================================ */
void LolbasDetector::BuildDatabase()
{
    /* ----- certutil.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"certutil.exe";
        e.suspiciousArgs = { L"-urlcache", L"-split", L"-decode", L"-encode" };
        e.baseScore = 75.0;
        m_Database[L"certutil.exe"] = std::move(e);
    }

    /* ----- mshta.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"mshta.exe";
        e.suspiciousArgs = { L"vbscript", L"javascript", L"about:" };
        e.baseScore = 80.0;
        m_Database[L"mshta.exe"] = std::move(e);
    }

    /* ----- regsvr32.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"regsvr32.exe";
        e.suspiciousArgs = { L"/s /n /u /i:", L"/s", L"/n", L"/u", L"/i:", L"scrobj.dll" };
        e.baseScore = 80.0;
        m_Database[L"regsvr32.exe"] = std::move(e);
    }

    /* ----- rundll32.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"rundll32.exe";
        e.suspiciousArgs = { L"javascript:", L"dllregisterserver", L"vbscript:" };
        e.baseScore = 75.0;
        m_Database[L"rundll32.exe"] = std::move(e);
    }

    /* ----- cscript.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"cscript.exe";
        e.suspiciousArgs = { L"/e:", L"//b", L"//nologo" };
        e.baseScore = 60.0;
        m_Database[L"cscript.exe"] = std::move(e);
    }

    /* ----- wscript.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"wscript.exe";
        e.suspiciousArgs = { L"/e:", L"//b", L"//nologo" };
        e.baseScore = 60.0;
        m_Database[L"wscript.exe"] = std::move(e);
    }

    /* ----- bitsadmin.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"bitsadmin.exe";
        e.suspiciousArgs = { L"/transfer", L"/create", L"/addfile" };
        e.baseScore = 70.0;
        m_Database[L"bitsadmin.exe"] = std::move(e);
    }

    /* ----- msiexec.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"msiexec.exe";
        e.suspiciousArgs = { L"/q", L"http://", L"https://" };
        e.baseScore = 70.0;
        m_Database[L"msiexec.exe"] = std::move(e);
    }

    /* ----- powershell.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"powershell.exe";
        e.suspiciousArgs = {
            L"-enc", L"-nop", L"-w hidden", L"-ep bypass",
            L"iex", L"invoke-expression", L"downloadstring",
            L"-encodedcommand", L"-windowstyle hidden",
            L"-executionpolicy bypass", L"net.webclient",
            L"invoke-webrequest", L"start-bitstransfer"
        };
        e.baseScore = 65.0;
        m_Database[L"powershell.exe"] = std::move(e);

        /* Also for pwsh.exe (PowerShell Core) */
        LolbasEntry e2 = m_Database[L"powershell.exe"];
        e2.binaryName = L"pwsh.exe";
        m_Database[L"pwsh.exe"] = std::move(e2);
    }

    /* ----- cmd.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"cmd.exe";
        e.suspiciousArgs = { L"/c", L"certutil", L"powershell", L"bitsadmin" };
        e.baseScore = 40.0;
        m_Database[L"cmd.exe"] = std::move(e);
    }

    /* ----- msbuild.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"msbuild.exe";
        e.suspiciousArgs = { L".xml", L".csproj", L"/p:" };
        e.baseScore = 70.0;
        m_Database[L"msbuild.exe"] = std::move(e);
    }

    /* ----- installutil.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"installutil.exe";
        e.suspiciousArgs = { L"/logfile=", L"/logtoconsole=false", L"/u" };
        e.baseScore = 75.0;
        m_Database[L"installutil.exe"] = std::move(e);
    }

    /* ----- regasm.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"regasm.exe";
        e.suspiciousArgs = { L"/u" };
        e.baseScore = 70.0;
        m_Database[L"regasm.exe"] = std::move(e);
    }

    /* ----- regsvcs.exe ----- */
    {
        LolbasEntry e;
        e.binaryName = L"regsvcs.exe";
        e.suspiciousArgs = { L"/u" };
        e.baseScore = 70.0;
        m_Database[L"regsvcs.exe"] = std::move(e);
    }
}

/* ============================================================================
 * Check a process against the LOLBAS database
 * ============================================================================ */
LolbasResult LolbasDetector::CheckProcess(const std::wstring& imageName,
                                           const std::wstring& commandLine) const
{
    LolbasResult result;

    std::wstring lowerName = ToLowerW(ExtractFilename(imageName));
    auto it = m_Database.find(lowerName);
    if (it == m_Database.end()) {
        return result;
    }

    result.isLolbas = true;
    const LolbasEntry& entry = it->second;
    std::wstring lowerCmd = ToLowerW(commandLine);

    for (const auto& arg : entry.suspiciousArgs) {
        std::wstring lowerArg = ToLowerW(arg);
        if (lowerCmd.find(lowerArg) != std::wstring::npos) {
            result.suspiciousArgs.push_back(arg);
        }
    }

    if (!result.suspiciousArgs.empty()) {
        /* Score scales with number of suspicious args matched */
        double matchRatio = static_cast<double>(result.suspiciousArgs.size()) /
                            static_cast<double>(entry.suspiciousArgs.size());
        result.score = entry.baseScore * (0.5 + 0.5 * matchRatio);
    }

    return result;
}

/* ============================================================================
 * Get all known binary names
 * ============================================================================ */
std::vector<std::wstring> LolbasDetector::GetKnownBinaries() const
{
    std::vector<std::wstring> result;
    result.reserve(m_Database.size());
    for (const auto& [name, entry] : m_Database) {
        (void)entry;
        result.push_back(name);
    }
    return result;
}

} /* namespace blud */
