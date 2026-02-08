/*
 * BludEDR - main.cpp
 * Service entry point. Runs as Windows service or console mode (--console).
 * Initializes all components and handles clean shutdown.
 *
 * Made by @tarry
 */

#include "../inc/agent.h"
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

/* ============================================================================
 * Global shutdown signal definition
 * ============================================================================ */
namespace blud {
    std::atomic<bool> g_ShutdownRequested(false);
}

/* ============================================================================
 * Parse command line for --console flag
 * ============================================================================ */
static bool IsConsoleMode(int argc, wchar_t* argv[])
{
    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--console") == 0 ||
            _wcsicmp(argv[i], L"-console") == 0 ||
            _wcsicmp(argv[i], L"/console") == 0) {
            return true;
        }
    }
    return false;
}

/* ============================================================================
 * Print banner to console
 * ============================================================================ */
static void PrintBanner()
{
    printf("\n");
    printf("  ____  _           _ _____ ____  ____  \n");
    printf(" | __ )| |_   _  __| | ____|  _ \\|  _ \\ \n");
    printf(" |  _ \\| | | | |/ _` |  _| | | | | |_) |\n");
    printf(" | |_) | | |_| | (_| | |___| |_| |  _ < \n");
    printf(" |____/|_|\\__,_|\\__,_|_____|____/|_| \\_\\\n");
    printf("\n");
    printf("  Endpoint Detection & Response Agent\n");
    printf("  Made by @tarry\n");
    printf("  Build: %s %s\n", __DATE__, __TIME__);
    printf("\n");
}

/* ============================================================================
 * wmain - entry point
 * ============================================================================ */
int wmain(int argc, wchar_t* argv[])
{
    bool consoleMode = IsConsoleMode(argc, argv);

    /* Create the service controller (manages lifetime of all components) */
    blud::ServiceController serviceCtrl;

    if (consoleMode) {
        /* Console mode: run interactively with dashboard */
        PrintBanner();
        printf("  Running in CONSOLE mode (use --console flag)\n");
        printf("  Press Ctrl+C to stop.\n\n");

        /* Initialize config and logger first for early logging */
        blud::ConfigManager::Instance().Load(BLUD_CONFIG_FILE);
        blud::Logger::Instance().Initialize(
            blud::ConfigManager::Instance().GetLogPath(),
            blud::ConfigManager::Instance().GetLogLevel());

        /* Start the console dashboard */
        blud::ConsoleDashboard::Instance().Start();

        /* Run service controller in console mode */
        if (!serviceCtrl.RunAsConsole()) {
            printf("  [ERROR] Failed to initialize components.\n");
            blud::ConsoleDashboard::Instance().Stop();
            return 1;
        }

        blud::ConsoleDashboard::Instance().Stop();
        printf("\n  BludEDR agent stopped.\n");
        return 0;
    }
    else {
        /* Service mode: register with SCM and run as service */
        if (!serviceCtrl.RunAsService()) {
            /*
             * If RunAsService returns false with
             * ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, we are not running
             * under the SCM. Print a helpful message.
             */
            PrintBanner();
            printf("  Not running under Service Control Manager.\n");
            printf("  Use --console flag to run interactively:\n");
            printf("    BludEDR.exe --console\n\n");
            printf("  Or install as a service:\n");
            printf("    sc create BludEDR binPath= \"<path>\\BludEDR.exe\" start= auto\n");
            printf("    sc start BludEDR\n\n");
            return 1;
        }
        return 0;
    }
}
