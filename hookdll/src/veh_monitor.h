/*
 * BludEDR - veh_monitor.h
 * Hook for AddVectoredExceptionHandler to track VEH registrations
 */

#pragma once

#include "../inc/hookdll.h"

extern pfnAddVectoredExceptionHandler g_pOrigAddVectoredExceptionHandler;
