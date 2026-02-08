@echo off
:: BludEDR - Driver Uninstallation Script
:: Must be run as Administrator

setlocal

echo ============================================
echo  BludEDR Driver Uninstallation
echo ============================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    pause
    exit /b 1
)

set DRIVER_NAME=BludDriver
set SERVICE_NAME=BludDriver

:: Stop the agent service first
echo [*] Stopping BludEDR agent service...
sc stop BludEDR >nul 2>&1
timeout /t 2 /nobreak >nul

:: Remove agent service
echo [*] Removing BludEDR agent service...
sc delete BludEDR >nul 2>&1

:: Unload the minifilter
echo [*] Unloading minifilter driver...
fltmc unload %SERVICE_NAME%
if %errorLevel% neq 0 (
    echo [WARNING] Minifilter may not have been loaded.
)

:: Stop the driver service
echo [*] Stopping driver service...
sc stop %SERVICE_NAME% >nul 2>&1
timeout /t 2 /nobreak >nul

:: Delete the service
echo [*] Removing driver service...
sc delete %SERVICE_NAME%

:: Remove driver file
echo [*] Removing driver file...
del /f "%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys" >nul 2>&1

echo.
echo [+] BludEDR uninstalled successfully.
echo.

pause
