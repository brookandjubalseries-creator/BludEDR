@echo off
:: BludEDR - Driver Installation Script
:: Must be run as Administrator
:: Requires test signing enabled for unsigned drivers

setlocal EnableDelayedExpansion

echo ============================================
echo  BludEDR Driver Installation
echo ============================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    echo         Right-click and select "Run as administrator"
    pause
    exit /b 1
)

set DRIVER_NAME=BludDriver
set DRIVER_SYS=%~dp0..\driver\%DRIVER_NAME%.sys
set DRIVER_INF=%~dp0..\driver\%DRIVER_NAME%.inf
set SERVICE_NAME=BludDriver
set ALTITUDE=385200
set AGENT_EXE=%~dp0..\agent\BludAgent.exe

:: Check if driver file exists
if not exist "%DRIVER_SYS%" (
    echo [ERROR] Driver file not found: %DRIVER_SYS%
    echo         Please build the driver first.
    pause
    exit /b 1
)

:: Check test signing status
echo [*] Checking test signing status...
bcdedit /enum | findstr /i "testsigning.*Yes" >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Test signing is not enabled.
    echo          Run enable_testsigning.bat first if using unsigned driver.
    echo.
    set /p CONTINUE="Continue anyway? (y/n): "
    if /i "!CONTINUE!" neq "y" exit /b 1
)

:: Stop existing service if running
echo [*] Stopping existing driver service...
sc stop %SERVICE_NAME% >nul 2>&1
timeout /t 2 /nobreak >nul

:: Remove existing service
echo [*] Removing existing driver registration...
sc delete %SERVICE_NAME% >nul 2>&1
fltmc unload %SERVICE_NAME% >nul 2>&1
timeout /t 1 /nobreak >nul

:: Copy driver to system directory
echo [*] Copying driver to System32\drivers...
copy /Y "%DRIVER_SYS%" "%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys" >nul
if %errorLevel% neq 0 (
    echo [ERROR] Failed to copy driver file.
    pause
    exit /b 1
)

:: Create the minifilter service
echo [*] Creating minifilter service...
sc create %SERVICE_NAME% type=filesys binPath="%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys" start=demand group="FSFilter Activity Monitor"
if %errorLevel% neq 0 (
    echo [ERROR] Failed to create service.
    pause
    exit /b 1
)

:: Set minifilter registry values
echo [*] Configuring minifilter registry settings...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%" /v "DependOnService" /t REG_MULTI_SZ /d "FltMgr" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Instances" /v "DefaultInstance" /t REG_SZ /d "%SERVICE_NAME% Instance" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Instances\%SERVICE_NAME% Instance" /v "Altitude" /t REG_SZ /d "%ALTITUDE%" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Instances\%SERVICE_NAME% Instance" /v "Flags" /t REG_DWORD /d 0 /f >nul

:: Load the minifilter
echo [*] Loading minifilter driver...
fltmc load %SERVICE_NAME%
if %errorLevel% neq 0 (
    echo [ERROR] Failed to load minifilter. Check WinDbg for details.
    echo         Make sure test signing is enabled.
    pause
    exit /b 1
)

echo.
echo [+] BludDriver loaded successfully!
echo.

:: Install agent service if available
if exist "%AGENT_EXE%" (
    echo [*] Installing BludAgent service...
    sc create BludEDR binPath="%AGENT_EXE%" type=own start=demand DisplayName="BludEDR Agent"
    sc description BludEDR "BludEDR Endpoint Detection and Response Agent"
    echo [+] Agent service installed. Start with: sc start BludEDR
) else (
    echo [*] Agent executable not found, skipping service install.
)

echo.
echo ============================================
echo  Installation Complete
echo ============================================
echo  Driver:  fltmc (to verify)
echo  Agent:   sc start BludEDR
echo  Console: BludAgent.exe --console
echo ============================================

pause
