@echo off
:: BludEDR - Enable Test Signing
:: Enables test signing mode for loading unsigned kernel drivers
:: Requires reboot after running

setlocal

echo ============================================
echo  BludEDR - Enable Test Signing Mode
echo ============================================
echo.
echo WARNING: This enables test signing mode which allows
echo          loading of unsigned kernel drivers.
echo          A reboot is required after running this script.
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    pause
    exit /b 1
)

:: Check if Secure Boot is enabled (blocks test signing)
echo [*] Checking Secure Boot status...
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State" /v UEFISecureBootEnabled 2>nul | findstr "0x1" >nul 2>&1
if %errorLevel% equ 0 (
    echo [WARNING] Secure Boot is ENABLED.
    echo          Test signing will not work with Secure Boot.
    echo          Disable Secure Boot in BIOS/UEFI first.
    echo.
)

:: Enable test signing
echo [*] Enabling test signing...
bcdedit /set testsigning on
if %errorLevel% neq 0 (
    echo [ERROR] Failed to enable test signing.
    echo         Try disabling Secure Boot first.
    pause
    exit /b 1
)

:: Also enable kernel debugging for WinDbg
echo [*] Enabling kernel debugging...
bcdedit /debug on >nul 2>&1

echo.
echo [+] Test signing mode enabled.
echo [!] Please REBOOT your machine for changes to take effect.
echo.
echo After reboot, you will see a "Test Mode" watermark on the desktop.
echo.

pause
