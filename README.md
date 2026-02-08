# BludEDR

A full kernel-level Endpoint Detection and Response (EDR) system for Windows 10/11 x64.

Detects crypter architectures at runtime, suspicious LOLBAS commands, rootkits, living-off-the-land malware, process injection, AMSI/ETW bypasses, memory encryption (sleep obfuscation), and VEH-based bypasses.

**Made by @tarry**

---

## Architecture

```
KERNEL:  BludDriver.sys (KMDF minifilter)
  Process/Thread/Image/File/Registry/Object callbacks
    -> Lock-free ring buffer (4096 slots)
      -> FltSendMessage
           |
     [\\BludCommPort]
           |
USER:    BludAgent.exe (service / console)
  FilterGetMessage (4 threads) -> EventDispatcher
    -> ProcessTree, IoCScoring, DetectionEngine, AlertManager
    -> InjectionManager (triggers DLL injection on new processes)
           |
     [\\.\pipe\BludHook_{PID}]
           |
USER:    BludHook.dll (injected into monitored processes)
  ntdll inline hooks + AMSI/ETW/VEH monitors + MemoryGuard
    -> Sends SENTINEL_MEMORY_EVENT via named pipe to agent
```

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| **BludDriver.sys** | C (KMDF) | Minifilter kernel driver at altitude 385200. Registers callbacks for process, thread, image load, file, registry, and object handle operations. LSASS protection via ObRegisterCallbacks. |
| **BludAgent.exe** | C++17 | Userspace service with IoC scoring engine, LOLBAS detector, process tree tracker, ETW consumer, YARA scanner, correlation engine, network monitor, and real-time console dashboard. |
| **BludHook.dll** | C++17 | Injected DLL with trampoline-based inline hooks on 6 ntdll APIs. Monitors for AMSI/ETW patching, VEH installation, sleep obfuscation, RWX memory, and credential material in memory. |

## Detection Capabilities

### Kernel Telemetry (BludDriver)
- Process creation/termination with full command line and parent tracking
- Cross-process thread creation (injection indicator)
- DLL/image load monitoring
- Suspicious file drops (.bat, .vbs, .ps1, .js, .wsf, .hta, .cmd, .scr)
- Registry persistence monitoring (Run keys, services, scheduled tasks, IFEO, Winlogon, etc.)
- LSASS handle protection (strips PROCESS_VM_READ/WRITE from unauthorized callers)

### Userspace Detection (BludAgent)
- **IoC Scoring**: Weighted scores with 5-minute half-life decay and 30% parent inheritance
- **LOLBAS Detection**: certutil, mshta, regsvr32, rundll32, cscript, wscript, bitsadmin, msiexec, powershell, cmd, msbuild, installutil, regasm, regsvcs
- **Process Lineage**: Suspicious parent-child chains (Office -> shell, svchost -> shell)
- **ETW Consumer**: Microsoft-Windows-Kernel-Process, DotNETRuntime, Threat-Intelligence providers
- **YARA Scanner**: 4 rule files for malware, shellcode, encryption patterns, and reflective DLL
- **Correlation Engine**: Multi-event pattern matching with time windows:
  - Process Injection: ALLOC -> WRITE -> THREAD (5s window)
  - AMSI Bypass + Execution: AMSI patch -> encoded PowerShell (10s window)
  - Credential Theft: LSASS access -> .dmp file write (30s window)
  - Sleep Obfuscation: RX<->RW cycling on same region (3s window)
- **Network Monitor**: TCP connection tracking, beaconing detection (low-jitter periodic connections), DGA entropy analysis
- **Callstack Analysis**: StackWalk64 with unbacked frame detection (code executing outside loaded modules)

### Hook DLL Detection (BludHook)
- **NtAllocateVirtualMemory**: RWX allocations, remote allocations
- **NtProtectVirtualMemory**: RW->RX transitions (shellcode loader pattern)
- **NtWriteVirtualMemory**: Cross-process writes
- **NtCreateThreadEx**: Remote thread creation
- **NtMapViewOfSection**: Cross-process section mapping (process hollowing)
- **NtQueueApcThread**: APC injection
- **AMSI Monitor**: Periodic integrity check of AmsiScanBuffer (detects RET, NOP sled, XOR+RET patches)
- **ETW Monitor**: Integrity check of EtwEventWrite and NtTraceEvent
- **VEH Monitor**: Hooks AddVectoredExceptionHandler, flags unbacked handlers
- **Memory Guard**: Periodic scan for RWX regions, shellcode signatures, AES key schedules
- **Sleep Obfuscation**: Detects Ekko/Cronos/Foliage patterns (rapid RX<->RW cycling)
- **Token Scanner**: Scans heap for JWT tokens, AWS keys, API keys

## Built-in Rules

| Rule ID | Trigger | Score | Action |
|---------|---------|-------|--------|
| 1001 | cmd.exe spawns powershell.exe | 25 | LOG |
| 1002 | powershell -enc / obfuscated | 90 | TERMINATE |
| 1003 | Script file dropped to disk | 100 | TERMINATE |
| 1004 | LOLBAS with suspicious args | 75 | ALERT |
| 1005 | Suspicious parent-child | 50 | ALERT |
| 1007 | Remote thread creation | 85 | SUSPEND |
| 1008 | LSASS handle with VM_READ | 100 | TERMINATE |
| 1009 | AMSI bypass detected | 90 | TERMINATE |
| 1010 | ETW bypass detected | 90 | TERMINATE |
| 1011 | RWX memory allocation | 40 | LOG |
| 1012 | RW->RX transition | 60 | ALERT |
| 1013 | Registry persistence | 75 | ALERT |
| 1014 | Sleep obfuscation | 70 | ALERT |

**Actions**: LOG (score < 50), ALERT (50-79), SUSPEND (80-89), TERMINATE (90-100)

## Prerequisites

- **Visual Studio 2022** with "Desktop development with C++" workload
- **Windows Driver Kit (WDK) 10.0.22621+** ([download](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk))
- **Test VM** running Windows 10/11 x64 (never test kernel drivers on your main machine)
- **Test signing** enabled on the VM

## Building

1. Clone the repo:
   ```
   git clone https://github.com/brookandjubalseries-creator/BludEDR.git
   ```

2. Open `BludEDR.sln` in Visual Studio 2022

3. Set configuration to **Release | x64**

4. Build the solution (Build -> Build Solution or Ctrl+Shift+B)

Build outputs:
```
Release\BludDriver.sys    # Kernel minifilter driver
Release\BludAgent.exe     # Userspace agent
Release\BludHook.dll      # Hook DLL
```

**Note**: The YARA scanner compiles in stub mode by default. To enable full YARA support, link libyara statically and define `BLUD_HAS_YARA` in the BludAgent preprocessor definitions.

## Installation

### 1. Prepare the Test VM

Copy the build outputs and the `tools/` folder to your test VM.

Enable test signing (requires reboot):
```cmd
:: Run as Administrator
bcdedit /set testsigning on
shutdown /r /t 0
```

### 2. Install the Driver

```cmd
:: Run as Administrator
tools\install_driver.bat
```

Or manually:
```cmd
copy BludDriver.sys %SystemRoot%\System32\drivers\
sc create BludDriver type=filesys binPath=%SystemRoot%\System32\drivers\BludDriver.sys start=demand group="FSFilter Activity Monitor"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BludDriver\Instances" /v "DefaultInstance" /t REG_SZ /d "BludDriver Instance" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BludDriver\Instances\BludDriver Instance" /v "Altitude" /t REG_SZ /d "385200" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BludDriver\Instances\BludDriver Instance" /v "Flags" /t REG_DWORD /d 0 /f
fltmc load BludDriver
```

### 3. Start the Agent

Console mode (recommended for testing - shows live dashboard):
```cmd
BludAgent.exe --console
```

As a Windows service:
```cmd
sc create BludEDR binPath="C:\path\to\BludAgent.exe" type=own start=demand
sc start BludEDR
```

## Testing Detections

With the agent running in console mode, open a second command prompt and try:

```cmd
:: Rule 1001 - cmd spawns powershell (score 25, LOG)
powershell -Command "whoami"

:: Rule 1002 - Encoded PowerShell (score 90, TERMINATE)
powershell -enc dwBoAG8AYQBtAGkA

:: Rule 1004 - LOLBAS certutil download (score 75, ALERT)
certutil -urlcache -split -f http://example.com/test.txt C:\temp\test.txt

:: Rule 1003 - Script file drop (score 100, TERMINATE)
echo @echo hello > %TEMP%\test.bat

:: Rule 1013 - Registry persistence (score 75, ALERT)
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v TestEDR /d "calc.exe" /f
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v TestEDR /f

:: Rule 1004 - LOLBAS mshta (score 75, ALERT)
mshta vbscript:Execute("MsgBox(""test"")")
```

Watch the console dashboard for:
- IoC scores updating in the process list
- Alerts appearing in the alert feed
- Event counters incrementing

## Uninstallation

```cmd
:: Run as Administrator
tools\uninstall_driver.bat
```

Or manually:
```cmd
fltmc unload BludDriver
sc delete BludDriver
sc stop BludEDR
sc delete BludEDR
del %SystemRoot%\System32\drivers\BludDriver.sys
```

## Kernel Debugging

If the driver causes issues, attach WinDbg to the VM:

```cmd
:: On the VM, enable debug over serial/network:
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

Useful WinDbg commands:
```
!analyze -v                    # Analyze bugcheck
lm m BludDriver                # Check if driver is loaded
bp BludDriver!DriverEntry      # Break on driver load
!fltkd.filters                 # List minifilter instances
```

## Recovery

If the VM won't boot after driver installation:
1. Boot into **Safe Mode** (hold Shift while clicking Restart, or interrupt boot 3 times)
2. Open an admin command prompt
3. Run: `sc delete BludDriver`
4. Reboot normally

## Project Structure

```
BludEDR/
├── BludEDR.sln                    # Visual Studio solution
├── shared/                        # Shared headers (driver + agent + hookdll)
│   ├── sentinel_shared.h          # Communication protocol structs
│   ├── sentinel_events.h          # Event type enum definitions
│   └── sentinel_ioc.h             # IoC scoring definitions
├── driver/                        # KMDF minifilter kernel driver (C)
│   ├── BludDriver.vcxproj
│   ├── BludDriver.inf             # Minifilter INF (altitude 385200)
│   ├── inc/driver.h               # Driver globals and prototypes
│   └── src/
│       ├── driver_entry.c         # DriverEntry, callback registration
│       ├── minifilter_ops.c       # File create/drop detection
│       ├── process_monitor.c      # Process create/terminate
│       ├── thread_monitor.c       # Thread creation, cross-process detection
│       ├── image_monitor.c        # DLL/image load tracking
│       ├── registry_monitor.c     # Persistence key monitoring
│       ├── object_monitor.c       # LSASS handle protection
│       ├── comm_port.c            # FltCreateCommunicationPort + worker
│       ├── event_queue.c          # Lock-free ring buffer
│       ├── process_context.c      # Per-process context tracking
│       └── string_utils.c         # Unicode string helpers
├── agent/                         # Userspace service (C++17)
│   ├── BludAgent.vcxproj
│   ├── blud_config.json           # Default configuration
│   ├── inc/                       # Agent headers
│   └── src/
│       ├── main.cpp               # Entry point (service / console)
│       ├── service_controller.*   # Windows Service lifecycle
│       ├── driver_comm.*          # FilterConnectCommunicationPort
│       ├── event_dispatcher.*     # Event routing by type
│       ├── process_tree.*         # Parent-child process tracking
│       ├── ioc_scoring.*          # Time-decaying IoC scores
│       ├── detection_engine.*     # Rule evaluation pipeline
│       ├── lolbas_detector.*      # LOLBAS binary + arg matching
│       ├── alert_manager.*        # Alert generation + response actions
│       ├── config_manager.*       # JSON config loading
│       ├── logger.*               # Structured logging + rotation
│       ├── console_dashboard.*    # Real-time colored console TUI
│       ├── injection_manager.*    # DLL injection (APC / NtCreateThreadEx)
│       ├── memory_scanner.*       # Process memory scanning
│       ├── etw_consumer.*         # ETW real-time consumer
│       ├── yara_scanner.*         # YARA rule integration
│       ├── callstack_analyzer.*   # StackWalk64 + unbacked detection
│       ├── correlation_engine.*   # Multi-event correlation
│       └── wfp_monitor.*          # Network + beaconing detection
├── hookdll/                       # Injected hook DLL (C++17)
│   ├── BludHook.vcxproj
│   ├── inc/hookdll.h              # DLL globals and prototypes
│   └── src/
│       ├── dllmain.cpp            # DLL entry, hook installation
│       ├── hook_engine.*          # Trampoline inline hooking engine
│       ├── iat_hook.*             # IAT patching (fallback)
│       ├── ntdll_hooks.*          # 6 ntdll API hooks
│       ├── amsi_monitor.*         # AmsiScanBuffer integrity check
│       ├── etw_monitor.*          # EtwEventWrite integrity check
│       ├── veh_monitor.*          # VEH registration monitoring
│       ├── memory_guard.*         # Periodic RWX + shellcode scan
│       ├── hook_comm.*            # Named pipe to agent
│       ├── callstack_capture.*    # RtlCaptureStackBackTrace wrapper
│       ├── token_scanner.*        # JWT/AWS/API key scanner
│       ├── sleep_obfuscation_detect.* # Ekko/Cronos/Foliage detection
│       └── pe_utils.*             # PE parsing utilities
├── rules/yara/                    # YARA detection rules
│   ├── malware_generic.yar        # C2, credential tools, packed PE
│   ├── shellcode_patterns.yar     # PEB walk, ROR13, syscall stubs
│   ├── encryption_patterns.yar    # AES S-box, RC4, sleep obfuscation
│   └── reflective_dll.yar         # Reflective loader, hollowing, AMSI bypass
└── tools/                         # Deployment scripts
    ├── install_driver.bat
    ├── uninstall_driver.bat
    └── enable_testsigning.bat
```

## Configuration

Edit `blud_config.json` to customize:

```json
{
    "logPath": "C:\\ProgramData\\BludEDR\\logs",
    "logLevel": "INFO",
    "enableHookDll": true,
    "enableYara": true,
    "enableEtw": true,
    "enableNetworkMonitor": true,
    "scoreThresholds": {
        "log": 0,
        "alert": 50,
        "suspend": 80,
        "terminate": 90
    },
    "scoreDecayHalfLifeSeconds": 300,
    "parentScoreInheritance": 0.30,
    "whitelistedProcesses": [
        "system", "smss.exe", "csrss.exe", "lsass.exe", "svchost.exe"
    ]
}
```

## License

This project is provided for educational and authorized security research purposes only.

## Disclaimer

This software interacts with the Windows kernel and hooks system APIs. Improper use can cause system instability, data loss, or blue screens. **Always test in a virtual machine.** The authors are not responsible for any damage caused by the use of this software.
