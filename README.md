# 🛡️ VYRON - Production-Grade AI-Powered Malware Detection System

**Enterprise-Level Endpoint Detection and Response (EDR) for Windows**

Vyron is an advanced, open-source EDR solution designed to rival commercial products like CrowdStrike Falcon and Microsoft Defender for Endpoint. Built with cutting-edge detection techniques, machine learning, and deep Windows internals integration.

## 🎯 Key Features

### Core Detection Capabilities
✅ **Multi-Layer Detection Engine**
- Signature-based scanning (YARA-like rules)
- Behavioral analysis (heuristics)
- Reputation-based detection (hash database)
- Machine learning inference (ML.NET)
- **NEW**: Advanced ETW telemetry (6+ providers)
- **NEW**: Memory forensics (injection, hollowing, hooks)
- **NEW**: Exploit detection (ROP, heap spray, DEP bypass)
- **NEW**: Network C2 detection (WFP)
- **NEW**: AMSI integration (PowerShell/script scanning)

### Advanced Detection Systems 🚀

#### 1. **Memory Forensics Scanner**
- **DLL Injection Detection**: Identifies suspicious module loads from Temp/AppData
- **Process Hollowing Detection**: Compares memory PE headers against disk images
- **Inline Hook Detection**: Scans critical APIs (ntdll, kernel32) for JMP/PUSH-RET patterns
- **Shellcode Detection**: Finds RWX memory regions with executable patterns
- **Reflective DLL Detection**: Locates PE structures in non-module memory

#### 2. **Exploit Detection Engine**
- **ROP Chain Detection**: Analyzes stack for gadget sequences (3+ consecutive)
- **Heap Spray Detection**: Identifies repeated patterns in large memory regions
- **DEP Bypass Detection**: Monitors VirtualProtect calls creating RWX pages
- **Stack Pivot Detection**: Compares RSP against legitimate TEB stack bounds
- **Shellcode Pattern Recognition**: GetProcAddress hashing, NOP sleds, PEB access

#### 3. **Advanced ETW Monitoring**
- **DNS Tunneling Detection**: Length analysis (>60 chars), DGA detection, suspicious TLDs
- **Network C2 Detection**: Malicious port tracking, private IP pivoting
- **Registry Persistence**: Monitors Run/RunOnce keys, service creation
- **WMI Lateral Movement**: Detects WMI process creation, reconnaissance queries
- **Thread Injection**: Tracks CreateRemoteThread across processes
- **Image Loads**: Flags DLLs from suspicious paths (mimikatz, pwdump)

#### 4. **Windows Filtering Platform (WFP) Network Monitor**
- **Kernel-Level Packet Inspection**: Superior to ETW for deep analysis
- **C2 Domain Detection**: Reverse DNS against known C2 domains (Telegram, Discord, pastebin)
- **Port-Based Blocking**: Flags connections to 4444, 5555, 6666, 31337, etc.
- **Tunneling Detection**: Identifies localhost connections on high ports

#### 5. **AMSI (Anti-Malware Scan Interface) Integration**
- **PowerShell/VBScript Scanning**: Real-time script analysis before execution
- **Obfuscation Detection**: Counts backticks, format strings, character joins
- **Base64 Execution Detection**: Flags FromBase64String + IEX patterns
- **AMSI Bypass Detection**: Identifies AmsiUtils, amsiInitFailed manipulation

### Operational Features
- **Windows Service**: Runs seamlessly in background as SYSTEM
- **Real-Time Monitoring**: Process creation, file operations, network connections
- **Automated Response**: Alert, quarantine, terminate, block
- **Machine Learning**: Adaptive learning from detections
- **Threat Correlation**: Links related events into attack chains
- **MITRE ATT&CK Mapping**: T1055, T1203, T1071, T1059.001, etc.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Vyron Agent Service                   │
├─────────────────────────────────────────────────────────┤
│  ┌───────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Monitoring  │  │  Detection   │  │   Response   │ │
│  │   (ETW/WMI)   │→ │   Engine     │→ │   Actions    │ │
│  └───────────────┘  └──────────────┘  └──────────────┘ │
│         ↓                   ↓                  ↓         │
│  ┌───────────────────────────────────────────────────┐  │
│  │          Event Store & Learning Pipeline          │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Project Structure

- **Vyron.Agent**: Windows Service host and main entry point
- **Vyron.Core**: Shared infrastructure (logging, config, models)
- **Vyron.Monitoring**: ETW/WMI monitors for process and file events
- **Vyron.Detection**: Multi-layer detection engine (signatures, behavior, ML)
- **Vyron.ML**: Machine learning training and inference pipeline
- **Vyron.Tests**: Comprehensive test suite

## Requirements

- Windows 10/11 or Windows Server 2019+
- .NET 8.0 or higher
- Administrator privileges (for ETW and service installation)

## Installation

```powershell
# Build the solution
dotnet build -c Release

# Install as Windows Service (run as Administrator)
.\scripts\install-service.ps1

# Start the service
Start-Service VyronAgent
```

## Configuration

Configuration is stored in `C:\ProgramData\Vyron\config.json`:

```json
{
  "DetectionLevel": "High",
  "MonitoringScope": "All",
  "AutoQuarantine": true,
  "LearningEnabled": true,
  "UpdateInterval": 3600
}
```

## Development

```powershell
# Restore dependencies
dotnet restore

# Build
dotnet build

# Run tests
dotnet test

# Run in development mode (console)
dotnet run --project src/Vyron.Agent -- --console
```

## Security Notice

This is an endpoint protection system designed for **defensive security purposes only**. Users must:
- Have proper authorization to deploy on target systems
- Comply with local privacy and data protection laws
- Use responsibly and ethically

## License

Copyright © 2026. All rights reserved.
