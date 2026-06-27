# Vyron Quick Start Guide

## Installation (5 minutes)

### Step 1: Build the Project

```powershell
# Clone or navigate to the project
cd e:\Designs\Development\[Ai]\Vyron

# Build the solution
.\scripts\build.ps1
```

### Step 2: Install the Service

**Run PowerShell as Administrator**, then:

```powershell
.\scripts\install-service.ps1
```

The installer will:
- ✅ Create program and data directories
- ✅ Install the Windows Service
- ✅ Start protection automatically

### Step 3: Verify Installation

```powershell
.\scripts\manage-service.ps1 -Action Status
```

You should see:
```
Vyron Agent Status:
  Status: Running
  Startup Type: Automatic
  Display Name: Vyron Advanced Malware Detection Agent
```

## Basic Usage

### Monitor Real-Time Activity

```powershell
# Watch logs in real-time
.\scripts\manage-service.ps1 -Action Logs
```

### View Recent Detections

```powershell
# Check Windows Event Log
Get-EventLog -LogName Application -Source "Vyron" -Newest 10
```

### Check Quarantined Files

```powershell
# List quarantined items
Get-ChildItem C:\ProgramData\Vyron\Quarantine
```

### Adjust Sensitivity

Edit `C:\ProgramData\Vyron\config.json`:

```json
{
  "Detection": {
    "Level": "High",
    "MinimumConfidenceThreshold": 0.7
  }
}
```

Then restart:
```powershell
.\scripts\manage-service.ps1 -Action Restart
```

## Testing the System

### Test with EICAR File

⚠️ **Safe test file** - not real malware:

```powershell
# Create EICAR test file
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path "$env:TEMP\eicar-test.txt" -Value $eicar
```

Watch the logs - Vyron should detect and quarantine this file.

### Test with Suspicious Behavior

```powershell
# Simulate ransomware-like command (safe, won't actually delete)
Write-Host "Simulating suspicious command (not executed):"
Write-Host "powershell -nop -w hidden -enc SGVsbG8gV29ybGQ="
```

## Development Mode

To run in console mode for debugging:

```powershell
# Run as Administrator
.\scripts\run-dev.ps1 -Build
```

This runs Vyron in console mode with full output visible.

## Common Tasks

### Stop Protection Temporarily

```powershell
Stop-Service VyronAgent
```

### Start Protection

```powershell
Start-Service VyronAgent
```

### Update After Code Changes

```powershell
.\scripts\build.ps1
.\scripts\install-service.ps1 -Update
```

### Uninstall

```powershell
.\scripts\install-service.ps1 -Uninstall
```

## Key Directories

| Path | Purpose |
|------|---------|
| `C:\Program Files\Vyron` | Application binaries |
| `C:\ProgramData\Vyron\Data` | Detection database |
| `C:\ProgramData\Vyron\Logs` | Log files |
| `C:\ProgramData\Vyron\Quarantine` | Quarantined threats |
| `C:\ProgramData\Vyron\Rules` | Detection signatures |
| `C:\ProgramData\Vyron\Models` | ML models |

## Understanding Detections

When Vyron detects a threat, it logs:

- **Type**: Malware, Ransomware, Trojan, etc.
- **Severity**: Info, Low, Medium, High, Critical
- **Confidence**: 0-100% probability
- **Detection Method**: Signature, Behavioral, ML, Reputation
- **Action Taken**: Alert, Quarantine, Terminate

## Customization

### Add Trusted Applications

Edit `config.json`:

```json
{
  "Detection": {
    "TrustedProcesses": [
      "C:\\Program Files\\MyApp\\myapp.exe"
    ],
    "TrustedHashes": [
      "abc123def456..."
    ]
  }
}
```

### Monitor Specific Directories Only

```json
{
  "Monitoring": {
    "MonitoredPaths": [
      "C:\\Users",
      "C:\\ImportantData"
    ]
  }
}
```

### Adjust Auto-Response

```json
{
  "Response": {
    "AutoQuarantine": true,
    "AutoTerminateProcess": false,
    "MinimumSeverityForAutoResponse": "Critical"
  }
}
```

## Getting Help

### Check Service Status
```powershell
.\scripts\manage-service.ps1 -Action Status
```

### View Configuration
```powershell
.\scripts\manage-service.ps1 -Action Config
```

### Enable Debug Logging

Set minimum log level to Debug in `appsettings.json`:
```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Debug"
    }
  }
}
```

## Next Steps

- 📖 Read [DEVELOPMENT.md](docs/DEVELOPMENT.md) for architecture details
- 🚀 Read [DEPLOYMENT.md](docs/DEPLOYMENT.md) for production deployment
- 🔒 Read [SECURITY.md](docs/SECURITY.md) for security and compliance
- 🤖 Train ML models with labeled data
- ✍️ Create custom detection signatures
- 📊 Integrate with SIEM for centralized monitoring

## Troubleshooting

### Service won't start?
```powershell
# Check Event Log
Get-EventLog -LogName Application -Source "Vyron" -Newest 5

# Try console mode
cd "C:\Program Files\Vyron"
.\Vyron.Agent.exe --console
```

### Not detecting anything?
- Verify service is running
- Check detection threshold isn't too high
- Ensure ETW monitoring is active (requires Admin)
- View logs for initialization errors

### Too many false positives?
- Increase `MinimumConfidenceThreshold` to 0.8 or 0.9
- Add trusted applications to whitelist
- Reduce monitoring scope

---

**🎉 You're now protected by Vyron!**

The agent is actively monitoring your system and will alert you to any threats detected.
