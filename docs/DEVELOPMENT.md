# Vyron Development Guide

## Getting Started

### Prerequisites

- Windows 10/11 or Windows Server 2019+
- .NET 8.0 SDK or higher
- Visual Studio 2022 or VS Code
- Administrator privileges (for ETW monitoring and service installation)

### Setting Up Development Environment

1. **Clone the repository**
   ```powershell
   git clone <repository-url>
   cd Vyron
   ```

2. **Restore dependencies**
   ```powershell
   dotnet restore
   ```

3. **Build the solution**
   ```powershell
   dotnet build
   ```

4. **Run tests**
   ```powershell
   dotnet test
   ```

## Project Structure

```
Vyron/
├── src/
│   ├── Vyron.Agent/         # Windows Service host
│   ├── Vyron.Core/          # Shared models, config, services
│   ├── Vyron.Monitoring/    # ETW/WMI process & file monitoring
│   ├── Vyron.Detection/     # Multi-layer detection engine
│   └── Vyron.ML/            # Machine learning pipeline
├── tests/
│   └── Vyron.Tests/         # Unit and integration tests
├── scripts/                 # PowerShell management scripts
└── docs/                    # Documentation
```

## Architecture Overview

### Components

1. **Agent Service** (`Vyron.Agent`)
   - Windows Service host
   - Orchestrates all components
   - Manages lifecycle and configuration

2. **Monitoring Layer** (`Vyron.Monitoring`)
   - **ProcessMonitorService**: ETW-based process monitoring with WMI fallback
   - **FileMonitorService**: FileSystemWatcher for file system events
   - Filters high-priority files and processes

3. **Detection Engine** (`Vyron.Detection`)
   - **SignatureScanner**: YARA-like signature matching
   - **BehavioralAnalyzer**: Heuristic analysis of process behavior
   - **ReputationService**: File hash and reputation checking
   - **DetectionEngine**: Orchestrates all detection methods

4. **Response System** (`Vyron.Detection`)
   - **QuarantineService**: Secure file quarantine
   - **ResponseOrchestrator**: Automated threat response (alert, terminate, quarantine)

5. **Learning Pipeline** (`Vyron.ML`)
   - **MachineLearningService**: ML.NET-based model training and inference
   - **LearningOrchestrator**: Feedback loop and model retraining

## Running in Development Mode

### Console Mode (Recommended for Development)

```powershell
# Run with automatic build
.\scripts\run-dev.ps1 -Build

# Or run directly
dotnet run --project src\Vyron.Agent -- --console
```

**Important**: Run PowerShell as Administrator for full ETW monitoring capabilities.

### Service Mode

```powershell
# Build and publish
.\scripts\build.ps1

# Install as service (requires Admin)
.\scripts\install-service.ps1

# Manage service
.\scripts\manage-service.ps1 -Action Status
.\scripts\manage-service.ps1 -Action Restart
.\scripts\manage-service.ps1 -Action Logs
```

## Configuration

Configuration file: `C:\ProgramData\Vyron\config.json`

Key settings:

```json
{
  "Detection": {
    "Level": "High",
    "MinimumConfidenceThreshold": 0.7,
    "EnableSignatureDetection": true,
    "EnableBehavioralDetection": true,
    "EnableMLDetection": true,
    "EnableReputationCheck": true
  },
  "Monitoring": {
    "EnableProcessMonitoring": true,
    "EnableFileMonitoring": true,
    "MonitoredPaths": ["C:\\Users", "C:\\Program Files"],
    "HighPriorityExtensions": [".exe", ".dll", ".ps1"]
  },
  "Response": {
    "AutoQuarantine": true,
    "AutoTerminateProcess": true,
    "MinimumSeverityForAutoResponse": "High"
  },
  "Learning": {
    "Enabled": true,
    "StoreTrainingData": true,
    "AutoRetrain": false
  }
}
```

## Adding Custom Detection Rules

### YARA-like Signatures

Create rule files in `C:\ProgramData\Vyron\rules\*.rule`:

```
# Format: RuleName|Pattern|Type
Ransomware_Example|vssadmin.*delete.*shadows|Ransomware
Trojan_Example|mimikatz|sekurlsa|Trojan
```

### Behavioral Heuristics

Extend `BehavioralAnalyzer.cs`:

```csharp
private bool IsNewSuspiciousBehavior(ProcessEvent processEvent)
{
    // Add custom heuristic logic
    return false;
}
```

### Custom ML Features

Add features to `ThreatTrainingData.cs`:

```csharp
[LoadColumn(21)]
public bool CustomFeature { get; set; }
```

Update feature extraction in `MachineLearningService.cs`.

## Machine Learning Workflow

### 1. Collect Training Data

Threat events are automatically stored in `C:\ProgramData\Vyron\Data\threats\`

### 2. Label Events

```csharp
var learningOrchestrator = serviceProvider.GetRequiredService<LearningOrchestrator>();
await learningOrchestrator.RecordFeedbackAsync(threatId, isTruePositive: true);
```

### 3. Retrain Model

```powershell
# Via API or directly
var mlService = serviceProvider.GetRequiredService<MachineLearningService>();
await mlService.TrainModelAsync(labeledEvents);
```

### 4. Deploy Model

Models are automatically loaded from `C:\ProgramData\Vyron\Models\threat_detection.zip`

## Testing

### Unit Tests

```powershell
dotnet test --configuration Debug --logger "console;verbosity=detailed"
```

### Integration Testing

1. Run in console mode with test workload
2. Generate benign and malicious processes
3. Verify detections in logs

### Test Malware Samples

⚠️ **NEVER use real malware**. Use EICAR test files or custom benign test patterns.

```powershell
# EICAR test file (standard antivirus test string)
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path "C:\temp\eicar.txt" -Value $eicar
```

## Debugging

### Attach Debugger

1. In Visual Studio: Debug → Attach to Process → Select `Vyron.Agent.exe`
2. Set breakpoints in detection logic

### View Logs

```powershell
# Real-time log viewing
.\scripts\manage-service.ps1 -Action Logs

# Or manually
Get-Content C:\ProgramData\Vyron\Logs\vyron-*.log -Tail 50 -Wait
```

### Event Log

```powershell
Get-EventLog -LogName Application -Source "Vyron" -Newest 20
```

## Performance Considerations

- **ETW Monitoring**: Low overhead (<2% CPU), requires Admin
- **File Monitoring**: Use targeted paths and extensions
- **Signature Scanning**: Only scan high-priority files
- **ML Inference**: Fast (<10ms per prediction)

## Security Best Practices

1. **Service Account**: Run as LocalSystem (default) or dedicated service account
2. **Quarantine Protection**: Quarantine directory has restricted ACLs
3. **Configuration Protection**: Protect config file with appropriate permissions
4. **Audit Logging**: All actions logged to Event Log and file
5. **Self-Protection**: Service marked as critical (optional)

## Contributing

1. Create feature branch
2. Implement with tests
3. Run full test suite
4. Update documentation
5. Submit PR

## Troubleshooting

### ETW Monitoring Not Working

- Ensure running as Administrator
- Check Event Log for access denied errors
- Fallback to WMI monitoring is automatic

### Service Won't Start

```powershell
# Check event log
Get-EventLog -LogName Application -Source "Vyron" -Newest 5

# Verify permissions on data directories
icacls C:\ProgramData\Vyron
```

### False Positives

- Adjust `MinimumConfidenceThreshold` in config
- Add trusted processes to whitelist
- Review and label detections for ML training

## Additional Resources

- [ML.NET Documentation](https://docs.microsoft.com/en-us/dotnet/machine-learning/)
- [ETW Tracing](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [Windows Service Development](https://docs.microsoft.com/en-us/dotnet/core/extensions/windows-service)
