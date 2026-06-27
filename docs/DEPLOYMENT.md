# Vyron Deployment Guide

## System Requirements

### Minimum Requirements
- **OS**: Windows 10 (1809+) or Windows Server 2019+
- **RAM**: 2 GB
- **Disk**: 500 MB for installation + 5 GB for data
- **CPU**: 2 cores
- **.NET Runtime**: .NET 8.0 Runtime (included in installer)

### Recommended Requirements
- **OS**: Windows 11 or Windows Server 2022
- **RAM**: 4 GB
- **Disk**: 1 GB + 10 GB for data and quarantine
- **CPU**: 4 cores
- **Privileges**: Administrator rights for installation

## Installation

### Option 1: Automated Installation (Recommended)

1. **Build the solution**
   ```powershell
   .\scripts\build.ps1 -Configuration Release
   ```

2. **Run installer as Administrator**
   ```powershell
   .\scripts\install-service.ps1
   ```

The installer will:
- Create installation directory at `C:\Program Files\Vyron`
- Create data directories at `C:\ProgramData\Vyron`
- Install and start the Windows Service
- Configure automatic restart on failure

### Option 2: Manual Installation

1. **Publish the application**
   ```powershell
   dotnet publish src\Vyron.Agent\Vyron.Agent.csproj -c Release -o C:\Vyron
   ```

2. **Create data directories**
   ```powershell
   New-Item -ItemType Directory -Path "C:\ProgramData\Vyron\Data" -Force
   New-Item -ItemType Directory -Path "C:\ProgramData\Vyron\Logs" -Force
   New-Item -ItemType Directory -Path "C:\ProgramData\Vyron\Quarantine" -Force
   New-Item -ItemType Directory -Path "C:\ProgramData\Vyron\Rules" -Force
   New-Item -ItemType Directory -Path "C:\ProgramData\Vyron\Models" -Force
   ```

3. **Install Windows Service**
   ```powershell
   New-Service -Name "VyronAgent" `
               -BinaryPathName "C:\Vyron\Vyron.Agent.exe" `
               -DisplayName "Vyron Advanced Malware Detection Agent" `
               -StartupType Automatic
   ```

4. **Start the service**
   ```powershell
   Start-Service VyronAgent
   ```

## Configuration

### Initial Configuration

After installation, edit `C:\ProgramData\Vyron\config.json`:

```json
{
  "Detection": {
    "Level": "High",
    "MinimumConfidenceThreshold": 0.7
  },
  "Monitoring": {
    "MonitoredPaths": [
      "C:\\Users",
      "C:\\Program Files",
      "C:\\Program Files (x86)"
    ]
  },
  "Response": {
    "AutoQuarantine": true,
    "AutoTerminateProcess": true,
    "MinimumSeverityForAutoResponse": "High"
  }
}
```

Restart the service after configuration changes:
```powershell
.\scripts\manage-service.ps1 -Action Restart
```

### Detection Level Presets

**Low (Development/Testing)**
```json
{
  "Detection": {
    "Level": "Low",
    "MinimumConfidenceThreshold": 0.9
  }
}
```

**Medium (Standard Protection)**
```json
{
  "Detection": {
    "Level": "Medium",
    "MinimumConfidenceThreshold": 0.7
  }
}
```

**High (Recommended)**
```json
{
  "Detection": {
    "Level": "High",
    "MinimumConfidenceThreshold": 0.6
  }
}
```

**Paranoid (Maximum Security)**
```json
{
  "Detection": {
    "Level": "Paranoid",
    "MinimumConfidenceThreshold": 0.5
  }
}
```

## Updating

### Update Procedure

1. **Stop the service**
   ```powershell
   Stop-Service VyronAgent
   ```

2. **Backup configuration**
   ```powershell
   Copy-Item C:\ProgramData\Vyron\config.json C:\ProgramData\Vyron\config.json.backup
   ```

3. **Run update script**
   ```powershell
   .\scripts\install-service.ps1 -Update
   ```

Or use the automated update:
```powershell
.\scripts\build.ps1 -Configuration Release
.\scripts\install-service.ps1 -Update
```

## Monitoring and Management

### Check Service Status

```powershell
.\scripts\manage-service.ps1 -Action Status
```

### View Logs

```powershell
# Real-time log viewing
.\scripts\manage-service.ps1 -Action Logs

# Or manually
Get-Content C:\ProgramData\Vyron\Logs\vyron-*.log -Tail 100
```

### View Event Log

```powershell
Get-EventLog -LogName Application -Source "Vyron" -Newest 50 | Format-Table -AutoSize
```

### Check Quarantined Files

```powershell
Get-ChildItem C:\ProgramData\Vyron\Quarantine
Get-Content C:\ProgramData\Vyron\Quarantine\metadata.json | ConvertFrom-Json
```

### Service Management

```powershell
# Start
Start-Service VyronAgent

# Stop
Stop-Service VyronAgent

# Restart
Restart-Service VyronAgent

# Or use helper script
.\scripts\manage-service.ps1 -Action Restart
```

## Performance Tuning

### Reduce Monitoring Overhead

Limit monitored paths to critical directories:
```json
{
  "Monitoring": {
    "MonitoredPaths": [
      "C:\\Users",
      "C:\\Windows\\System32"
    ],
    "ExcludedPaths": [
      "C:\\Windows\\Temp",
      "C:\\Windows\\SoftwareDistribution"
    ]
  }
}
```

### Optimize File Scanning

Only monitor high-risk extensions:
```json
{
  "Monitoring": {
    "HighPriorityExtensions": [".exe", ".dll", ".ps1", ".vbs", ".js"]
  }
}
```

### Disable Optional Features

```json
{
  "Detection": {
    "EnableMLDetection": false,
    "EnableReputationCheck": false
  }
}
```

## Security Hardening

### 1. Restrict Configuration Access

```powershell
# Allow only SYSTEM and Administrators
icacls "C:\ProgramData\Vyron\config.json" /inheritance:r
icacls "C:\ProgramData\Vyron\config.json" /grant:r "SYSTEM:(F)"
icacls "C:\ProgramData\Vyron\config.json" /grant:r "Administrators:(F)"
```

### 2. Protect Quarantine Directory

```powershell
icacls "C:\ProgramData\Vyron\Quarantine" /inheritance:r
icacls "C:\ProgramData\Vyron\Quarantine" /grant:r "SYSTEM:(OI)(CI)(F)"
icacls "C:\ProgramData\Vyron\Quarantine" /grant:r "Administrators:(OI)(CI)(F)"
```

### 3. Enable Audit Logging

```json
{
  "Response": {
    "EnableEventLog": true,
    "EnableNotifications": true
  }
}
```

### 4. Service Recovery

Configure service to restart on failure (done automatically by installer):
```powershell
sc.exe failure VyronAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000
```

## Uninstallation

### Complete Removal

```powershell
.\scripts\install-service.ps1 -Uninstall
```

This will:
1. Stop and remove the service
2. Delete installation files
3. Optionally remove data and configuration

### Manual Uninstall

```powershell
# Stop and remove service
Stop-Service VyronAgent
sc.exe delete VyronAgent

# Remove files
Remove-Item "C:\Program Files\Vyron" -Recurse -Force
Remove-Item "C:\ProgramData\Vyron" -Recurse -Force
```

## Troubleshooting

### Service Won't Start

1. **Check Event Log**
   ```powershell
   Get-EventLog -LogName Application -Source "Vyron" -Newest 10
   ```

2. **Verify Permissions**
   ```powershell
   whoami /user
   icacls "C:\Program Files\Vyron"
   icacls "C:\ProgramData\Vyron"
   ```

3. **Test Console Mode**
   ```powershell
   cd "C:\Program Files\Vyron"
   .\Vyron.Agent.exe --console
   ```

### High CPU Usage

- Reduce monitored paths
- Disable real-time ML detection
- Check for recursive file monitoring

### False Positives

- Increase `MinimumConfidenceThreshold`
- Add trusted applications to whitelist
- Review detection reasons in logs

### ETW Monitoring Unavailable

- Service must run with Administrator privileges
- Check for conflicting ETW sessions
- Fallback to WMI monitoring is automatic

## Enterprise Deployment

### Group Policy Deployment

1. Create MSI installer (future enhancement)
2. Deploy via GPO
3. Configure via GPO preferences

### Configuration Management

Use configuration management tools (Ansible, Puppet, etc.):

```yaml
# Ansible example
- name: Deploy Vyron config
  win_copy:
    src: vyron-config.json
    dest: C:\ProgramData\Vyron\config.json
  
- name: Restart Vyron
  win_service:
    name: VyronAgent
    state: restarted
```

### Centralized Monitoring

Export logs to SIEM:
- Forward Windows Event Logs
- Parse Vyron log files
- Monitor threat detection rates

## Support

For issues and questions:
- Check logs: `C:\ProgramData\Vyron\Logs`
- Review Event Log: Application → Vyron
- Enable debug logging in configuration
