# Manage Vyron service

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Status", "Start", "Stop", "Restart", "Logs", "Config")]
    [string]$Action
)

$ServiceName = "VyronAgent"
$DataPath = "C:\ProgramData\Vyron"

function Get-VyronStatus {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if ($null -eq $service) {
        Write-Host "Vyron service is not installed" -ForegroundColor Red
        return
    }
    
    Write-Host "`nVyron Agent Status:" -ForegroundColor Cyan
    Write-Host "  Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq "Running") { "Green" } else { "Yellow" })
    Write-Host "  Startup Type: $($service.StartType)"
    Write-Host "  Display Name: $($service.DisplayName)"
    
    # Get process info if running
    if ($service.Status -eq "Running") {
        $process = Get-Process -Name "Vyron.Agent" -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "  Process ID: $($process.Id)"
            Write-Host "  Memory Usage: $([math]::Round($process.WorkingSet64 / 1MB, 2)) MB"
            Write-Host "  CPU Time: $($process.TotalProcessorTime.ToString('hh\:mm\:ss'))"
        }
    }
    
    # Show recent log entries
    Write-Host "`nRecent Events:" -ForegroundColor Cyan
    Get-EventLog -LogName Application -Source "Vyron" -Newest 5 -ErrorAction SilentlyContinue | 
        Format-Table TimeGenerated, EntryType, Message -AutoSize
}

function Start-VyronService {
    Write-Host "Starting Vyron service..." -ForegroundColor Green
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2
    Get-VyronStatus
}

function Stop-VyronService {
    Write-Host "Stopping Vyron service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force
    Write-Host "Service stopped" -ForegroundColor Green
}

function Restart-VyronService {
    Stop-VyronService
    Start-Sleep -Seconds 2
    Start-VyronService
}

function Show-VyronLogs {
    $logPath = Join-Path $DataPath "Logs"
    
    if (-not (Test-Path $logPath)) {
        Write-Host "Log directory not found: $logPath" -ForegroundColor Red
        return
    }
    
    $latestLog = Get-ChildItem -Path $logPath -Filter "*.log" | 
                 Sort-Object LastWriteTime -Descending | 
                 Select-Object -First 1
    
    if ($null -eq $latestLog) {
        Write-Host "No log files found" -ForegroundColor Yellow
        return
    }
    
    Write-Host "`nShowing latest log: $($latestLog.Name)" -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop`n" -ForegroundColor Yellow
    
    Get-Content -Path $latestLog.FullName -Tail 50 -Wait
}

function Show-VyronConfig {
    $configPath = Join-Path $DataPath "config.json"
    
    if (-not (Test-Path $configPath)) {
        Write-Host "Configuration file not found: $configPath" -ForegroundColor Red
        return
    }
    
    Write-Host "`nCurrent Configuration:" -ForegroundColor Cyan
    Get-Content -Path $configPath | ConvertFrom-Json | ConvertTo-Json -Depth 10
    
    Write-Host "`nConfig file location: $configPath" -ForegroundColor Gray
    Write-Host "Edit the file and restart the service to apply changes" -ForegroundColor Yellow
}

# Execute requested action
switch ($Action) {
    "Status" { Get-VyronStatus }
    "Start" { Start-VyronService }
    "Stop" { Stop-VyronService }
    "Restart" { Restart-VyronService }
    "Logs" { Show-VyronLogs }
    "Config" { Show-VyronConfig }
}
