# Vyron Installation Script
# Requires Administrator privileges

param(
    [switch]$Uninstall,
    [switch]$Update,
    [string]$ServiceName = "VyronAgent"
)

$ErrorActionPreference = "Stop"

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

$InstallPath = "C:\Program Files\Vyron"
$DataPath = "C:\ProgramData\Vyron"
$ServiceDisplayName = "Vyron Advanced Malware Detection Agent"
$ServiceDescription = "Provides real-time malware detection and protection using multi-layer analysis and machine learning"

function Install-VyronService {
    Write-Host "Installing Vyron Agent..." -ForegroundColor Green
    
    # Create installation directory
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }
    
    # Create data directories
    $dataDirs = @(
        $DataPath,
        "$DataPath\Data",
        "$DataPath\Logs",
        "$DataPath\Quarantine",
        "$DataPath\Models",
        "$DataPath\Rules"
    )
    
    foreach ($dir in $dataDirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "Created directory: $dir"
        }
    }
    
    # Copy binaries
    $publishPath = Join-Path $PSScriptRoot "..\src\Vyron.Agent\bin\Release\net8.0-windows\publish"
    
    if (-not (Test-Path $publishPath)) {
        Write-Error "Publish directory not found. Please build the solution first with: dotnet publish -c Release"
        exit 1
    }
    
    Write-Host "Copying binaries to $InstallPath..."
    Copy-Item -Path "$publishPath\*" -Destination $InstallPath -Recurse -Force
    
    # Install Windows Service
    $servicePath = Join-Path $InstallPath "Vyron.Agent.exe"
    
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "Service already exists. Stopping..."
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    } else {
        Write-Host "Creating Windows Service..."
        New-Service -Name $ServiceName `
                    -BinaryPathName $servicePath `
                    -DisplayName $ServiceDisplayName `
                    -Description $ServiceDescription `
                    -StartupType Automatic
    }
    
    # Configure service to restart on failure
    sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000
    
    # Start service
    Write-Host "Starting Vyron service..."
    Start-Service -Name $ServiceName
    
    # Verify service is running
    Start-Sleep -Seconds 3
    $service = Get-Service -Name $ServiceName
    
    if ($service.Status -eq "Running") {
        Write-Host "`nVyron Agent installed successfully!" -ForegroundColor Green
        Write-Host "Service Status: $($service.Status)"
        Write-Host "Installation Path: $InstallPath"
        Write-Host "Data Path: $DataPath"
        Write-Host "`nConfiguration file: $DataPath\config.json"
        Write-Host "Logs: $DataPath\Logs"
    } else {
        Write-Warning "Service installed but not running. Status: $($service.Status)"
        Write-Warning "Check event log for errors: Get-EventLog -LogName Application -Source Vyron -Newest 10"
    }
}

function Uninstall-VyronService {
    Write-Host "Uninstalling Vyron Agent..." -ForegroundColor Yellow
    
    # Stop service
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "Stopping service..."
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
        
        Write-Host "Removing service..."
        sc.exe delete $ServiceName
    }
    
    # Remove installation directory
    if (Test-Path $InstallPath) {
        Write-Host "Removing installation files..."
        Remove-Item -Path $InstallPath -Recurse -Force
    }
    
    # Ask about data
    $removeData = Read-Host "Remove data and configuration? (Y/N)"
    if ($removeData -eq "Y" -or $removeData -eq "y") {
        if (Test-Path $DataPath) {
            Write-Host "Removing data directory..."
            Remove-Item -Path $DataPath -Recurse -Force
        }
    }
    
    Write-Host "`nVyron Agent uninstalled successfully!" -ForegroundColor Green
}

function Update-VyronService {
    Write-Host "Updating Vyron Agent..." -ForegroundColor Cyan
    
    # Stop service
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "Stopping service..."
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    
    # Update binaries
    $publishPath = Join-Path $PSScriptRoot "..\src\Vyron.Agent\bin\Release\net8.0-windows\publish"
    
    if (-not (Test-Path $publishPath)) {
        Write-Error "Publish directory not found. Please build the solution first."
        exit 1
    }
    
    Write-Host "Updating binaries..."
    Copy-Item -Path "$publishPath\*" -Destination $InstallPath -Recurse -Force
    
    # Start service
    Write-Host "Starting service..."
    Start-Service -Name $ServiceName
    
    Write-Host "`nVyron Agent updated successfully!" -ForegroundColor Green
}

# Main execution
Write-Host @"
╔═══════════════════════════════════════════════════╗
║   Vyron Advanced Malware Detection Agent          ║
║   Installation & Management Script                ║
╚═══════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

if ($Uninstall) {
    Uninstall-VyronService
} elseif ($Update) {
    Update-VyronService
} else {
    Install-VyronService
}

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
