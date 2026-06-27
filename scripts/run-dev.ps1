# Development helper script - Run Vyron in console mode

param(
    [switch]$Build
)

$ErrorActionPreference = "Stop"
$SolutionRoot = Split-Path -Parent $PSScriptRoot

if ($Build) {
    Write-Host "Building solution..." -ForegroundColor Cyan
    dotnet build "$SolutionRoot\Vyron.sln" --configuration Debug
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed"
        exit 1
    }
}

Write-Host @"
╔═══════════════════════════════════════════════════╗
║   Vyron Agent - Development Console Mode          ║
║   Press Ctrl+C to stop                            ║
╚═══════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "Not running as Administrator. ETW monitoring will not be available."
    Write-Warning "Restart PowerShell as Administrator for full functionality."
}

Write-Host "`nStarting Vyron Agent in console mode...`n" -ForegroundColor Green

# Run in console mode
dotnet run --project "$SolutionRoot\src\Vyron.Agent\Vyron.Agent.csproj" -- --console
