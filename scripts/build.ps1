# Build and publish Vyron Agent

param(
    [string]$Configuration = "Release",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$SolutionRoot = Split-Path -Parent $PSScriptRoot

Write-Host "Building Vyron Agent..." -ForegroundColor Green
Write-Host "Configuration: $Configuration"
Write-Host "Solution Root: $SolutionRoot"

# Restore dependencies
Write-Host "`nRestoring NuGet packages..." -ForegroundColor Cyan
dotnet restore "$SolutionRoot\Vyron.sln"

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to restore packages"
    exit 1
}

# Run tests (unless skipped)
if (-not $SkipTests) {
    Write-Host "`nRunning tests..." -ForegroundColor Cyan
    dotnet test "$SolutionRoot\Vyron.sln" --configuration $Configuration --no-restore
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Tests failed, but continuing with build..."
    }
}

# Build solution
Write-Host "`nBuilding solution..." -ForegroundColor Cyan
dotnet build "$SolutionRoot\Vyron.sln" --configuration $Configuration --no-restore

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}

# Publish Agent
Write-Host "`nPublishing Vyron.Agent..." -ForegroundColor Cyan
$agentProject = "$SolutionRoot\src\Vyron.Agent\Vyron.Agent.csproj"
$publishPath = "$SolutionRoot\src\Vyron.Agent\bin\$Configuration\net8.0-windows\publish"

dotnet publish $agentProject `
    --configuration $Configuration `
    --no-restore `
    --no-build `
    --output $publishPath

if ($LASTEXITCODE -ne 0) {
    Write-Error "Publish failed"
    exit 1
}

Write-Host "`n✓ Build completed successfully!" -ForegroundColor Green
Write-Host "Published to: $publishPath"
Write-Host "`nTo install the service, run (as Administrator):"
Write-Host "  .\scripts\install-service.ps1" -ForegroundColor Yellow
