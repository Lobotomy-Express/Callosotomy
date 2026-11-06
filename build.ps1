#Requires -Version 5.1
<#
.SYNOPSIS
  Tests, publishes and packages Callosotomy into an MSI.
.EXAMPLE
  .\build.ps1                 # Release build + MSI in .\artifacts
  .\build.ps1 -SkipInstaller  # just the published binaries
#>
param(
    [string]$Configuration = 'Release',
    [switch]$SkipInstaller
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$publish = Join-Path $PSScriptRoot 'artifacts\publish'
if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }

dotnet test tests\Callosotomy.Core.Tests -c $Configuration
if ($LASTEXITCODE) { throw 'Tests failed' }

# Both apps publish self-contained into one folder so they share a single copy of the runtime.
foreach ($proj in 'src\Callosotomy.Service', 'src\Callosotomy.Tray') {
    dotnet publish $proj -c $Configuration -r win-x64 --self-contained true -o $publish `
        -p:DebugType=none -p:PublishReadyToRun=true
    if ($LASTEXITCODE) { throw "Publish failed: $proj" }
}

if (-not $SkipInstaller) {
    $version = ([xml](Get-Content Directory.Build.props)).Project.PropertyGroup.Version
    dotnet build installer\Callosotomy.Installer.wixproj -c $Configuration -p:Version=$version -p:PublishDir=$publish -o artifacts
    if ($LASTEXITCODE) { throw 'Installer build failed' }
}

Write-Host "Done. Output in $(Join-Path $PSScriptRoot 'artifacts')" -ForegroundColor Green
