#Requires -Version 5.1
<#
.SYNOPSIS
    GPrep Helper - OS-aware software installer. Works with GPrep.cpl / GPrepUI.hta.
.DESCRIPTION
    Installs selected software based on manifest.json.
    - Modern (Win10+): Uses winget, chocolatey
    - Legacy (Win7/8): Uses direct download URLs from manifest
#>

param(
    [string[]]$AppIds = @(),
    [string]$ManifestPath,
    [switch]$SkipAdminCheck
)

# Support comma-separated string from HTA
if ($AppIds.Count -eq 1 -and $AppIds[0] -match ',') {
    $AppIds = $AppIds[0] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

$ErrorActionPreference = "Stop"
$host.ui.RawUI.BackgroundColor = "Black"
$host.ui.RawUI.ForegroundColor = "White"

function Get-OSVersion {
    $os = Get-WmiObject Win32_OperatingSystem
    $version = [version]$os.Version
    return @{
        Major = $version.Major
        Minor = $version.Minor
        Build = $version.Build
        IsLegacy = ($version.Major -lt 10)
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ScriptDirectory {
    $invocation = (Get-Variable MyInvocation -Scope 1).Value
    return Split-Path $invocation.MyCommand.Path
}

function Get-ManifestPath {
    if ($ManifestPath -and (Test-Path $ManifestPath)) { return $ManifestPath }
    $scriptDir = Get-ScriptDirectory
    $candidates = @(
        Join-Path $scriptDir "manifest.json",
        Join-Path (Split-Path $scriptDir) "manifest.json"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    throw "manifest.json not found"
}

if (-not $SkipAdminCheck -and -not (Test-Administrator)) {
    Start-Process powershell -Verb runAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -AppIds $($AppIds -join ',') -SkipAdminCheck"
    exit
}

$manifestPath = Get-ManifestPath
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$osInfo = Get-OSVersion

Write-Host "GPrep Helper - OS-aware installer" -ForegroundColor Cyan
Write-Host "OS: Windows $($osInfo.Major).$($osInfo.Minor) (Legacy mode: $($osInfo.IsLegacy))" -ForegroundColor Gray

if ($AppIds.Count -eq 0) {
    Write-Host "No apps selected. Exiting." -ForegroundColor Yellow
    exit 0
}

$selected = $manifest.apps | Where-Object { $AppIds -contains $_.id }
$legacyOnly = $selected | Where-Object { $_.legacy -ne $null }
$modernOnly = $selected | Where-Object { $null -ne $_.modern -and $_.legacy -eq $null }
$universal = $selected | Where-Object { $null -ne $_.modern -and $null -ne $_.legacy }

if ($osInfo.IsLegacy) {
    $toInstall = $selected | Where-Object { $_.legacy -ne $null }
    $skipped = $selected | Where-Object { $_.legacy -eq $null }
} else {
    $toInstall = $selected
    $skipped = @()
}

foreach ($app in $skipped) {
    Write-Host "[SKIP] $($app.name) - no Legacy (Win7) support" -ForegroundColor Yellow
}

$tempDir = Join-Path $env:TEMP "GPrepInstall"
if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }

foreach ($app in $toInstall) {
    Write-Host "`n[$($app.name)]" -ForegroundColor Cyan
    try {
        if ($osInfo.IsLegacy) {
            $cfg = $app.legacy
            if ($cfg.choco) {
                if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                    Write-Host "  Installing Chocolatey..." -ForegroundColor Yellow
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                }
                Write-Host "  Using Chocolatey: $($cfg.choco)" -ForegroundColor Gray
                choco install $cfg.choco -y --no-progress
            } else {
                $url = $cfg.url
                $outFile = Join-Path $tempDir $cfg.filename
                Write-Host "  Downloading from $url ..." -ForegroundColor Gray
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing -ErrorAction Stop
                Write-Host "  Running installer..." -ForegroundColor Gray
                if ($cfg.isZip) {
                    Expand-Archive -Path $outFile -DestinationPath (Join-Path $tempDir $app.id) -Force
                    $exe = Get-ChildItem -Path (Join-Path $tempDir $app.id) -Filter "*.exe" -Recurse | Select-Object -First 1
                    if ($exe) { Start-Process -FilePath $exe.FullName -Wait }
                } elseif ($outFile -match '\.msi$') {
                    Start-Process msiexec.exe -ArgumentList "/i", $outFile, "/qn" -Wait
                } else {
                    Start-Process -FilePath $outFile -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
                    if ($LASTEXITCODE -ne 0) { Start-Process -FilePath $outFile -Wait }
                }
            }
        } else {
            $cfg = $app.modern
            if ($cfg.winget) {
                Write-Host "  Using winget: $($cfg.winget)" -ForegroundColor Gray
                winget install -e --id $cfg.winget --accept-package-agreements --accept-source-agreements --disable-interactivity -h 2>&1
            } elseif ($cfg.choco) {
                if (Get-Command choco -ErrorAction SilentlyContinue) {
                    Write-Host "  Using Chocolatey: $($cfg.choco)" -ForegroundColor Gray
                    choco install $cfg.choco -y --no-progress
                } else {
                    Write-Host "  Chocolatey not installed. Installing..." -ForegroundColor Yellow
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                    choco install $cfg.choco -y --no-progress
                }
            } elseif ($cfg.url) {
                $fn = if ($cfg.filename) { $cfg.filename } else { "installer.exe" }
                $outFile = Join-Path $tempDir $fn
                Invoke-WebRequest -Uri $cfg.url -OutFile $outFile -UseBasicParsing
                Start-Process -FilePath $outFile -Wait
            }
        }
        Write-Host "  Done." -ForegroundColor Green
    } catch {
        Write-Host "  Error: $_" -ForegroundColor Red
    }
}

Write-Host "`nGPrep installation completed." -ForegroundColor Green
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
