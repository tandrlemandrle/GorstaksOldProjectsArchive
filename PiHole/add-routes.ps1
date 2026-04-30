#Requires -RunAsAdministrator
# add-routes.ps1 - Resolve domains from blocklist.txt and generate a .reg file with persistent routes
# Run: powershell -ExecutionPolicy Bypass -File add-routes.ps1
# Then import: regedit /s routes.reg

$blocklistFile = Join-Path $PSScriptRoot "blocklist.txt"
$regFile = Join-Path $PSScriptRoot "routes.reg"

if (-not (Test-Path $blocklistFile)) {
    Write-Host "blocklist.txt not found in $PSScriptRoot" -ForegroundColor Red
    exit 1
}

$domains = Get-Content $blocklistFile | Where-Object { $_ -and $_.Trim() -and -not $_.StartsWith('#') }
Write-Host "Resolving $($domains.Count) domains..." -ForegroundColor Cyan

$ips = @{}
$resolved = 0; $failed = 0

foreach ($domain in $domains) {
    $domain = $domain.Trim()
    if (-not $domain) { continue }
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($domain)
        foreach ($addr in $addrs) {
            if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                $ipStr = $addr.ToString()
                if (-not $ipStr.StartsWith('127.') -and -not $ipStr.StartsWith('10.') -and
                    -not $ipStr.StartsWith('192.168.') -and -not $ipStr.StartsWith('169.254.') -and
                    -not $ipStr.StartsWith('0.')) {
                    $ips[$ipStr] = $true
                }
            }
        }
        $resolved++
    } catch { $failed++ }

    if (($resolved + $failed) % 50 -eq 0) {
        Write-Host "  $($resolved + $failed) / $($domains.Count) ($($ips.Count) unique IPs)" -ForegroundColor Gray
    }
}

Write-Host "Resolved: $resolved, Failed: $failed, Unique IPs: $($ips.Count)" -ForegroundColor Cyan

# Generate .reg file
# Persistent routes registry key: HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes
# Format: "ip,mask,gateway,metric"=""

$lines = @()
$lines += 'Windows Registry Editor Version 5.00'
$lines += ''
$lines += '; Ceprkac Ad Blocker - Persistent Routes'
$lines += '; Generated: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$lines += "; Domains: $($domains.Count), Unique IPs: $($ips.Count)"
$lines += ''
$lines += '[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes]'

foreach ($ip in ($ips.Keys | Sort-Object)) {
    # Format: "destination,netmask,gateway,metric"=""
    $lines += """$ip,255.255.255.255,0.0.0.0,1""="""""
}

$lines | Out-File $regFile -Encoding ASCII
Write-Host ""
Write-Host "Generated $regFile with $($ips.Count) persistent routes." -ForegroundColor Green
Write-Host "Import with: regedit /s `"$regFile`"" -ForegroundColor Yellow
