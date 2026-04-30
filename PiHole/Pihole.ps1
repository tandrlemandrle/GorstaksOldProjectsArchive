#Requires -RunAsAdministrator
# Pihole.ps1 - System-wide ad blocker for Windows using permanent routes
# Resolves ad/tracker domains to IPs and blocks them via "route add -p"
# Always additive — never removes existing routes.

param (
    [int]$MaxDomains = 0
)

# Configuration
$FilterLists = @(
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://filters.adtidy.org/windows/filters/2.txt"
)
# Malware/botnet IP blocklists (from IPBlock project)
$ThreatIPLists = @(
    "https://www.spamhaus.org/drop/drop.lasso",
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "http://cinsscore.com/list/ci-badguys.txt",
    "https://www.talosintelligence.com/documents/ip-blacklist",
    "https://iplists.firehol.org/files/firehol_level3.netset"
)
$LogFile = "$env:TEMP\PiHole.log"
$CacheFile = Join-Path $PSScriptRoot "route-cache.txt"

function Write-Log {
    param ($Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    Add-Content -Path $LogFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "White" } }
    Write-Host $entry -ForegroundColor $color
}

# Download and parse filter lists for domains
function Get-BlockedDomains {
    Write-Log "Downloading filter lists..."
    $domains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($url in $FilterLists) {
        Write-Log "Downloading: $url"
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            $lines = $response.Content -split "`n"
            $count = 0
            foreach ($line in $lines) {
                if ($line -match "^\|\|([a-zA-Z0-9][\w\.\-]+\.[a-zA-Z]{2,})\^") {
                    $domain = $Matches[1].Trim()
                    if ($domain -and -not $domain.Contains('/') -and -not $domain.Contains('*')) {
                        $domains.Add($domain) | Out-Null
                        $count++
                    }
                }
            }
            Write-Log "Extracted $count domains from $url"
        } catch {
            Write-Log "Failed to download ${url}: $_" "ERROR"
        }
    }

    Write-Log "Total unique domains: $($domains.Count)"
    return $domains
}

# Get IPs already in persistent routes (IPv4 + IPv6 from cache)
function Get-ExistingRouteIPs {
    $existing = @{}
    # IPv4 from route print
    try {
        $output = & route print 2>&1
        foreach ($line in $output) {
            if ($line -match "^\s*(\d+\.\d+\.\d+\.\d+)\s+255\.255\.255\.255\s+0\.0\.0\.0") {
                $existing[$Matches[1]] = $true
            }
        }
    } catch {}
    # Both IPv4 and IPv6 from cache file
    if (Test-Path $CacheFile) {
        foreach ($ip in (Get-Content $CacheFile -ErrorAction SilentlyContinue)) {
            $ip = $ip.Trim()
            if ($ip) { $existing[$ip] = $true }
        }
    }
    return $existing
}

# Resolve domains to IPs — skips domains already routed via DNS cache
function Resolve-DomainsToIPs {
    param ([System.Collections.Generic.HashSet[string]]$Domains)

    $existingIPs = Get-ExistingRouteIPs
    Write-Log "Found $($existingIPs.Count) IPs already in persistent routes."

    # Load DNS cache
    $dnsCache = @{}
    $dnsCacheFile = Join-Path $PSScriptRoot "dns-cache.txt"
    if (Test-Path $dnsCacheFile) {
        foreach ($line in (Get-Content $dnsCacheFile -ErrorAction SilentlyContinue)) {
            $parts = $line.Split('=', 2)
            if ($parts.Count -eq 2) { $dnsCache[$parts[0]] = $parts[1] }
        }
        Write-Log "DNS cache loaded: $($dnsCache.Count) entries."
    }

    $domainList = @($Domains)
    if ($MaxDomains -gt 0 -and $domainList.Count -gt $MaxDomains) {
        Write-Log "Limiting to first $MaxDomains domains"
        $domainList = $domainList | Select-Object -First $MaxDomains
    }

    $total = $domainList.Count
    $newIPs = @{}
    $skipped = 0; $cached = 0; $resolved = 0; $failed = 0

    for ($i = 0; $i -lt $total; $i++) {
        $domain = $domainList[$i]

        if ($dnsCache.ContainsKey($domain)) {
            # Domain already resolved before — check if IPs are already routed
            $cachedIPs = $dnsCache[$domain].Split(',') | Where-Object { $_ }
            $allRouted = $true
            foreach ($cip in $cachedIPs) {
                if (-not $existingIPs.ContainsKey($cip)) {
                    $newIPs[$cip] = $true
                    $allRouted = $false
                }
            }
            if ($allRouted) { $skipped++ } else { $cached++ }
        } else {
            # Fresh DNS resolution — both IPv4 and IPv6
            $domainIPs = @()
            try {
                $addrs = [System.Net.Dns]::GetHostAddresses($domain)
                foreach ($addr in $addrs) {
                    $ipStr = $addr.ToString()
                    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                        # IPv4 — skip private/loopback
                        if (-not $ipStr.StartsWith("127.") -and -not $ipStr.StartsWith("10.") -and
                            -not $ipStr.StartsWith("192.168.") -and -not $ipStr.StartsWith("169.254.") -and
                            -not $ipStr.StartsWith("0.")) {
                            $domainIPs += $ipStr
                            if (-not $existingIPs.ContainsKey($ipStr)) { $newIPs[$ipStr] = $true }
                        }
                    }
                    elseif ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                        # IPv6 — skip loopback (::1) and link-local (fe80::)
                        if ($ipStr -ne "::1" -and -not $ipStr.StartsWith("fe80:")) {
                            $domainIPs += $ipStr
                            if (-not $existingIPs.ContainsKey($ipStr)) { $newIPs[$ipStr] = $true }
                        }
                    }
                }
                $resolved++
            } catch { $failed++ }
            $dnsCache[$domain] = ($domainIPs -join ',')
        }

        if (($i + 1) % 1000 -eq 0) {
            Write-Log "Progress: $($i + 1) / $total ($skipped already routed, $cached cache+new, $resolved resolved, $failed failed)"
        }
    }

    # Save DNS cache
    $cacheLines = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $dnsCache.Keys) { $cacheLines.Add("$key=$($dnsCache[$key])") }
    [System.IO.File]::WriteAllLines($dnsCacheFile, $cacheLines)
    Write-Log "DNS cache saved: $($dnsCache.Count) entries."

    Write-Log "Result: $($newIPs.Count) new IPs to route ($skipped already routed, $resolved freshly resolved, $failed failed)" "OK"
    return @($newIPs.Keys)
}

# Add permanent routes (IPv4 and IPv6)
function Add-PermanentRoutes {
    param ([string[]]$IPs)

    Write-Log "Adding $($IPs.Count) permanent routes (IPv4 + IPv6)..."
    $added = 0
    $errors = 0

    # Find a valid interface index for IPv6 black-hole routes
    $ipv6IfIndex = $null
    try {
        $ipv6If = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0" -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($ipv6If) { $ipv6IfIndex = $ipv6If.InterfaceIndex }
    } catch {}
    if (-not $ipv6IfIndex) {
        # Fallback: use the loopback pseudo-interface
        try {
            $loopback = Get-NetAdapter -Name "*Loopback*" -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($loopback) { $ipv6IfIndex = $loopback.ifIndex }
        } catch {}
    }
    if ($ipv6IfIndex) {
        Write-Log "Using interface index $ipv6IfIndex for IPv6 black-hole routes."
    } else {
        Write-Log "No suitable IPv6 interface found — IPv6 routes will be skipped." "WARN"
    }

    foreach ($ip in $IPs) {
        try {
            if ($ip.Contains(':')) {
                # IPv6 — route to :: (null) via default gateway interface, persistent
                if (-not $ipv6IfIndex) {
                    $errors++
                    continue
                }
                $result = & netsh interface ipv6 add route "$ip/128" interface=$ipv6IfIndex nexthop=:: metric=1 store=persistent 2>&1
                if ($LASTEXITCODE -eq 0) { $added++ } else { $errors++ }
            } else {
                # IPv4 — route add -p to black hole (0.0.0.0)
                $result = & route add $ip MASK 255.255.255.255 0.0.0.0 -p 2>&1
                if ($LASTEXITCODE -eq 0) { $added++ } else { $errors++ }
            }
        } catch {
            $errors++
        }

        if (($added + $errors) % 500 -eq 0) {
            Write-Log "Progress: $added added, $errors errors out of $($IPs.Count)"
        }
    }

    # Merge new IPs into cache
    $existingCache = @{}
    if (Test-Path $CacheFile) {
        foreach ($line in (Get-Content $CacheFile -ErrorAction SilentlyContinue)) {
            $line = $line.Trim()
            if ($line) { $existingCache[$line] = $true }
        }
    }
    foreach ($ip in $IPs) { $existingCache[$ip] = $true }
    @($existingCache.Keys) | Out-File $CacheFile -Encoding UTF8 -Force

    Write-Log "Routes added: $added, errors: $errors" "OK"
}

# Download malware/botnet IP lists (raw IPs, no DNS resolution needed)
function Get-ThreatIPs {
    Write-Log "Downloading threat intelligence IP lists..."
    $threatIPs = @{}

    foreach ($url in $ThreatIPLists) {
        Write-Log "Downloading threat list: $url"
        try {
            $headers = @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PiHole-RouteBlocker/1.0" }
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -Headers $headers -ErrorAction Stop
            $lines = $response.Content -split "`n"
            $count = 0
            foreach ($line in $lines) {
                $line = $line.Trim()
                # Skip comments and empty lines
                if (-not $line -or $line.StartsWith("#") -or $line.StartsWith(";")) { continue }
                # Extract IP or CIDR — take first token on the line
                $ip = ($line -split "\s+")[0].Trim()
                # Match single IPs
                if ($ip -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$") {
                    $ipStr = $Matches[1]
                    if (-not $ipStr.StartsWith("127.") -and
                        -not $ipStr.StartsWith("10.") -and
                        -not $ipStr.StartsWith("192.168.") -and
                        -not $ipStr.StartsWith("0.")) {
                        $threatIPs[$ipStr] = $true
                        $count++
                    }
                }
                # Match CIDR /24 or smaller — expand to single IP (just block the network address)
                elseif ($ip -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)$") {
                    $netAddr = $Matches[1]
                    $prefix = [int]$Matches[2]
                    if (-not $netAddr.StartsWith("127.") -and
                        -not $netAddr.StartsWith("10.") -and
                        -not $netAddr.StartsWith("192.168.") -and
                        -not $netAddr.StartsWith("0.")) {
                        $threatIPs[$netAddr] = $true
                        $count++
                    }
                }
            }
            Write-Log "Extracted $count IPs from $url" "OK"
        } catch {
            Write-Log "Failed to download threat list ${url}: $($_.Exception.Message)" "WARN"
        }
    }

    Write-Log "Total unique threat IPs: $($threatIPs.Count)" "OK"
    return @($threatIPs.Keys)
}

# Disable DoH so routes work
function Disable-DoH {
    Write-Log "Disabling DNS over HTTPS..."
    try {
        $paths = @{
            "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" = "DoHPolicy"
            "HKLM:\SOFTWARE\Policies\Microsoft\Edge" = @("DnsOverHttpsMode", "EncryptedClientHelloEnabled")
            "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" = "EnableDoH"
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS" = "EnableAutoDoh"
        }
        foreach ($path in $paths.Keys) {
            if (Test-Path $path) {
                $props = $paths[$path]
                if ($props -is [string]) { $props = @($props) }
                foreach ($prop in $props) {
                    Remove-ItemProperty -Path $path -Name $prop -ErrorAction SilentlyContinue
                }
            }
        }
        Write-Log "DoH disabled."
    } catch {
        Write-Log "Error disabling DoH: $_" "WARN"
    }
}

# Register scheduled task
function Register-UpdateTask {
    Write-Log "Registering daily update task..."
    try {
        $taskName = "PiHole-RouteUpdate"
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\Pihole.ps1`""
        $trigger = New-ScheduledTaskTrigger -Daily -At "3:00AM"
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -TaskPath "\PiHole\" -Action $action `
            -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
        Write-Log "Scheduled task registered." "OK"
    } catch {
        Write-Log "Error registering task: $_" "WARN"
    }
}

# Main
function Main {
    Write-Log "=== PiHole Route Blocker ===" "OK"

    # Phase 1: Threat intelligence IPs (fast — direct IP lists, no DNS needed)
    $threatIPs = Get-ThreatIPs
    if ($threatIPs.Count -gt 0) {
        Write-Log "Routing $($threatIPs.Count) threat IPs first..."
        Add-PermanentRoutes -IPs $threatIPs
    }

    # Phase 2: Ad/tracker domains (slow — requires DNS resolution)
    $domains = Get-BlockedDomains
    $adIPs = Resolve-DomainsToIPs -Domains $domains

    if ($adIPs.Count -gt 0) {
        Write-Log "Routing $($adIPs.Count) ad/tracker IPs..."
        Add-PermanentRoutes -IPs $adIPs
    }

    $totalNew = $threatIPs.Count + $adIPs.Count
    if ($totalNew -eq 0) {
        Write-Log "No new IPs to route. Everything is already blocked." "OK"
        return
    }

    # Ensure scheduled task is registered
    Register-UpdateTask

    Write-Log "=== PiHole complete: $($threatIPs.Count) threat IPs + $($adIPs.Count) ad IPs blocked ===" "OK"
}

Main