# test-alert.ps1 - Generate a test alert for Gorstak EDR
# Run this while GEdr.exe monitor is active to verify detection is working.
#
# This script creates a harmless EICAR test file that all AV/EDR tools
# should detect. It does NOT contain actual malware.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File test-alert.ps1

$testDir = "$env:TEMP\GEdr-Test"
if (-not (Test-Path $testDir)) { New-Item -ItemType Directory -Path $testDir | Out-Null }

# EICAR test string - standard AV test pattern (NOT malware)
# See: https://www.eicar.org/download-anti-malware-testfile/
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

$testFile = "$testDir\eicar-test.com"
Write-Host "[*] Creating EICAR test file: $testFile" -ForegroundColor Cyan
[System.IO.File]::WriteAllText($testFile, $eicar)

Write-Host "[*] Waiting 5 seconds for EDR to detect..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

if (Test-Path $testFile) {
    Write-Host "[!] Test file still exists - EDR may not have detected it" -ForegroundColor Red
    Write-Host "    Check if GEdr.exe monitor is running" -ForegroundColor Gray
    Remove-Item $testFile -Force
} else {
    Write-Host "[+] Test file was quarantined - EDR is working!" -ForegroundColor Green
}

# Cleanup
if (Test-Path $testDir) { Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "Check GEdr logs for the detection entry." -ForegroundColor Gray
