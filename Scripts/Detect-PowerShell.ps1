function Detect-PowerShell {
    param([string]$PSLogPath)

    Write-Host "`n[*] Checking for suspicious PowerShell activity in powershell_log.txt"
    Write-Host "-----------------------------------------------------------"

    $script:powershell_alerts = 0

    # Suspicious keywords to search for
    $suspiciousPatterns = @(
        "EncodedCommand",
        "Invoke-WebRequest",
        "DownloadString",
        "ExecutionPolicy Bypass",
        "Invoke-Expression",
        "IEX",
        "DownloadFile"
    )

    foreach ($pattern in $suspiciousPatterns) {

        $hits = Select-String $pattern $PSLogPath

        if ($hits) {
            Write-Host "[ALERT] Suspicious PowerShell indicator detected: $pattern"
            $script:powershell_alerts++

            # Show the matching line - same style as Week 5 lab
            Write-Host "Sample: $($hits[0].Line)"
            Write-Host ""
        }
    }

    if ($script:powershell_alerts -eq 0) {
        Write-Host "[OK] No suspicious PowerShell activity found"
    }
}