function Detect-Exfiltration {
    param(
        [string]$AccessLogPath,
        [string]$PSLogPath
    )

    Write-Host "`n[*] Checking for potential data exfiltration indicators"
    Write-Host "------------------------------------------------------------"

    $script:exfil_alerts = 0

    # first check, large POST requests in access.log
        Write-Host "`n[Task] Checking for large POST requests in access.log"

    $postHits = Select-String "POST" $AccessLogPath

    if ($postHits) {
        foreach ($hit in $postHits) {

            # Extract the response size 
            if ($hit.Line -match "POST\s+\S+\s+\S+\s+\d+\s+(\d+)") {
                $size = [int]$matches[1]

                # Flag if response size is unusually large (over 500000 bytes)
                if ($size -gt 500000) {
                    Write-Host "[ALERT] Large POST request detected - possible data exfiltration"
                    Write-Host "Sample: $($hit.Line)"
                    $script:exfil_alerts++
                }
            }
        }
    }

    if ($script:exfil_alerts -eq 0) {
        Write-Host "[OK] No large POST requests detected"
    }

    # second check, suspicious download commands in PowerShell log
   
    Write-Host "`n[Task] Checking for download/upload activity in powershell_log.txt"

    $downloadPatterns = @(
        "UploadFile",
        "UploadString",
        "WebClient",
        "Start-BitsTransfer",
        "Copy-Item.*\\\\",
        "compress-archive",
        "Invoke-WebRequest.*-OutFile"
    )

    foreach ($pattern in $downloadPatterns) {
        $hits = Select-String $pattern $PSLogPath

        if ($hits) {
            Write-Host "[ALERT] Suspicious exfiltration indicator detected: $pattern"
            Write-Host "Sample: $($hits[0].Line)"
            $script:exfil_alerts++
        }
    }

    if ($script:exfil_alerts -eq 0) {
        Write-Host "[OK] No suspicious download or upload activity found"
    }
}