function Detect-BruteForce {
    param([string]$AuthLogPath)

    Write-Host "`n[*] Checking SSH brute force attempts in auth.log"
    Write-Host "-----------------------------------------------------"

    $threshold = 5
    $script:bruteforce_alerts = 0
    $script:top_attacker = "None"
    $topCount = 0

    # Finding all the failed login lines and extracting the IPs
    $hits = Select-String "Failed password" $AuthLogPath

    if (-not $hits) {
        Write-Host "[OK] No failed login attempts found"
        return
    }

    # Extracting IPs from matching lines
    $ipList = $hits | ForEach-Object {
        if ($_.Line -match "from\s+([\d\.]+)") {
            $matches[1]
        }
    }

    # Counting attempts per IP
    $ipCounts = $ipList | Group-Object | Sort-Object Count -Descending

    foreach ($entry in $ipCounts) {
        if ($entry.Count -ge $threshold) {
            Write-Host "[ALERT] Brute force suspected from $($entry.Name) ($($entry.Count) attempts)"
            $script:bruteforce_alerts++

            # Track the top attacker
            if ($entry.Count -gt $topCount) {
                $topCount = $entry.Count
                $script:top_attacker = $entry.Name
            }
        }
    }

    if ($script:bruteforce_alerts -eq 0) {
        Write-Host "[OK] No IPs exceeded the brute force threshold"
    }
}