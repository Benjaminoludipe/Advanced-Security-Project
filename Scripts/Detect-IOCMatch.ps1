function Detect-IOCMatch {
    param(
        [string]$AccessLogPath,
        [string]$AuthLogPath,
        [string]$IOCPath
    )

    Write-Host "`n[*] Checking IoC matches against ioc.txt"
    Write-Host "------------------------------------------------------------"

    $script:ioc_alerts = 0

    # Read each IP/indicator from ioc.txt
    $iocList = Get-Content $IOCPath

    if (-not $iocList) {
        Write-Host "[OK] No IOCs found in ioc.txt"
        return
    }

    foreach ($ioc in $iocList) {

        # Skip empty lines
        if ([string]::IsNullOrWhiteSpace($ioc)) { continue }

        $foundInAccess = Select-String $ioc $AccessLogPath -Quiet
        $foundInAuth   = Select-String $ioc $AuthLogPath -Quiet

        # Alert if IOC appears in either log - same OR logic as Week 4 lab
        if ($foundInAccess -or $foundInAuth) {
            Write-Host "[ALERT] IOC HIT detected for: $ioc"

            if ($foundInAccess) {
                Write-Host "  --> Found in access.log"
            }
            if ($foundInAuth) {
                Write-Host "  --> Found in auth.log"
            }

            $script:ioc_alerts++
        }
    }

    if ($script:ioc_alerts -eq 0) {
        Write-Host "[OK] No IOC matches found in log files"
    }
}