function Generate-Report {
    param([string]$ReportPath)

    Write-Host "`n[*] Generating SOC Investigation Report"
    Write-Host "-------------------------------------------------------"

    # Calculate total alerts
    $total = $script:bruteforce_alerts + $script:powershell_alerts + $script:ioc_alerts + $script:exfil_alerts

    # Determine risk level
    if ($total -ge 6) {
        $risk = "HIGH"
    } elseif ($total -ge 2) {
        $risk = "MEDIUM"
    } else {
        $risk = "LOW"
    }

    Write-Host "`n============================="
    Write-Host "     SOC INVESTIGATION REPORT"
    Write-Host "=============================="
    Write-Host "Brute Force Alerts   : $script:bruteforce_alerts"
    Write-Host "PowerShell Alerts    : $script:powershell_alerts"
    Write-Host "IOC Match Alerts     : $script:ioc_alerts"
    Write-Host "Exfiltration Alerts  : $script:exfil_alerts"
    Write-Host "------------------------------"
    Write-Host "Total Alerts         : $total"
    Write-Host "Risk Level           : $risk"
    Write-Host "Top Attacker IP      : $script:top_attacker"
    Write-Host "=============================="

    # Build the report content
    $report = @"
===============================================
        SOC SECURITY INVESTIGATION REPORT
===============================================
Date/Time  : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
------------------------------------------------

[1] BRUTE FORCE DETECTION
--------------------------
Alerts Detected  : $script:bruteforce_alerts
Top Attacker IP  : $script:top_attacker

[2] SUSPICIOUS POWERSHELL DETECTION
-------------------------------------
Alerts Detected  : $script:powershell_alerts

[3] IOC MATCH DETECTION
------------------------
Alerts Detected  : $script:ioc_alerts

[4] EXFILTRATION DETECTION
---------------------------
Alerts Detected  : $script:exfil_alerts

------------------------------------------------
INVESTIGATION SUMMARY
------------------------------------------------
Total Alerts     : $total
Risk Level       : $risk

Risk Level Guide:
  HIGH   = 6 or more alerts - Immediate action required
  MEDIUM = 2 to 5 alerts   - Investigate further
  LOW    = 0 to 1 alerts   - Low suspicion

================================================
"@

    # Saving report to a file
    $report | Out-File $ReportPath -Encoding UTF8

    Write-Host "`nReport saved to: $ReportPath"
}