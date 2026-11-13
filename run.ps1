
# letting the scripts run
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# File Paths
$AuthLog    = ".\ProjectDataset\auth.log"
$AccessLog  = ".\ProjectDataset\access.log"
$PSLog      = ".\ProjectDataset\powershell_log.txt"
$IOCFile    = ".\ProjectDataset\ioc.txt"
$ReportPath = ".\investigation_report.txt"

# Loading all the detection scripts from the script folder r

. .\Scripts\Detect-BruteForce.ps1
. .\Scripts\Detect-PowerShell.ps1
. .\Scripts\Detect-IOCMatch.ps1
. .\Scripts\Detect-Exfiltration.ps1
. .\Scripts\Generate-Report.ps1

# Initialise all alert counters to 0

$script:bruteforce_alerts = 0
$script:powershell_alerts = 0
$script:ioc_alerts        = 0
$script:exfil_alerts      = 0
$script:top_attacker      = "None"


# Run the full investigation pipeline

Write-Host "`n================================================"
Write-Host "       SOC SECURITY INVESTIGATION TOOL"
Write-Host "================================================"
Write-Host "Starting investigation at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "================================================"

# Run each detection function one by one
Detect-BruteForce   -AuthLogPath $AuthLog
Detect-PowerShell   -PSLogPath $PSLog
Detect-IOCMatch     -AccessLogPath $AccessLog -AuthLogPath $AuthLog -IOCPath $IOCFile
Detect-Exfiltration -AccessLogPath $AccessLog -PSLogPath $PSLog

# Generate the final report
Generate-Report -ReportPath $ReportPath

Write-Host "`nInvestigation complete."
Write-Host "================================================`n"