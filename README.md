# SOC Security Investigation Tool (PowerShell)

A modular PowerShell tool that works like a small Security Operations Centre (SOC) triage pipeline. It scans server, web and PowerShell logs for four attack patterns and writes a scored investigation report.

**Module:** Advanced Scripting for Cyber Security, TU Dublin (2025–26), individual project
**Author:** Benjamin Oludipe
**Tools:** PowerShell, regular expressions, log analysis (Linux `auth.log`, web `access.log`, PowerShell logs), Indicators of Compromise (IoCs)

---

## What it detects
| Module | Log analysed | Logic |
|---|---|---|
| `Detect-BruteForce.ps1` | `auth.log` | Counts `Failed password` lines per source IP and alerts at **5 or more** attempts; tracks the top attacker |
| `Detect-PowerShell.ps1` | PowerShell log | Flags attacker techniques: `EncodedCommand`, `IEX` / `Invoke-Expression`, `DownloadString`, `ExecutionPolicy Bypass` and others |
| `Detect-IOCMatch.ps1` | `access.log` + `auth.log` | Checks every indicator in `ioc.txt` against both logs |
| `Detect-Exfiltration.ps1` | `access.log` + PowerShell log | POST requests over 500 KB, plus upload/transfer commands (`UploadFile`, `Start-BitsTransfer`, `Compress-Archive`, ...) |
| `Generate-Report.ps1` | n/a | Totals the alerts and assigns a risk level: **HIGH** (6+), **MEDIUM** (2–5) or **LOW** (0–1) |

`run.ps1` loads every module, runs them in order and writes `investigation_report.txt`.

## Result on the course dataset
From `investigation_report.txt` (sample output in this repo):

| Detection | Alerts |
|---|---|
| Brute force | 47 (top attacker `[REDACTED-IP]`) |
| Suspicious PowerShell | 3 |
| IoC matches | 5 |
| Exfiltration | 1 |
| **Total** | **56, risk level HIGH** |

## My contribution
Individual project. The overall structure follows patterns from the module's weekly labs (noted in code comments); I designed the modular tool, wrote all five detection and reporting scripts and the `run.ps1` orchestrator, and chose the thresholds and indicators.

## How to run
```powershell
# place the course dataset in .\ProjectDataset\ (auth.log, access.log, powershell_log.txt, ioc.txt)
pwsh ./run.ps1
```
The dataset was provided by the module and is not redistributed here.

## What it demonstrates
Log analysis and detection engineering, threshold-based alerting, IoC matching, mapping attacker techniques (encoded or downloaded PowerShell, data exfiltration) to detections, and modular, reusable scripting.
