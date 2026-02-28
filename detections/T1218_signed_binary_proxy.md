# Detection: Suspicious LOLBins Execution (mshta / rundll32)

## Overview
This detection identifies execution of trusted Windows binaries commonly abused by attackers to execute malicious code while bypassing traditional security controls.

Living-Off-The-Land Binaries (LOLBins) such as **mshta.exe** and **rundll32.exe** are frequently used during post-exploitation and defense evasion stages.

## MITRE ATT&CK Mapping
- **Technique:** T1218 – Signed Binary Proxy Execution
- **Tactic:** Defense Evasion

## Detection Logic
The detection monitors Sysmon Process Creation events (Event ID 1) and identifies execution of known LOLBins associated with proxy execution techniques.

### Monitored binaries
- `mshta.exe`
- `rundll32.exe`

These binaries can execute scripts, DLL exports, or remote payloads while appearing legitimate.

## SPL Query
```spl
index=windows EventCode=1
(Image="*mshta.exe" OR Image="*rundll32.exe*")
| eval technique="T1218 - Signed Binary Proxy Execution"
| eval tactic="Defense Evasion"
| eval severity="Medium"
| eval detection_name="Suspicious LOLBins Execution"
| table _time host User Image CommandLine ParentImage tactic technique severity detection_name
| sort -_time