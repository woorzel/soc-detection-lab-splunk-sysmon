# Detection: Suspicious PowerShell Encoded Command

## Overview
This detection identifies suspicious PowerShell executions using encoded commands or commonly abused execution flags.  
Attackers frequently use encoded PowerShell commands to evade detection and execute malicious payloads.

## MITRE ATT&CK Mapping
- **Technique:** T1059.001 – PowerShell
- **Tactic:** Execution

## Detection Logic
The detection monitors Sysmon Process Creation events (Event ID 1) and searches for PowerShell executions containing suspicious command-line arguments.

### Indicators detected:
- `-enc`
- `-encodedcommand`
- `bypass`
- `iex`

These parameters are commonly associated with obfuscated or malicious PowerShell usage.

## SPL Query
```spl
index=windows EventCode=1 Image="*powershell.exe"
| eval suspicious=if(match(CommandLine,"(?i)(-enc|-encodedcommand|bypass|iex)"),"YES","NO")
| where suspicious="YES"
| eval technique="T1059.001 - PowerShell"
| eval tactic="Execution"
| eval severity="Medium"
| eval detection_name="Suspicious PowerShell Encoded Command"
| table _time host User Image CommandLine ParentImage tactic technique severity detection_name
| sort -_time