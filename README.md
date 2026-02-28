# Splunk + Sysmon Threat Detection Lab

Home lab focused on endpoint telemetry (Sysmon) and basic SOC-style detections in Splunk.
Goal: collect Windows process activity, build SPL detections, and trigger alerts mapped to MITRE ATT&CK.

## What’s inside
- Sysmon deployed on a Windows endpoint (Event ID 1/3/11/22)
- Splunk Universal Forwarder shipping logs to Splunk Enterprise (Linux VM)
- Field extraction via Splunk Add-on for Microsoft Windows (TA-Windows)
- Detections (SPL), alerts, and a simple monitoring dashboard

## Architecture
Windows (Sysmon) → Splunk Universal Forwarder → Splunk Enterprise (Linux VM) → Detections/Alerts/Dashboard

(See: `architecture/lab-architecture.png`)

## Data sources
- Sysmon Operational log: `Microsoft-Windows-Sysmon/Operational`
- Key events used:
  - Event ID 1 — Process Create
  - Event ID 3 — Network Connection (optional)
  - Event ID 22 — DNS Query (optional)

## Detections
### 1) Suspicious PowerShell Execution (MITRE T1059.001)
Detects PowerShell launched with patterns commonly seen in abuse/malware (encoded command, bypass, IEX).

SPL: `splunk/searches/powershell_encoded_detection.spl`  
Notes: `detections/T1059_powershell.md`

### 2) Signed Binary Proxy Execution / LOLBins (MITRE T1218)
Detects usage of common LOLBins like `rundll32.exe` / `mshta.exe`.

SPL: `splunk/searches/signed_binary_proxy_execution.spl`  
Notes: `detections/T1218_signed_binary_proxy.md`

## Alerts
- Scheduled alerts created from detections (per-result mode)
- Actions: add to Triggered Alerts
- Recommended schedule: every 5 minutes, time range last 5 minutes (avoid re-triggering on old data)

(Details: `splunk/alerts/`)

## Dashboard
Basic SOC view:
- detection hits over time
- latest suspicious events (table)

Export/notes: `splunk/dashboards/`

## How to reproduce (high level)
1. Install Sysmon using provided config: `sysmon/sysmonconfig.xml`
2. Configure Splunk Universal Forwarder to collect Sysmon channel (see `splunk/inputs.conf`)
3. Install TA-Windows on Splunk Enterprise for field extraction
4. Run SPL searches from `splunk/searches/`, save as alerts, add to dashboard

## Screenshots
See `screenshots/` for:
- sample Sysmon events
- detection search results
- triggered alerts

## Notes / tuning ideas
- Add allowlists for admin scripts to reduce false positives
- Extend to Event ID 3 and 22 to enrich triage (network + DNS)
- Add severity logic (e.g., encoded PowerShell + suspicious parent process)
