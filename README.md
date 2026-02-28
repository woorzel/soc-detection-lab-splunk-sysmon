# Splunk + Sysmon SOC Detection Lab

Home lab project focused on endpoint telemetry collection and SOC-style
detection engineering using **Sysmon** and **Splunk Enterprise**.

The lab simulates a basic Security Operations Center workflow --- from
log ingestion and normalization to detection creation, alerting, and
analyst triage using MITRE ATT&CK--aligned logic.


##  Project Objectives

-   Collect endpoint security telemetry from Windows hosts using Sysmon
-   Centralize and parse logs in Splunk Enterprise
-   Build SPL detections mapped to MITRE ATT&CK techniques
-   Implement scheduled alerts and monitoring dashboard
-   Document detection logic, assumptions, and false positives
-   Practice SOC analyst investigation workflow


##  Lab Architecture

Windows Endpoint (Sysmon)
↓
Splunk Universal Forwarder
↓
Splunk Enterprise (Linux VM)

**Components**

-   **Sysmon** --- generates detailed endpoint telemetry
-   **Splunk Universal Forwarder** --- forwards Windows Event Logs (port
    9997)
-   **Splunk Enterprise** --- indexing, parsing, detections, alerting
-   **TA-Windows** --- field extraction and normalization


##  Data Sources

**Log Source** - `Microsoft-Windows-Sysmon/Operational`

##  Implemented Detections (MITRE ATT&CK)

###  Suspicious PowerShell Execution

Detection of encoded or execution-policy bypass PowerShell activity.

-   **Technique:** T1059.001 --- PowerShell
-   **Tactic:** Execution
-   **SPL Query:** `searches/powershell_encoded_detection.spl`
-   **Documentation:** `detections/T1059_powershell.md`

Detection logic includes: - encoded commands (`-enc`,
`-encodedcommand`) - execution policy bypass - suspicious inline
execution (`iex`)

Alert configured as scheduled search triggering on detection results.


###  Signed Binary Proxy Execution (LOLBins)

Detection of potential abuse of trusted Windows binaries.

-   **Technique:** T1218 --- Signed Binary Proxy Execution
-   **Tactic:** Defense Evasion
-   **SPL Query:** `searches/signed_binary_proxy_execution.spl`
-   **Documentation:** `detections/T1218_signed_binary_proxy.md`

Monitored binaries: - `mshta.exe` - `rundll32.exe`


##  Alert Configuration

Alerts are implemented as **Scheduled Searches** in Splunk:

  Setting      Value
  ------------ -------------------------
  Schedule     Every 5 minutes
  Time Range   Last 5 minutes
  Trigger      For each result
  Throttle     15 minutes
  Action       Add to Triggered Alerts

Screenshots available in `/screenshots`.


##  SOC Dashboard

Custom dashboard created to simulate analyst monitoring view:

-   Detection activity timeline
-   PowerShell execution alerts
-   Signed binary execution monitoring
-   Quick triage visibility

Screenshot: `screenshots/dashboard.png`


##  Setup Overview

### Windows Endpoint

1.  Install Sysmon:

    Sysmon.exe -accepteula -i sysmonconfig.xml

2.  Install Splunk Universal Forwarder
3.  Configure event log inputs (see `inputs.conf`)


### Splunk Enterprise (Linux VM)

1.  Enable receiving port **9997**
2.  Install **Splunk Add-on for Microsoft Windows (TA-Windows)**
3.  Verify ingestion:

    index=windows EventCode=1
    | table _time host Image CommandLine ParentImage


##  Detection Testing (Safe Commands)

### PowerShell encoded execution

    powershell -ExecutionPolicy Bypass -enc aQBlAHgA

### rundll32 execution test

    rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl

Commands are non-destructive and used only to generate telemetry.


##  Evidence / Screenshots

-   `screenshots/sysmon_installed_event_viewer.png`
-   `screenshots/detection_T1059_query.png`
-   `screenshots/detection_T1218_query.png`
-   `screenshots/alert_T1059_triggered.png`
-   `screenshots/alert_T1218_triggered.png`
-   `screenshots/dashboard.png`


##  Skills Demonstrated

-   Endpoint telemetry onboarding (Sysmon)
-   Splunk Universal Forwarder configuration & troubleshooting
-   Windows Event Log ingestion
-   SPL detection engineering
-   MITRE ATT&CK mapping
-   Alert creation and tuning
-   SOC-style triage workflow
-   Dashboard creation for monitoring

