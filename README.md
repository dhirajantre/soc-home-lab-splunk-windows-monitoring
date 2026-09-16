# 🛡️ SOC Home Lab – Windows Security Monitoring & Brute-Force Detection

A hands-on Security Operations Center (SOC) home lab built using Splunk Enterprise to collect, monitor, investigate, and detect Windows authentication activity.

The project demonstrates an end-to-end SOC workflow:

**Windows Security Logs → SIEM → Detection Engineering → Alerting → Investigation → MITRE ATT&CK Mapping → Analyst Assessment → Response**

---

# 📌 Project Overview

This project simulates a practical SOC monitoring and detection environment using Windows Security Event Logs and Splunk Enterprise.

The primary objective was to monitor Windows authentication activity, investigate failed logon events, develop a time-based brute-force detection rule, configure a scheduled alert, validate the detection using controlled lab activity, and document the investigation.

All authentication failures used for detection validation were intentionally generated in a controlled home-lab environment.

---

# 🎯 Objectives

- Collect Windows Security Event Logs in Splunk
- Monitor Windows authentication activity
- Analyze successful and failed Windows logons
- Investigate Windows Security Event IDs
- Develop a time-based brute-force detection rule
- Configure a scheduled Splunk security alert
- Validate the detection using controlled authentication failures
- Investigate detected authentication activity
- Analyze source IP and authentication details
- Map observed behavior to MITRE ATT&CK
- Document investigation findings
- Create SOC response recommendations
- Build a centralized security monitoring dashboard

---

# 🛠️ Technologies & Tools

| Technology / Tool | Purpose |
|---|---|
| **Splunk Enterprise 10.4.3** | SIEM, log analysis, detection and alerting |
| **Windows 11** | Endpoint generating security events |
| **Windows Security Event Logs** | Authentication and security telemetry |
| **Splunk Processing Language (SPL)** | Detection and investigation queries |
| **VMware** | Virtualization environment |
| **MITRE ATT&CK** | Adversary behavior mapping |

---

# 🔎 Windows Security Events Investigated

| Event ID | Description |
|---|---|
| **4624** | Successful Logon |
| **4625** | Failed Logon |
| **4672** | Special Privileges Assigned to New Logon |

These events were used to analyze authentication activity and privileged logon behavior. :contentReference[oaicite:1]{index=1}

---

# 🚨 Detection Engineering

## Detection Objective

Detect **three or more failed Windows logon attempts for the same user and source within a five-minute window**.

---

## 🔍 SPL Detection Query

```spl
index=* sourcetype=WinEventLog:Security EventCode=4625
| eval User_Account=mvfilter(Account_Name!="DHIRAJ-WIN11$")
| where isnotnull(User_Account)
| bin _time span=5m
| stats count as failed_attempts by _time User_Account Source_Network_Address
| where failed_attempts >= 3
| sort - failed_attempts
```

---

## 🧠 Detection Logic

The detection performs the following steps:

1. Filters Windows failed authentication events using Event ID `4625`.
2. Extracts the user account while excluding the machine account.
3. Groups events into five-minute time windows.
4. Groups activity by user and source network address.
5. Counts failed authentication attempts.
6. Returns a detection when the count reaches three or more.

This detection logic is documented in the project report. :contentReference[oaicite:2]{index=2}

---

# 🔔 Alert Configuration

The detection was operationalized as a scheduled Splunk alert.

## Alert Details

| Configuration | Value |
|---|---|
| **Alert Name** | Brute Force - 5 Minute Failed Login Detection |
| **Alert Type** | Scheduled |
| **Schedule** | Every 5 minutes |
| **Cron Schedule** | `*/5 * * * *` |
| **Time Range** | Last 5 minutes |
| **Trigger Condition** | Number of Results > 0 |
| **Trigger Frequency** | Once |
| **Alert Expiration** | 24 hours |
| **Severity** | Medium |
| **Action** | Add to Triggered Alerts |
| **Permissions** | Private |

The alert configuration was documented and validated in Splunk. :contentReference[oaicite:3]{index=3}

---

# 📸 Alert Configuration Evidence

![Splunk Alert Configuration](04-alert-configuration.png)

The screenshot shows the scheduled alert configuration, cron schedule, time range, and trigger condition.

---

# 🧪 Detection Validation

The detection was validated using a controlled authentication test.

Three incorrect passwords were intentionally entered for the test account. On the next five-minute scheduled cycle, Splunk evaluated the detection search, identified the qualifying activity, and successfully triggered the alert. :contentReference[oaicite:4]{index=4}

---

# 🚨 Triggered Alert

The configured alert successfully appeared in Splunk's triggered-alert history.

The validated detection was:

```text
Brute Force - 5 Minute Failed Login Detection
```

The triggered alert confirmed that the scheduled detection was functioning as intended.

---

# 📸 Triggered Alert Evidence

![Splunk Triggered Alert](05-triggered-alert.png)

The screenshot shows the Splunk triggered-alert history containing the validated detection.

---

# 🔎 Detection Result

The validated detection identified:

| Field | Observed Value |
|---|---|
| **User Account** | Dhiraj |
| **Source Address** | `127.0.0.1` |
| **Failed Attempts** | 3 |
| **Detection Window** | 5 minutes |
| **Event ID** | 4625 |
| **Logon Type** | 2 – Interactive |

The validated detection occurred during the `17:00–17:05` window on 15 September 2026. :contentReference[oaicite:5]{index=5}

---

# 📸 Detection Result Evidence

![Brute-Force Detection Result](03-bruteforce-detection-result.png)

The screenshot shows the SPL detection aggregating failed logons into five-minute windows and identifying the qualifying three-attempt detection.

---

# 🔎 Incident Investigation

The investigation was expanded to the surrounding 24-hour period.

The search identified **11 failed logon attempts against the same account in four separate bursts**.

One burst containing three attempts between approximately `17:01:46` and `17:01:51` met the detection threshold and was carried forward for investigation. :contentReference[oaicite:6]{index=6}

---

# 📋 Observed Activity

| Field | Observed Value |
|---|---|
| **Event ID** | 4625 |
| **User Account** | Dhiraj |
| **Source Address** | `127.0.0.1` |
| **Workstation** | `DHIRAJ-WIN11` |
| **Logon Type** | 2 – Interactive |
| **Status** | `0xC000006D` |
| **Sub-Status** | `0xC000006A` |
| **Failure Reason** | Unknown user name or bad password |
| **Attempts** | 3 within a 5-minute window |

---

# 📸 Failed Login Investigation Evidence

![Failed Login Investigation](02-failed-login-investigation.png)

The screenshot shows the Event ID 4625 investigation and authentication-related fields.

---

# 🌐 Source Analysis

The source address for the observed authentication attempts was:

```text
127.0.0.1
```

`127.0.0.1` is the localhost address of the system.

Therefore, the activity showed **no evidence of an external source** during this controlled test. :contentReference[oaicite:7]{index=7}

---

# ⏱️ Timeline Analysis

During the validated `17:00–17:05` detection window:

```text
Failed Authentication Attempt
          ↓
~2–3 seconds
          ↓
Failed Authentication Attempt
          ↓
~2–3 seconds
          ↓
Failed Authentication Attempt
          ↓
Detection Threshold Reached
          ↓
Splunk Alert Triggered
```

Splunk grouped the three qualifying events into a single five-minute detection window. :contentReference[oaicite:8]{index=8}

---

# 🧑‍💻 Analyst Assessment

The observed authentication pattern is consistent with password-guessing behavior because multiple failed attempts occurred for the same account within a short time window.

However, the source was `127.0.0.1` and the authentication failures were intentionally generated as part of a controlled SOC laboratory test. :contentReference[oaicite:9]{index=9}

## Final Classification

**CONTROLLED LAB TEST — NO CONFIRMED MALICIOUS ACTIVITY**

No confirmed external attack or account compromise was identified from this test. :contentReference[oaicite:10]{index=10}

---

# 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique |
|---|---|---|
| **Credential Access** | **T1110 – Brute Force** | **T1110.001 – Password Guessing** |

The repeated failed-authentication pattern observed during the controlled test was mapped to password-guessing behavior. :contentReference[oaicite:11]{index=11}

---

# 🛡️ Recommended SOC Response

If similar authentication activity were detected in a production environment, a SOC Analyst could:

1. Validate whether the authentication attempts were authorized.
2. Review successful logon events following the failed attempts.
3. Investigate the source IP address and affected account.
4. Check for additional authentication anomalies.
5. Review related Windows Security events.
6. If malicious activity is confirmed, consider temporarily locking or disabling the affected account according to organizational procedures.
7. Continue monitoring the account and source for additional suspicious activity.

These recommendations are based on the response workflow documented in the project report. :contentReference[oaicite:12]{index=12}

---

# 📊 Splunk Security Monitoring Dashboard

A Splunk Dashboard Studio dashboard named:

**SOC Home Lab - Security Monitoring**

was created to provide centralized visibility into Windows authentication activity.

## Dashboard Panels

- Failed Windows Logins
- Successful Windows Logins
- Brute Force Detections
- Privileged Logons
- Failed Login Activity Over Time

The dashboard uses a rolling 24-hour view of Windows authentication activity. :contentReference[oaicite:13]{index=13}

---

# 📸 Dashboard Evidence

![Splunk Security Monitoring Dashboard](01-splunk-dashboard.png)

The dashboard provides a centralized view of Windows authentication activity.

> **Note:** The dashboard's Brute Force Detections panel may show `0` after the validated detection ages out of the rolling 24-hour dashboard window. The triggered-alert and detection-result evidence confirm that the detection fired successfully when the test activity occurred. :contentReference[oaicite:14]{index=14}

---

# 🔄 SOC Workflow

```text
Windows Authentication Activity
            ↓
Windows Security Event ID 4625
            ↓
Splunk SIEM
            ↓
Detection Rule
            ↓
3+ Failed Logins / 5 Minutes
            ↓
Scheduled Alert
            ↓
Alert Triggered
            ↓
Investigation
            ↓
MITRE ATT&CK Mapping
            ↓
Analyst Assessment
            ↓
Recommended Response
```

This workflow represents the end-to-end process implemented in the lab. :contentReference[oaicite:15]{index=15}

---

# 📚 Skills Demonstrated

## SIEM & Security Monitoring

- Splunk Enterprise
- SIEM Monitoring
- Windows Security Event Log Analysis
- Authentication Monitoring

## Detection Engineering

- SPL
- Time-Based Detection
- Failed Authentication Detection
- Brute-Force Detection Logic
- Scheduled Security Alerts

## Investigation

- Alert Triage
- Windows Event Analysis
- Authentication Investigation
- Source/IP Analysis
- Timeline Analysis
- Incident Investigation

## Security Framework

- MITRE ATT&CK
- T1110 – Brute Force
- T1110.001 – Password Guessing

## SOC Operations

- Security Monitoring
- Detection Validation
- Incident Investigation
- Alert Analysis
- SOC Workflow Documentation

---

# 💡 Key Learning Outcomes

Through this project, I practiced:

- Collecting and analyzing Windows Security logs
- Understanding Windows authentication Event IDs
- Writing SPL detection logic
- Creating time-based detection rules
- Configuring scheduled security alerts
- Validating detections using controlled authentication activity
- Investigating authentication failures
- Analyzing source and authentication information
- Performing timeline analysis
- Mapping observed behavior to MITRE ATT&CK
- Documenting SOC investigation findings
- Building a security monitoring dashboard
- Following an end-to-end SOC detection workflow

---

# 📄 Project Documentation Report

A detailed PDF documentation report is included in this repository.

**Report:**

`Dhiraj_Antre_SOC_Home_Lab_Documentation_Report.pdf`

The report contains:

- Executive Summary
- Project Overview
- Objectives
- Tools & Technologies
- Windows Events Investigated
- Detection Engineering
- SPL Detection Query
- Detection Logic
- Alert Configuration
- Detection Validation
- Detection Result
- Incident Investigation
- Source Analysis
- Timeline
- Analyst Assessment
- MITRE ATT&CK Mapping
- Recommended SOC Response
- Splunk Dashboard
- SOC Workflow
- Skills Demonstrated
- Key Learning Outcomes
- Project Status
- Conclusion

---

# 📁 Project Files

```text
soc-home-lab-splunk-windows-monitoring/
│
├── README.md
├── Dhiraj_Antre_SOC_Home_Lab_Documentation_Report.pdf
│
├── 01-splunk-dashboard.png
├── 02-failed-login-investigation.png
├── 03-bruteforce-detection-result.png
├── 04-alert-configuration.png
└── 05-triggered-alert.png
```

---

# 📸 Project Evidence

| Evidence | File |
|---|---|
| Splunk Security Dashboard | `01-splunk-dashboard.png` |
| Failed Login Investigation | `02-failed-login-investigation.png` |
| Brute-Force Detection Result | `03-bruteforce-detection-result.png` |
| Alert Configuration | `04-alert-configuration.png` |
| Triggered Alert | `05-triggered-alert.png` |
| Full Documentation | `Dhiraj_Antre_SOC_Home_Lab_Documentation_Report.pdf` |

---

# ⚠️ Lab Disclaimer

All authentication failures referenced in this project were intentionally generated in a controlled home-lab environment for cybersecurity learning and detection-engineering practice.

No production system or real attacker was involved.

The observed activity should not be interpreted as a confirmed real-world attack.

---

# 🚀 Project Status

**Completed ✅**

## Completed Components

- [x] Splunk Enterprise Setup
- [x] Windows Security Log Collection
- [x] Windows Authentication Event Analysis
- [x] Event ID 4624 Investigation
- [x] Event ID 4625 Investigation
- [x] Event ID 4672 Investigation
- [x] SPL Detection Engineering
- [x] 5-Minute Brute-Force Detection
- [x] Splunk Security Dashboard
- [x] Scheduled Security Alert
- [x] Alert Trigger Validation
- [x] Failed Login Investigation
- [x] Source Analysis
- [x] Timeline Analysis
- [x] MITRE ATT&CK Mapping
- [x] SOC Response Recommendations
- [x] Evidence Screenshots
- [x] Documentation Report

---

# 👨‍💻 Project Summary

This project demonstrates a practical SOC monitoring, detection, alerting, and investigation workflow using **Splunk Enterprise** and **Windows Security Event Logs**.

The complete workflow is:

**Log Collection → Monitoring → Detection → Alerting → Investigation → MITRE ATT&CK Mapping → Analyst Assessment → Response**

The project was built and validated in a controlled home-lab environment and demonstrates practical entry-level SOC Analyst skills in security monitoring, detection engineering, alert triage, Windows event analysis, incident investigation, and security documentation.
