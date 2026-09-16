# 🛡️ SOC Home Lab – Windows Security Monitoring & Brute-Force Detection

A hands-on Security Operations Center (SOC) home lab built using Splunk Enterprise to collect, monitor, investigate, and detect Windows authentication activity.

This project demonstrates an end-to-end SOC workflow:

**Windows Security Logs → SIEM → Detection Engineering → Alerting → Investigation → MITRE ATT&CK Mapping → Response**

---

## 📌 Project Overview

This project simulates a practical SOC monitoring and detection environment using Windows Security Event Logs and Splunk Enterprise.

The primary objective was to monitor Windows authentication activity, investigate failed logon events, develop a time-based brute-force detection rule, configure a scheduled alert, validate the detection using controlled lab activity, and document the investigation.

The authentication failures used for detection validation were intentionally generated in a controlled home-lab environment.

---

## 🎯 Objectives

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
- Document the investigation using a SOC workflow
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

The following Windows Security Event IDs were investigated during the project:

| Event ID | Description | SOC Use Case |
|---|---|---|
| **4624** | Successful Logon | Monitor successful authentication |
| **4625** | Failed Logon | Detect authentication failures and password-guessing patterns |
| **4672** | Special Privileges Assigned to New Logon | Monitor privileged logon activity |

---

# 🚨 Detection Engineering

## Detection Objective

Detect **3 or more failed Windows logon attempts for the same user and source within a 5-minute window**.

This type of detection can help identify repeated authentication failures that may require further investigation.

---

## 🔍 Detection SPL

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

The SPL detection performs the following steps:

1. Filters Windows failed logon events using Event ID `4625`.
2. Extracts the relevant user account.
3. Groups authentication failures into 5-minute time windows.
4. Groups the events by:
   - User account
   - Source network address
5. Counts the failed authentication attempts.
6. Returns activity when the number of failures reaches **3 or more attempts**.
7. Sorts the results by the number of failed attempts.

---

# 🔔 Alert Configuration

The detection was converted into a scheduled Splunk alert to simulate a practical SOC detection workflow.

## Alert Details

| Configuration | Value |
|---|---|
| **Alert Name** | Brute Force - 5 Minute Failed Login Detection |
| **Alert Type** | Scheduled |
| **Schedule** | Every 5 minutes |
| **Cron Schedule** | `*/5 * * * *` |
| **Time Range** | Last 5 minutes |
| **Trigger Condition** | Number of Results > 0 |
| **Trigger** | Once |
| **Severity** | Medium |
| **Trigger Action** | Add to Triggered Alerts |
| **Permissions** | Private |
| **Status** | Enabled |

---

## 📸 Alert Configuration Evidence

![Splunk Alert Configuration](04-alert-configuration.png)

---

# 🧪 Detection Validation

The detection was validated using controlled Windows authentication activity.

Three incorrect passwords were intentionally entered for the test account. The resulting Windows authentication failures were collected by Splunk and evaluated by the detection rule.

The detection successfully identified the repeated failed authentication attempts.

---

## Detection Result

| Field | Observed Value |
|---|---|
| **User Account** | Dhiraj |
| **Source Address** | `127.0.0.1` |
| **Failed Attempts** | 3 |
| **Detection Window** | 5 minutes |
| **Event ID** | 4625 |
| **Logon Type** | 2 |
| **Status** | `0xC000006D` |
| **Sub-Status** | `0xC000006A` |

---

## 📸 Detection Result Evidence

![Brute-Force Detection Result](03-bruteforce-detection-result.png)

---

# 🚨 Triggered Alert Validation

After the controlled authentication test, the scheduled Splunk alert successfully triggered.

The triggered alert confirmed that the detection rule and scheduled alert were working together as intended.

---

## Triggered Alert

**Alert:** Brute Force - 5 Minute Failed Login Detection

**Severity:** Medium

**Trigger:** Number of Results > 0

**Validation:** Successfully triggered after controlled authentication failures.

---

## 📸 Triggered Alert Evidence

![Splunk Triggered Alert](05-triggered-alert.png)

---

# 🔎 Incident Investigation

After the detection was triggered, the authentication events were investigated using Splunk.

The investigation focused on:

- User account
- Source network address
- Logon type
- Authentication status
- Sub-status
- Failure reason
- Event timeline
- Frequency of authentication failures

---

## Observed Authentication Activity

The investigated failed authentication events contained the following characteristics:

| Field | Observed Value |
|---|---|
| **Event ID** | 4625 |
| **User Account** | Dhiraj |
| **Source Address** | `127.0.0.1` |
| **Logon Type** | 2 – Interactive |
| **Status** | `0xC000006D` |
| **Sub-Status** | `0xC000006A` |
| **Failure Reason** | Unknown user name or bad password |
| **Attempts** | 3 within the detection window |

---

## 📸 Failed Login Investigation Evidence

![Failed Login Investigation](02-failed-login-investigation.png)

---

# 🌐 Source Analysis

The observed source network address was:

```text
127.0.0.1
```

`127.0.0.1` is the localhost address of the Windows system.

Therefore, the observed authentication activity originated from the local machine during this controlled test.

There was no evidence in this test of an external source IP performing the authentication attempts.

---

# ⏱️ Timeline Analysis

The failed authentication events were analyzed chronologically.

During detection validation, three failed authentication attempts occurred within the same 5-minute detection window.

The observed pattern was:

```text
Failed Login Attempt
        ↓
~2–3 seconds
        ↓
Failed Login Attempt
        ↓
~2–3 seconds
        ↓
Failed Login Attempt
        ↓
Detection Threshold Reached
        ↓
Splunk Alert Triggered
```

This behavior allowed the time-based detection rule to identify the repeated authentication failures.

---

# 🧑‍💻 Analyst Assessment

The observed authentication pattern is **consistent with password-guessing behavior** because multiple failed authentication attempts occurred for the same account within a short period.

However, the source address was `127.0.0.1`, and the authentication failures were intentionally generated as part of controlled detection testing.

### Final Assessment

**Controlled Lab Authentication Test**

There was **no confirmed external attack or account compromise** identified from this test.

The purpose of the activity was to validate the SOC detection and alerting workflow.

---

# 🎯 MITRE ATT&CK Mapping

The observed authentication pattern was mapped to the MITRE ATT&CK framework.

## Tactic

**Credential Access**

## Technique

**T1110 – Brute Force**

## Sub-technique

**T1110.001 – Password Guessing**

### Mapping Rationale

Repeated authentication attempts using incorrect passwords are consistent with the behavior described by the Password Guessing sub-technique.

In this project, the behavior was intentionally generated in a controlled lab environment for detection validation.

---

# 🛡️ Recommended SOC Response

If similar authentication activity were detected in a production environment, a SOC analyst could perform the following steps:

1. Validate whether the authentication attempts were authorized.
2. Identify the affected user account.
3. Investigate the source IP address.
4. Review successful logon events following the failed attempts.
5. Search for additional authentication anomalies.
6. Review related Windows Security Events.
7. Check whether the affected account shows other suspicious activity.
8. If malicious activity is confirmed, follow the organization's account containment procedures.
9. Continue monitoring the affected account and source for additional suspicious activity.
10. Document the investigation and escalate according to the organization's incident response process.

---

# 📊 Splunk Security Monitoring Dashboard

A Splunk Dashboard Studio dashboard was created to provide centralized visibility into Windows authentication activity.

## Dashboard Name

**SOC Home Lab - Security Monitoring**

## Dashboard Time Range

**Last 24 hours**

## Dashboard Panels

The dashboard contains:

- **Failed Windows Logins**
- **Successful Windows Logins**
- **Brute Force Detections**
- **Privileged Logons**
- **Failed Login Activity Over Time**

---

## 📸 Dashboard Evidence

![Splunk Security Monitoring Dashboard](01-splunk-dashboard.png)

---

# 📸 Project Evidence

The following screenshots provide evidence of the completed SOC monitoring and detection workflow.

### 1. Splunk Security Monitoring Dashboard

![Splunk Security Monitoring Dashboard](01-splunk-dashboard.png)

Centralized dashboard showing Windows authentication activity and security monitoring metrics.

---

### 2. Failed Login Investigation

![Failed Login Investigation](02-failed-login-investigation.png)

Investigation of Windows Event ID 4625 and authentication-related fields.

---

### 3. Brute-Force Detection Result

![Brute-Force Detection Result](03-bruteforce-detection-result.png)

Detection result identifying repeated failed authentication attempts for the same user and source.

---

### 4. Splunk Alert Configuration

![Splunk Alert Configuration](04-alert-configuration.png)

Scheduled Splunk alert configured to detect the authentication failure pattern.

---

### 5. Splunk Triggered Alert

![Splunk Triggered Alert](05-triggered-alert.png)

Triggered alert confirming successful detection validation.

---

# 🔄 SOC Detection & Investigation Workflow

```text
Windows Endpoint
       ↓
Windows Security Events
       ↓
Splunk SIEM
       ↓
Log Monitoring
       ↓
Detection Engineering
       ↓
3+ Failed Logins / 5 Minutes
       ↓
Scheduled Alert
       ↓
Alert Triggered
       ↓
Alert Triage
       ↓
Authentication Investigation
       ↓
Source Analysis
       ↓
MITRE ATT&CK Mapping
       ↓
Analyst Assessment
       ↓
Recommended Response
       ↓
Documentation
```

---

# 🧩 Skills Demonstrated

## SIEM & Security Monitoring

- Splunk Enterprise
- SIEM Monitoring
- Security Event Monitoring
- Windows Security Log Analysis

## Detection Engineering

- SPL
- Time-Based Detection
- Authentication Failure Detection
- Brute-Force Detection Logic
- Scheduled Security Alerts

## Investigation

- Alert Triage
- Windows Event Analysis
- Authentication Investigation
- Source IP Analysis
- Timeline Analysis
- Event Correlation

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

Through this project, I gained practical experience in:

- Collecting Windows Security Event Logs
- Monitoring authentication activity using Splunk
- Understanding Windows Security Event IDs
- Investigating failed authentication events
- Writing SPL queries for security monitoring
- Building time-based detection logic
- Configuring scheduled Splunk alerts
- Validating detections using controlled activity
- Investigating source and authentication information
- Performing basic alert triage
- Mapping observed behavior to MITRE ATT&CK
- Documenting security investigations
- Building a SOC monitoring dashboard
- Following an end-to-end SOC detection workflow

---

# ⚠️ Lab Disclaimer

This project was performed in a controlled home-lab environment for cybersecurity learning, detection engineering, and portfolio development.

All authentication failures used for detection validation were intentionally generated.

The observed activity should not be interpreted as a confirmed real-world attack.

No unauthorized systems were targeted as part of this project.

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
- [x] Project Documentation

---

# 👨‍💻 Project Summary

This project demonstrates a practical SOC monitoring, detection, alerting, and investigation workflow using **Splunk Enterprise** and **Windows Security Event Logs**.

The project covers the complete workflow:

**Log Collection → Monitoring → Detection → Alerting → Investigation → MITRE ATT&CK Mapping → Analyst Assessment → Response**

The project was completed in a controlled home-lab environment and focuses on demonstrating practical entry-level SOC Analyst skills through hands-on security monitoring and detection engineering.
