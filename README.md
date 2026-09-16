# SOC Home Lab – Windows Security Monitoring & Brute-Force Detection

## 📌 Project Overview

Built a hands-on Security Operations Center (SOC) home lab using Splunk Enterprise to collect, monitor, investigate, and detect suspicious Windows authentication activity.

The project demonstrates an end-to-end SOC workflow:

Windows Security Logs → SIEM → Detection Engineering → Alerting → Investigation → MITRE ATT&CK Mapping → Response

## 🎯 Objectives

- Collect Windows Security Event Logs in Splunk
- Monitor authentication activity
- Investigate failed and successful logons
- Develop a brute-force detection rule
- Configure a scheduled security alert
- Validate the detection using controlled lab activity
- Map the detected behavior to MITRE ATT&CK
- Document investigation findings and response recommendations

## 🛠️ Technologies & Tools

- Splunk Enterprise 10.4.3
- Windows 11
- Windows Event Logs
- SPL (Splunk Search Processing Language)
- VMware
- MITRE ATT&CK

## 🔍 Windows Events Investigated

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Special Privileges Assigned to New Logon |

## 🚨 Detection Engineering

### Detection Objective

Detect 3 or more failed Windows logon attempts for the same user and source within a 5-minute window.

### SPL Detection

```spl
index=* sourcetype=WinEventLog:Security EventCode=4625
| eval User_Account=mvfilter(Account_Name!="DHIRAJ-WIN11$")
| where isnotnull(User_Account)
| bin _time span=5m
| stats count as failed_attempts by _time User_Account Source_Network_Address
| where failed_attempts >= 3
| sort - failed_attempts
