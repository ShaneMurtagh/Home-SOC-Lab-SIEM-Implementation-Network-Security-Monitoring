# 🏠 Home SOC Lab: SIEM Implementation & Network Security Monitoring

## 📋 Overview
A Windows-based SOC lab using **Splunk Enterprise** to detect brute force attacks mapped to the **MITRE ATT&CK framework**. This lab demonstrates practical security monitoring and threat detection skills.

## 🎯 Purpose
This lab showcases hands-on experience in:
- 🛡️ **SIEM implementation** (Splunk)
- 📊 **Windows Event Log** collection and analysis
- 🔍 **Threat detection** (brute force attacks)
- 🧠 **MITRE ATT&CK mapping** (T1110.001)
- 📝 **Security documentation** and incident response workflows

## 🧰 Lab Components
| Component | Description |
| :--- | :--- |
| **SIEM Platform** | Splunk Enterprise (free license) |
| **Data Sources** | Windows Event Logs (Security, Application, System) |
| **Detection Focus** | Brute force attacks (EventCode 4625) |
| **Threat Intelligence** | MITRE ATT&CK Framework mapping |

## 🎯 Detection Engineering: Brute Force Attack (T1110.001)

### 🧠 MITRE ATT&CK Mapping
| Attribute | Value |
| :--- | :--- |
| **Technique ID** | `T1110.001` |
| **Technique Name** | Brute Force: Password Guessing |
| **Tactic** | Credential Access |

### 🔎 Detection Logic
```spl
index=windows EventCode=4625
| stats count by ComputerName, Account_Name
| where count > 1
| eval technique_id="T1110.001"
| eval technique_name="Brute Force: Password Guessing"
| eval tactic="Credential Access"
| table ComputerName, Account_Name, count, technique_id, technique_name, tactic
