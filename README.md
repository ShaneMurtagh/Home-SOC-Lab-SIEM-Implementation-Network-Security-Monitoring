# 🏠 Home SOC Lab: SIEM Implementation & Network Security Monitoring

## 📋 Overview
A Windows-based SOC lab using **Splunk Enterprise** to detect brute force attacks mapped to the **MITRE ATT&CK framework**. This lab demonstrates practical security monitoring and threat detection skills.

<br>

## 🎯 Purpose
This lab showcases hands-on experience in:
- 🛡️ **SIEM implementation** (Splunk)
- 📊 **Windows Event Log** collection and analysis
- 🔍 **Threat detection** (brute force attacks)
- 🧠 **MITRE ATT&CK mapping** (T1110.001)
- 📝 **Security documentation** and incident response workflows

<br>

## 🧰 Lab Components

| Component | Description |
| :--- | :--- |
| **SIEM Platform** | Splunk Enterprise (free license) |
| **Data Sources** | Windows Event Logs (Security, Application, System) |
| **Detection Focus** | Brute force attacks (EventCode 4625) |
| **Threat Intelligence** | MITRE ATT&CK Framework mapping |

<br>

## 🎯 Detection Engineering: Brute Force Attack (T1110.001)

<br>

### 🧠 MITRE ATT&CK Mapping

| Attribute | Value |
| :--- | :--- |
| **Technique ID** | `T1110.001` |
| **Technique Name** | Brute Force: Password Guessing |
| **Tactic** | Credential Access |

<br>

### 🔎 Detection Logic

    index=windows EventCode=4625
    | stats count by ComputerName, Account_Name
    | where count > 1
    | eval technique_id="T1110.001"
    | eval technique_name="Brute Force: Password Guessing"
    | eval tactic="Credential Access"
    | table ComputerName, Account_Name, count, technique_id, technique_name, tactic

<br>

### ⚠️ What It Detects
Multiple failed login attempts from the same source, indicating a potential brute force attack against local accounts.

<br>

## 📸 Screenshots

<br>

### 1. Splunk Data Ingestion
![Splunk Data](<img width="1228" height="723" alt="splunk11" src="https://github.com/user-attachments/assets/6b4e511d-d8ed-435f-b608-20067d832376" />
)
*Splunk actively collecting Windows Event Logs with 2,000+ events*

<br>

### 2. Failed Login Detection
![Failed Logins](<img width="1227" height="709" alt="splunk22" src="https://github.com/user-attachments/assets/efcc9e4b-d5f3-448b-9443-0ec16f0d1bc6" />
)
*EventCode 4625 events showing failed authentication attempts*

<br>

### 3. MITRE-Mapped Detection Results
![MITRE T1110 Detection](./03_mitre_mapping.png)
*Detection results enriched with MITRE ATT&CK context (T1110.001)*

<br>

## 📚 What I Learned

Building this lab taught me:

| Skill | Description |
| :--- | :--- |
| **Splunk Installation & Configuration** | Installing Splunk Enterprise, setting up indexes, and configuring data inputs |
| **Windows Event Log Analysis** | Understanding Event Codes (4625 for failed logins) and extracting meaningful security data |
| **Threat Detection Engineering** | Creating correlation searches to identify brute force patterns |
| **MITRE ATT&CK Mapping** | Enriching alerts with technique IDs (T1110.001), names, and tactics |
| **Documentation** | Recording setup steps, detection logic, and findings professionally |

<br>

<br>

## 👨‍💻 About This Project

Built as part of my journey into cybersecurity. I'm a career changer from **construction**,
<br>

## 📬 Connect With Me

| Platform | Link |
| :--- | :--- |
| **LinkedIn** | [linkedin.com/in/shane-murtagh](https://www.linkedin.com/in/shane-murtagh/) |
| **Email** | shanemurtagh@protonmail.com |

<br>

## 📝 License
This project is for educational purposes only.

