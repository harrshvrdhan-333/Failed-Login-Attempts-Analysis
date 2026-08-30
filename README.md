# 🔐 Failed Login Attempts Analysis Using Splunk

## 📌 Project Overview

This project demonstrates a **SOC L1 investigation of Windows authentication events using Splunk**.

The investigation focuses on failed login attempts, successful logons, authentication correlation, event timelines, and evaluation of potential brute-force activity.

The goal was to investigate the available evidence and determine whether the observed authentication activity was **benign, suspicious, or potentially malicious**.

---

## 🎯 Objectives

The main objectives of this investigation were to:

* Identify failed authentication attempts
* Analyze Windows Security Event ID **4625**
* Analyze successful authentication events using Event ID **4624**
* Investigate account names and source IP addresses
* Analyze Logon Types and Failure Reasons
* Correlate failed and successful authentication events
* Build an authentication event timeline
* Evaluate potential brute-force activity
* Determine the severity and final analyst verdict

---

## 🛠️ Tools & Technologies

* **Splunk Enterprise**
* **Windows Security Event Logs**
* **Windows Event ID 4624 & 4625**
* **SPL (Search Processing Language)**

---

## 📋 Event IDs Analyzed

| Event ID | Description      | Investigation Purpose                                    |
| -------- | ---------------- | -------------------------------------------------------- |
| **4625** | Failed Logon     | Identify unsuccessful authentication attempts            |
| **4624** | Successful Logon | Correlate successful authentication with failed attempts |

---

# 🔎 Investigation Methodology

The investigation followed a basic SOC L1 workflow:

```text
Windows Security Logs
        ↓
Identify Event ID 4625
        ↓
Analyze Account & Source IP
        ↓
Review Failure Reason & Logon Type
        ↓
Correlate 4625 with 4624
        ↓
Build Authentication Timeline
        ↓
Evaluate Brute-Force Indicators
        ↓
Determine Severity
        ↓
Final Analyst Verdict
```

---

# 1️⃣ Failed Login Investigation

The initial investigation searched for Windows Security Event ID **4625**.

### SPL Query

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
```

A total of **5 failed login events** were identified.

The following fields were reviewed:

* `_time`
* `Account_Name`
* `Account_Domain`
* `Source_Network_Address`
* `Logon_Type`
* `Failure_Reason`
* `ComputerName`

### Initial Finding

The observed failed authentication events originated from:

```text
127.0.0.1
```

The observed account was a **machine/system account**.

The failure reason observed in the investigated events included **Bad Password**.

### Evidence

![Failed Login Evidence](./screenshots/Failure%20Reason.png)

The evidence was reviewed to determine whether the failed authentication activity represented normal local authentication behavior or potential malicious activity.

---

# 2️⃣ Authentication Correlation — 4625 & 4624

To investigate whether failed authentication attempts were associated with successful logons, Event ID **4625** and **4624** were correlated.

### SPL Query

```spl
index=* sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| stats values(EventCode) as Events
        earliest(_time) as first_seen
        latest(_time) as last_seen
        count as total_events
        by Account_Name Source_Network_Address
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort - total_events
```

This analysis compares authentication events using:

* Account
* Source IP
* First observed time
* Last observed time
* Event IDs

### Finding

Both **4625 and 4624 events** were observed in the available authentication data.

The correlation was used to determine whether successful authentication occurred in the context of failed attempts.

### Evidence

![Authentication Correlation](./screenshots/Authentication%20Correlation.png)

---

# 3️⃣ Authentication Timeline

A timeline was created to examine the order in which authentication events occurred.

### SPL Query

```spl
index=* sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| table _time EventCode Account_Name Source_Network_Address Logon_Type Failure_Reason ComputerName
| sort _time
```

The timeline was reviewed to identify the sequence of failed and successful authentication events and to determine whether the events occurred close together in time.

### Investigation Focus

The following factors were considered:

* Was the account the same?
* Was the source IP the same?
* Did a successful 4624 occur after failed 4625 events?
* How close together were the events?
* Was the source local or external?

### Evidence

![Authentication Timeline](./screenshots/Authentication%20Timeline.png)

---

# 4️⃣ Brute-Force Detection Logic

Repeated failed authentication attempts from the same source and account may indicate potential brute-force activity.

### SPL Query

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count as failed_attempts by Source_Network_Address, Account_Name
| sort - failed_attempts
```

This query helps identify accounts or source addresses generating repeated failed authentication attempts.

A higher number of failures from the same source/account combination can be used as an indicator for further investigation.

> **Important:** Repeated failed logins alone do not automatically confirm a brute-force attack. Additional context such as source IP, account, timing, successful authentication, and surrounding events should be reviewed.

📄 **Detection query:** [brute-force-detection.spl](./queries/brute-force-detection.spl)

---

# 5️⃣ Investigation Findings

| Investigation Area        | Finding                                            |
| ------------------------- | -------------------------------------------------- |
| Failed Logons             | **5 events identified**                            |
| Failed Logon Event ID     | **4625**                                           |
| Successful Logon Event ID | **4624**                                           |
| Observed Source Address   | **127.0.0.1**                                      |
| Observed Account          | **Machine/System account**                         |
| Failure Reason            | **Bad Password observed**                          |
| External Source IP        | **Not observed in the investigated failed events** |
| Brute Force               | **Not confirmed**                                  |

---

# 🚦 Severity Assessment

### Severity: **Low**

### Reasoning

The investigated failed authentication events originated from the local loopback address:

```text
127.0.0.1
```

The observed account was a machine/system account.

Although failed and successful authentication events were present in the broader authentication data, the available evidence did not establish a confirmed external brute-force attack.

Therefore, the activity was assessed as **Low severity based on the available evidence**.

---

# 🛡️ MITRE ATT&CK Mapping

### Technique Evaluated

**T1110 — Brute Force**

This technique was evaluated because repeated failed authentication attempts can be associated with password guessing or brute-force activity.

However, **T1110 was not confirmed** in this investigation because the available evidence did not demonstrate a confirmed external brute-force attack.

---

# 🧑‍💻 Analyst Verdict

> **Verdict: No confirmed malicious activity**

Five failed authentication events were identified and investigated.

The investigation examined the source address, account, failure reason, successful authentication events, and event timing.

The observed failed events originated from `127.0.0.1` and involved a machine/system account. Based on the available evidence, there was no confirmed indication of an external attacker or confirmed brute-force activity.

The activity was therefore classified as **Low severity / No confirmed malicious activity**.

---

# 💡 Recommendations

The following actions are recommended for continued monitoring:

1. Monitor repeated Event ID **4625** events from external source IP addresses.
2. Investigate multiple failed attempts against the same account.
3. Correlate **4625 → 4624** authentication sequences.
4. Investigate successful logons occurring shortly after repeated failures.
5. Monitor authentication failures involving privileged accounts.
6. Review unusual Logon Types and authentication patterns.
7. Create threshold-based Splunk alerts for repeated authentication failures.

---

# 📸 Investigation Evidence

All investigation screenshots are stored in the [`screenshots`](./screenshots/) directory.

### 1. Failed Login / Bad Password Evidence

![Failure Reason](./screenshots/Failure%20Reason.png)

Shows the failure reason associated with the investigated failed authentication events.

---

### 2. Authentication Correlation

![Authentication Correlation](./screenshots/Authentication%20Correlation.png)

Shows the correlation of Event ID 4625 and Event ID 4624 using account and source information.

---

### 3. Authentication Timeline

![Authentication Timeline](./screenshots/Authentication%20Timeline.png)

Shows authentication events in chronological order for timeline-based investigation.

---

# 🧠 Skills Demonstrated

* Splunk Log Analysis
* SPL Query Writing
* Windows Security Event Log Analysis
* Event ID 4624 & 4625 Analysis
* Authentication Monitoring
* Failed Login Investigation
* Authentication Correlation
* Timeline Analysis
* Brute-Force Detection Logic
* Alert Triage
* Security Investigation
* MITRE ATT&CK Mapping
* SOC L1 Investigation Methodology

---

# 📝 Conclusion

This project demonstrates a **SOC L1 authentication investigation using Splunk**.

The investigation identified five failed Windows authentication events and analyzed their account, source address, failure reason, authentication type, and surrounding authentication activity.

Event ID **4625** was correlated with Event ID **4624**, and the authentication timeline was reviewed to understand the relationship between failed and successful logons.

The investigated failed events originated from `127.0.0.1` and involved a machine/system account. Based on the available evidence, no confirmed external brute-force attack was identified.

This investigation demonstrates the importance of **correlation, timeline analysis, and evidence-based classification rather than automatically labeling failed logins as malicious activity**.
