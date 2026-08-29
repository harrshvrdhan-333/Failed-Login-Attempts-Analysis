# 🔐 Failed Login Attempts Analysis Using Splunk

## 📌 Project Overview

This project demonstrates a **SOC L1 investigation of failed Windows authentication attempts** using Splunk.

Windows Security Event Logs were analyzed to identify failed login activity, investigate the associated accounts and source addresses, analyze authentication details, and determine whether the observed activity indicated potential malicious behavior.

---

## 🎯 Objective

The primary objectives of this investigation were to:

* Identify failed authentication attempts
* Analyze Windows Security **Event ID 4625**
* Investigate affected accounts
* Analyze source network addresses
* Analyze Logon Types and Failure Reasons
* Compare failed authentication events with successful logons
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

| Event ID | Description      | Purpose                                                  |
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
Analyze Authentication Details
        ↓
Investigate Account & Source Address
        ↓
Review Failure Reason & Logon Type
        ↓
Compare 4625 with 4624
        ↓
Evaluate Brute-Force Indicators
        ↓
Determine Severity
        ↓
Final Analyst Verdict
```

---

# 1️⃣ Identify Failed Login Attempts

The first step was to search for Windows Security Event ID **4625**, which represents a failed logon attempt.

### SPL Query

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
```

### Result

A total of **5 failed login events** were identified.

---

# 2️⃣ Analyze Failed Login Details

The following fields were reviewed during the investigation:

| Field                    | Purpose                                           |
| ------------------------ | ------------------------------------------------- |
| `_time`                  | Identify when the authentication occurred         |
| `ComputerName`           | Identify the affected host                        |
| `Account_Name`           | Identify the account involved                     |
| `Account_Domain`         | Identify the account domain                       |
| `Source_Network_Address` | Identify the source of the authentication attempt |
| `Logon_Type`             | Understand the authentication method              |
| `Failure_Reason`         | Determine why authentication failed               |

This information helps determine whether the failed authentication was caused by normal system activity or potentially malicious behavior.

---

# 3️⃣ Source IP & Account Investigation

The identified failed login events originated from:

```text
127.0.0.1
```

The observed account was a **machine/system account**.

Because the source address was the local loopback address rather than an external IP address, there was **no clear evidence of an external attacker** based on the available logs.

The activity may be associated with local system authentication or an application/service running on the host.

---

# 4️⃣ Failure Reason Analysis

The failure reasons associated with the Event ID 4625 entries were reviewed to understand why the authentication attempts failed.

Analyzing failure reasons can help distinguish between:

* Incorrect credentials
* Invalid accounts
* Expired credentials
* Service/application authentication issues
* Potential password-guessing activity

The observed events did not provide sufficient evidence to confirm malicious authentication activity.

---

# 5️⃣ Successful vs Failed Login Analysis

Successful and failed authentication events were also reviewed.

### SPL Query

```spl
index=* sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| stats count by EventCode
```

This comparison helps determine whether failed authentication attempts were followed by successful logons.

A pattern involving multiple failed attempts followed by a successful login can warrant further investigation for potential credential compromise.

---

# 6️⃣ Brute-Force Detection Logic

Repeated failed authentication attempts from the same source can be an indicator of potential brute-force activity.

The following SPL query can be used to identify repeated failed attempts by source and account:

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count as failed_attempts by Source_Network_Address, Account_Name
| sort - failed_attempts
```

This type of detection can help a SOC analyst identify accounts or source addresses generating an unusual number of failed authentication attempts.

**Note:** The current dataset did not provide sufficient evidence to classify the observed activity as a confirmed brute-force attack.

---

# 📊 Investigation Findings

| Investigation Area          | Finding                    |
| --------------------------- | -------------------------- |
| Failed Logons               | **5 events identified**    |
| Event ID                    | **4625**                   |
| Source Address              | **127.0.0.1**              |
| Account                     | **Machine/System account** |
| External Source IP          | **Not observed**           |
| Brute Force                 | **Not confirmed**          |
| Evidence of External Attack | **Not identified**         |

---

# 🚦 Severity Assessment

### Severity: **Low**

### Reasoning

The observed failed authentication events originated from the local loopback address (`127.0.0.1`) and involved a machine/system account.

No external source IP or other clear indicators of an external brute-force attack were identified in the available logs.

Therefore, the activity was assessed as **Low severity** based on the current evidence.

---

# 🛡️ MITRE ATT&CK Mapping

### Technique Evaluated

**T1110 — Brute Force**

This technique was evaluated because repeated failed authentication attempts can be associated with password guessing or brute-force attacks.

However, **T1110 was not confirmed** in this investigation because the available evidence did not demonstrate an external brute-force attack.

---

# 🧑‍💻 Analyst Verdict

> **Verdict: No confirmed malicious activity**

Five failed authentication events were identified and investigated.

The events originated from `127.0.0.1` and involved a machine/system account. Based on the available evidence, there was no clear indication of an external attacker or confirmed brute-force activity.

The activity is therefore considered **low severity and potentially related to local system authentication**.

---

# 💡 Recommendations

A SOC analyst should continue monitoring authentication activity for:

1. Repeated Event ID **4625** from external IP addresses.
2. Multiple failed attempts against the same user account.
3. Failed logins followed by successful **Event ID 4624**.
4. Authentication failures involving privileged accounts.
5. Unusual Logon Types or authentication patterns.
6. Repeated authentication failures across multiple accounts.

Additional investigation should be performed if future events reveal external source addresses, abnormal authentication patterns, or successful logons following repeated failures.

---

# 📸 Investigation Evidence

### 1. Failed Login Events

![Failed Events](./Failed%20Events.png)

Shows the Windows Security Event ID 4625 events identified during the investigation.

---

### 2. Failure Reason Analysis

![Failure Reason](./Failure%20Reason.png)

Shows the failure reasons associated with the failed authentication events.

---

### 3. Account Name & Source IP Analysis

![Account Name and Source IP](./Account%20name%20and%20source%20id.png)

Shows the account and source network address associated with the authentication attempts.

---

### 4. All Events Analysis

![All Events](./All%20events.png)

Shows the broader authentication event data reviewed during the investigation.

---

### 5. Successful Login Analysis

![Successful Login](./Successfull%20login.png)

Shows successful authentication events reviewed for correlation with failed login activity.

---

# 🧠 Skills Demonstrated

* Splunk Log Analysis
* SPL Query Writing
* Windows Security Event Log Analysis
* Authentication Monitoring
* Event ID 4624 & 4625 Analysis
* Failed Login Investigation
* Basic Brute-Force Detection
* Alert Triage
* Security Investigation
* MITRE ATT&CK Mapping
* SOC L1 Investigation Methodology

---

# 📝 Conclusion

This project demonstrates a basic **SOC L1 authentication investigation using Splunk**.

Five failed Windows authentication events were identified and analyzed using Event ID 4625. The investigation examined the affected account, source address, failure reasons, and authentication patterns.

The observed events originated from `127.0.0.1` and involved a machine/system account. No confirmed evidence of an external brute-force attack was identified.

The investigation highlights the importance of **correlating authentication events and analyzing contextual evidence before classifying an alert as malicious**.
