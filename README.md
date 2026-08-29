# Failed Login Attempts Analysis Using Splunk

## Project Overview

This project focuses on analyzing Windows Security Event Logs using Splunk to investigate failed login attempts.

## Objective

- Identify failed login attempts
- Analyze Windows Event ID 4625
- Investigate account names and source IP addresses
- Analyze logon types and failure reasons
- Compare failed logins with successful logins

## Tools Used

- Splunk
- Windows Event Logs
- Windows Security Logs

## Event IDs Analyzed

| Event ID | Description |
|---|---|
| 4625 | Failed Logon |
| 4624 | Successful Logon |

## Investigation

### 1. Failed Login Events

I searched for Windows Security Event ID 4625 to identify failed login attempts.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
```

A total of 5 failed login events were identified.

### 2. Failed Login Details

The following fields were analyzed:

- Time
- Computer Name
- Account Name
- Account Domain
- Source Network Address
- Logon Type
- Failure Reason

### 3. Successful vs Failed Logins

Successful and failed logon events were compared using the following query:

```spl
EventCode=4624 OR EventCode=4625
| stats count by EventCode
```

## Findings

- Total failed login events identified: 5
- Failed events originated from `127.0.0.1`
- The observed account was a machine/system account
- No clear evidence of an external brute-force attack was identified
- The observed activity may be related to local system authentication

## Conclusion

Five failed login attempts were identified and analyzed using Splunk. Based on the available logs, no confirmed evidence of an external brute-force attack was found. Continued monitoring of Event ID 4625 is recommended to identify unusual or repeated authentication failures.

## Skills Demonstrated

- Splunk Log Analysis
- Windows Event Log Analysis
- Authentication Monitoring
- Failed Login Investigation
- Basic SOC L1 Investigation
- SPL Query Writing
## Screenshots

### 1. Failed Login Events
![Failed Events](./Failed%20Events.png)

### 2. Failure Reason Analysis
![Failure Reason](./Failure%20Reason.png)

### 3. Account Name and Source IP Analysis
![Account Name and Source IP](./Account%20name%20and%20source%20id.png)

### 4. All Events Analysis
![All Events](./All%20events.png)

### 5. Successful Login Analysis
![Successful Login](./Successfull%20login.png)
