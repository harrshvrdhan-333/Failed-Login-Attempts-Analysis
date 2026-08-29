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
|----------|-------------|
| 4625 | Failed Logon |
| 4624 | Successful Logon |

## Investigation

### Failed Login Events

I searched for Windows Security Event ID 4625 to identify failed login attempts.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
# Failed Login Attempts Analysis Using Splunk

...poora README content...

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
![Account Name and Source ID](./Account%20name%20and%20source%20id.png)

### 4. All Events Analysis
![All Events](./All%20events.png)

### 5. Successful Login Analysis
![Successful Login](./Successfull%20login.png)
