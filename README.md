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

### 1. Failed Login Events

I searched for Windows Security Event ID 4625 to identify failed login attempts.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
