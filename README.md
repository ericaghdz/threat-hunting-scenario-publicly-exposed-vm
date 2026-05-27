# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

---

# Threat Hunting Scenario #1: Searching for Brute Force Attempts on a Publicly Exposed Virtual Machine

In this project, we simulated a scenario to seek out Virtual Machines running on the Microsoft Azure platform that may have been mistakenly exposed to the public internet. As a Security Analyst, I was tasked with identifying which of these machines, if any, were exposed. Once identified, I searched through various logs for signs of successful brute force attacks. 

---

# Technology Utilized
- Microsoft Defender for Endpoint | Endpoint Detection & Response (EDR) platform 
- Kusto Query Language (KQL) | Log Querying & Analytics
- Microsoft Azure Virtual Machines (VM)

# Cybersecurity Framework
- MITRE ATT&CK Framework | Mapping to relevant tactics, techniques, & procedures (TTPs)

---

## Table of Contents
* [Step 1: Confirm Internet Exposure of Target Device](#step-1-confirm-internet-exposure-of-target-device)
* [Step 2: Identify Top Source IPs Associated with Failed Logon Attempts](#step-2-identify-top-source-ips-associated-with-failed-logon-attempts)
* [Step 3: Determine Whether Top Failed IPs Successfully Authenticated](#step-3-determine-whether-top-failed-ips-successfully-authenticated)
* [Step 4: Validate Successful Logons to Legitimate User Account](#step-4-validate-successful-logons-to-legitimate-user-account)
* [Step 5: Review Successful Authentication Activity](#step-5-review-successful-authentication-activity)
* [Conclusion](#conclusion)
* [Relevant MITRE ATT&CK Techniques](#relevant-mitre-attck-techniques)
* [Response and Mitigation Actions](#response-and-mitigation-actions)
* [Threat Hunt Process Improvements](#threat-hunt-process-improvements)

---

## Step 1: Confirm Internet Exposure of Target Device

A query was executed to determine whether the target system had been publicly exposed to the internet.

### KQL Query
```kql
// Confirm whether target device has been internet-facing
let honeypot = "windows-target-";
DeviceInfo
| where DeviceName == honeypot
| where IsInternetFacing == true
| order by Timestamp desc
```

### Findings
The `windows-target-1` VM was confirmed to be internet-facing for several consecutive days, increasing exposure to unsolicited external authentication attempts and potential malicious activity.

**Last observed internet-facing timestamp:**
- May 26, 2026 6:59:51 PM

**Approximate investigation time:**
- May 26, 2026 7:03:55 PM

> **Important Note:** Microsoft Defender truncates `DeviceName` values after 15 characters. Due to this limitation, the queries I used targeted `windows-target-` rather than the full hostname `windows-target-1`.

_________________________

## Step 2: Identify Top Source IPs Associated with Failed Logon Attempts

A query was conducted to identify the top external IP addresses responsible for failed authentication attempts against the `windows-target-1` VM over the previous seven days.

### KQL Query
```kql
// Retrieve top 10 IPs involved in failed logon attempts to windows-target-1
let honeypot = "windows-target-";
DeviceLogonEvents
| where DeviceName == honeypot
| where LogonType has_any ("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc
| take 10
```

### Findings

<img width="850" alt="image" src="Screenshot 2026-05-26 190047.png">

The following IP addresses generated the highest number of failed authentication attempts within the previous seven days:

| Remote IP | Failed Attempts |
|------------|----------------|
| `159.100.20.23` | 64 |
| `51.178.174.31` | 61 |
| `102.88.21.214` | 55 |
| `54.151.176.0` | 47 |
| `188.246.226.124` | 46 |
| `135.125.90.97` | 36 |
| `45.238.132.30` | 32 |
| `95.213.184.95` | 31 |
| `211.229.255.252` | 29 |
| `188.68.217.132` | 23 |

The repeated failed logon attempts from multiple external IP addresses are consistent with **brute force password spraying or credential guessing activity** targeting an exposed system.

_________________________

## Step 3: Determine Whether Top Failed IPs Successfully Authenticated

A follow-up query was executed to determine whether any of the top offending IP addresses were able to successfully authenticate to the target system.

### KQL Query
```kql
// Investigate whether top failed IPs later succeeded in authentication
let RemoteIPs = dynamic([
    "159.100.20.23",
    "51.178.174.31",
    "102.88.21.214",
    "54.151.176.0",
    "188.246.226.124",
    "135.125.90.97",
    "45.238.132.30",
    "95.213.184.95",
    "211.229.255.252",
    "188.68.217.132"
]);
DeviceLogonEvents
| where LogonType has_any ("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPs)
```

### Findings

<img width="850" alt="image" src="Screenshot 2026-05-26 191502.png">

No successful authentication attempts were returned from the query results.

This indicates that **none of the top 10 external IP addresses responsible for failed logon activity successfully authenticated to the system**, reducing the likelihood of a successful brute force compromise originating from these sources.

_________________________

## Step 4: Validate Successful Logons to Legitimate User Account

The investigation shifted toward validating all successful network logons associated with the legitimate user account `labuser0`.

### KQL Query — Successful Logons
```kql
// Determine successful logon attempts to labuser0
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where DeviceName == "windows-target-"
| where AccountName == "labuser0"
| summarize count()
```

### Findings
A total of **3 successful logons** to the `labuser0` account were identified on `windows-target-1` during the previous 30 days.

### KQL Query — Failed Logons
```kql
// Determine failed logon attempts to labuser0
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where DeviceName == "windows-target-"
| where AccountName == "labuser0"
| summarize count()
```

### Findings
A total of **0 failed authentication attempts** were observed against the `labuser0` account during the previous 30 days.

This significantly reduces the likelihood that the legitimate account was targeted or compromised through brute force activity.

_________________________

## Step 5: Review Successful Authentication Activity

A final review was conducted on successful authentication events associated with the `labuser0` account to determine whether any suspicious characteristics were present.

### KQL Query
```kql
// Investigate successful logons to labuser0
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where DeviceName == "windows-target-"
| where AccountName == "labuser0"
| summarize LogonCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

### Findings
Manual review of all three successful logon events associated with `labuser0` showed normal and expected activity. No indicators of suspicious behavior, anomalous access patterns, or unauthorized usage were identified.

_________________________

## Conclusion

Although `windows-target-1` was publicly exposed to the internet and experienced repeated failed authentication attempts indicative of brute force behavior, there is **no evidence of successful unauthorized access** at this time.

Key conclusions include:

- The VM was internet-facing for multiple days, increasing attack surface exposure.
- Multiple external IP addresses attempted repeated failed authentications consistent with brute force or credential guessing activity.
- None of the highest-volume offending IP addresses successfully authenticated.
- The legitimate account `labuser0` experienced only successful, expected logons with no associated failed attempts.
- No suspicious activity was identified during review of authenticated sessions.

Based on available telemetry, the activity appears to represent **unsuccessful brute force attempts against an exposed system rather than a confirmed compromise**.

_________________________

## Relevant MITRE ATT&CK Techniques

| Technique ID | Technique | Relevance |
|--------------|-----------|------------|
| **T1190** | Exploit Public-Facing Application | Target system was internet-facing and externally exposed |
| **T1110** | Brute Force | Repeated failed authentication attempts from multiple IP addresses |
| **T1078** | Valid Accounts | Successful logons observed from the legitimate `labuser0` account |

_________________________

## Response and Mitigation Actions

Although no successful compromise was identified, several hardening measures were implemented to reduce future risk exposure:

- Restricted inbound Remote Desktop Protocol (RDP) access using an Azure Network Security Group (NSG) to allow only authorized connections.
- Implemented an account lockout policy to limit repeated authentication failures and mitigate brute force attempts.
- Reduced the VM’s external attack surface by limiting unnecessary internet exposure and strengthening access controls.

_________________________

## Threat Hunt Process Improvements

After review of the threat hunt process, an area of improvement in KQL syntax was identified in `Step 3: Determine Whether Top Failed IPs Successfully Authenticated`. 

Recall that the KQL query used in Step 3 was used to investigate the list of 10 IPs with the highest failed logon attempts. 
```kql
// Investigate whether top failed IPs later succeeded in authentication
let RemoteIPs = dynamic([
    "159.100.20.23",
    "51.178.174.31",
    "102.88.21.214",
    "54.151.176.0",
    "188.246.226.124",
    "135.125.90.97",
    "45.238.132.30",
    "95.213.184.95",
    "211.229.255.252",
    "188.68.217.132"
]);
DeviceLogonEvents
| where LogonType has_any ("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPs)
```
Although this query worked sufficiently for the purposes of this threat hunt, the line `| where RemoteIP has_any(RemoteIPs)` should be `| where RemoteIP in (RemoteIPs)`. 

Why?
- `has_any` is generally used for searching inside multi-value fields or text blobs
- `in` is more appropriately used for explicit value matching against a list

This slight change in syntax will be incorporated into future threat hunts for cleaner and semantically clearer querying.
