# Sentinel-Lab-05-Suspicious-Signin-Endpoint-Activity

## Overview

A suspicious sign-in becomes significantly more important when it is followed by unusual activity on the associated endpoint. Instead of investigating the authentication event in isolation, the analyst correlates:

- User sign-in
- Source IP and location
- Authentication result
- Device/host
- Process execution
- PowerShell or other suspicious endpoint activity
- Timing between the identity and endpoint events

This lab investigates whether a suspicious authentication event is followed by potentially related activity on a Windows endpoint.

The investigation moves beyond analyzing identity or endpoint telemetry separately. It correlates **user, computer, authentication time, source IP, location, and process execution** to determine whether events occurring close together may represent a related security incident.

> **Investigation principle:** Correlation strengthens an investigation, but correlation alone does not prove causation.

---

## Investigation Scenario

A SOC analyst is investigating a potentially suspicious authentication event involving `user1@sentinellab.local`. The account successfully authenticates from **New York**, after which activity appears on the associated Windows endpoint.

The analyst needs to determine whether the endpoint activity is potentially related to the preceding sign-in rather than treating the two events independently.

The investigation focuses on:

- The identity involved and associated endpoint.
- Authentication timestamp, source IP, and location.
- Endpoint process execution following the sign-in.
- The parent process responsible for launching PowerShell.
- Suspicious PowerShell parameters such as `-ExecutionPolicy Bypass` and `-EncodedCommand`.
- The time difference between the authentication and endpoint events.

The primary sequence shows a successful sign-in at **10:00 UTC**, followed by PowerShell execution on `DESKTOP-LAB01` at **10:08 UTC**. The events share the same user and endpoint context, creating a potentially meaningful correlation.

The analyst must assess whether this sequence represents suspicious activity while keeping **correlation separate from causation** and documenting what the available telemetry can and cannot establish.

---

## Lab Objectives

The objectives of this lab are to:

- Examine how identity and endpoint events can be investigated as part of the same security timeline.
- Identify useful fields for correlating authentication and process activity.
- Establish whether two events are connected through **user and host context**.
- Measure the time interval between a successful sign-in and subsequent endpoint activity.
- Analyze whether suspicious endpoint behavior follows an authentication event closely enough to warrant investigation.
- Compare correlated activity with other user and endpoint events to establish context.
- Apply KQL filtering and projection techniques to isolate relevant events.
- Distinguish **event correlation from confirmed causation**.
- Classify observations as confirmed, plausible, or unknown based on available telemetry.
- Identify additional identity and endpoint data required to validate a suspected security incident.

---

## Environment

| Component | Details |
|---|---|
| Platform | Microsoft Sentinel |
| Workspace | `Microsoft-Sentinel-Workspace` |
| Query Language | KQL |
| Data Type | Synthetic telemetry |
| Primary Host | `DESKTOP-LAB01` |
| Primary User | `user1@sentinellab.local` |
| Investigation Date | 2026-09-15 |

---

## Data Source

Persistent Entra sign-in and endpoint telemetry was not available for this investigation.

Therefore, synthetic authentication and process data was created using KQL `datatable()`.

The datasets are temporary and exist only within the individual queries where they are defined.

The lab does not represent real production telemetry.

---

## Investigation Workflow

The investigation followed this sequence:

1. Review successful sign-ins.
2. Identify the primary user and endpoint.
3. Review endpoint process activity.
4. Filter for PowerShell execution.
5. Examine the parent process and command line.
6. Compare the authentication and endpoint timestamps.
7. Correlate the user and computer.
8. Assess whether the sequence is suspicious.
9. Review evidence limitations and false positives.
10. Assign a final investigation verdict.

---

## Step 1 — Review Successful Sign-ins

The authentication dataset contains three successful sign-ins.

The query used was:

    | where ResultType == 0
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, Computer
    | order by TimeGenerated asc

### Observed Results

| Time | User | IP Address | Location | Computer |
|---|---|---|---|---|
| 10:00 UTC | user1@sentinellab.local | 203.0.113.25 | New York | DESKTOP-LAB01 |
| 10:02 UTC | user2@sentinellab.local | 10.10.10.30 | Hyderabad | DESKTOP-LAB02 |
| 10:05 UTC | user3@sentinellab.local | 10.10.10.40 | Mumbai | DESKTOP-LAB03 |

The primary investigation target is `user1@sentinellab.local`.

---

## Step 2 — Review Endpoint Activity

The endpoint dataset contains activity from all three systems.

Filtering for PowerShell produced:

| Time | Computer | User | Parent | Process |
|---|---|---|---|---|
| 10:08 UTC | DESKTOP-LAB01 | user1 | winword.exe | powershell.exe |
| 13:00 UTC | DESKTOP-LAB02 | user2 | explorer.exe | powershell.exe |

The `user1` event is the primary endpoint finding.

---

## Step 3 — Analyze the Primary Endpoint Event

The suspicious event occurred at:

**2026-09-15 10:08 UTC**

Observed context:

| Field | Value |
|---|---|
| Computer | `DESKTOP-LAB01` |
| User | `user1` |
| Parent Process | `winword.exe` |
| Process | `powershell.exe` |
| Parameters | `-ExecutionPolicy Bypass -EncodedCommand` |

This is the same suspicious PowerShell pattern investigated in Sentinel Lab 04.

---

## Step 4 — Correlate Authentication and Endpoint Activity

The primary sequence is:

    10:00 UTC
    user1@sentinellab.local
    Successful sign-in
    New York
    DESKTOP-LAB01

    10:08 UTC
    user1
    DESKTOP-LAB01
    winword.exe → powershell.exe
    ExecutionPolicy Bypass + EncodedCommand

The authentication and endpoint events share:

- Same user context.
- Same computer.
- Close timestamps.

---

## Step 5 — Calculate the Time Relationship

The successful sign-in occurred at:

**10:00 UTC**

The suspicious PowerShell event occurred at:

**10:08 UTC**

The observed time difference is:

**8 minutes**

For this training lab, a short interval is used as a correlation condition.

A short time gap does not prove that one event caused the other.

---

## Step 6 — Compare Other Activity

The remaining events provide useful comparison activity.

`user2`:

    10:02 UTC — Successful sign-in
    13:00 UTC — explorer.exe → powershell.exe
    Get-Service

The three-hour gap and ordinary administrative command provide less immediate correlation than the `user1` sequence.

`user3`:

    10:05 UTC — Successful sign-in
    13:05 UTC — explorer.exe → cmd.exe
    ipconfig

This activity also occurs several hours after authentication.

---

## Primary Finding

The strongest sequence is:

    Successful sign-in
    ↓
    user1 / DESKTOP-LAB01
    ↓
    8 minutes
    ↓
    winword.exe
    ↓
    powershell.exe
    ↓
    -ExecutionPolicy Bypass
    -EncodedCommand

The combination of identity correlation, timing, parent process, and PowerShell parameters makes this sequence suspicious.

---

## Investigation Verdict

**Verdict: Suspicious — Sign-in Followed by Potentially Malicious Endpoint Activity**

The evidence supports further investigation.

However, the available synthetic data does not establish that the sign-in was unauthorized or that the endpoint was compromised.

---

## Evidence Assessment

| Evidence | Assessment |
|---|---|
| Successful sign-in for user1 | Confirmed |
| Sign-in associated with DESKTOP-LAB01 | Confirmed |
| PowerShell executed on DESKTOP-LAB01 | Confirmed |
| `winword.exe` launched PowerShell | Confirmed |
| `-ExecutionPolicy Bypass` present | Confirmed |
| `-EncodedCommand` present | Confirmed |
| Eight-minute temporal relationship | Confirmed |
| Sign-in caused endpoint activity | Unknown |
| Sign-in was unauthorized | Unknown |
| Malicious payload executed | Unknown |
| System compromise | Unknown |

---

## False-Positive Considerations

Possible legitimate explanations include:

- Authorized user activity.
- VPN or proxy-related authentication behavior.
- Enterprise document automation.
- Authorized PowerShell scripts.
- Security testing.
- Administrative workflows.

The identity event should therefore be investigated together with endpoint and user context.

---

## Evidence Gaps

Important telemetry was not available in this lab:

- MFA result.
- Conditional Access result.
- Device identity and compliance.
- Sign-in risk.
- Authentication method.
- PowerShell Script Block Logging.
- Child-process activity.
- Network connections.
- File creation or modification.
- Endpoint detection alerts.
- Actual decoded command content.

---

## MITRE ATT&CK

**T1059.001 — Command and Scripting Interpreter: PowerShell**

The endpoint activity involves PowerShell execution.

The technique mapping describes the observed execution mechanism and does not independently prove malicious activity.

---

