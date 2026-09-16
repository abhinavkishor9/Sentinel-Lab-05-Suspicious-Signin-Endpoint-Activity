# Sentinel Lab 05 — Suspicious Sign-in + Endpoint Activity

## Overview

This lab investigates whether a suspicious authentication event is followed by potentially related activity on a Windows endpoint.

The investigation moves beyond analyzing identity or endpoint telemetry separately. It correlates **user, computer, authentication time, source IP, location, and process execution** to determine whether events occurring close together may represent a related security incident.

> **Investigation principle:** Correlation strengthens an investigation, but correlation alone does not prove causation.

---

## Investigation Scenario

A successful sign-in is observed for `user1@sentinellab.local` from New York. Eight minutes later, the associated endpoint `DESKTOP-LAB01` records PowerShell execution launched by `winword.exe`.

The PowerShell command contains `-ExecutionPolicy Bypass` and `-EncodedCommand`, creating a potential link between the authentication event and suspicious endpoint activity.

The investigation compares this sequence with activity from other users to determine whether the observed behavior warrants escalation.

---

## Lab Objectives

- Review successful authentication activity.
- Identify the user, source IP, location, and associated endpoint.
- Review endpoint process execution for the same environment.
- Correlate identity and endpoint activity using user and computer context.
- Measure the time between authentication and endpoint activity.
- Investigate suspicious PowerShell execution characteristics.
- Compare the primary sequence with other activity in the dataset.
- Assess whether the events are potentially related.
- Document confirmed evidence, plausible relationships, and unknowns.
- Avoid treating temporal correlation as proof of compromise.

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

## Key SOC Lesson

Identity and endpoint events become more useful when they are correlated using multiple fields.

The primary sequence combines:

**User + Computer + Time + Process + Command Line**

This provides a stronger investigation lead than analyzing the sign-in or PowerShell event independently.

---

## Lab Outcome

This lab demonstrated how to:

- Review successful sign-in activity.
- Review endpoint process execution.
- Correlate identity and endpoint telemetry.
- Measure the time between related events.
- Analyze suspicious PowerShell context.
- Compare primary and baseline activity.
- Separate confirmed evidence from assumptions.
- Identify telemetry required for deeper investigation.

---

## Conclusion

The investigation identified a suspicious sequence involving a successful sign-in by `user1@sentinellab.local` followed eight minutes later by PowerShell execution on `DESKTOP-LAB01`.

The endpoint activity was launched by `winword.exe` and contained `-ExecutionPolicy Bypass` and `-EncodedCommand`.

The sequence warrants further investigation, but the available synthetic telemetry is insufficient to confirm unauthorized access or system compromise.
