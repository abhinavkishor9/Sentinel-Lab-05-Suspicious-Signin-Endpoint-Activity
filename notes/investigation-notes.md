# Investigation Notes — Sentinel Lab 05

## Investigation Overview

**Investigation Type:** Suspicious Sign-in + Endpoint Activity  
**Platform:** Microsoft Sentinel  
**Data Source:** Synthetic KQL `datatable()`  
**Primary User:** `user1@sentinellab.local`  
**Primary Host:** `DESKTOP-LAB01`

---

## Investigation Question

Did suspicious endpoint activity occur shortly after a successful sign-in, and does the available evidence support treating the events as potentially related?

---

## Evidence Reviewed

The investigation reviewed:

- Successful authentication events.
- Source IP addresses.
- Authentication locations.
- Associated computers.
- Endpoint process execution.
- Parent-child process context.
- PowerShell command-line parameters.
- Time relationship between identity and endpoint activity.

---

## Initial Authentication Review

The authentication dataset contained three successful sign-ins.

The primary event was:

| Field | Value |
|---|---|
| Time | 2026-09-15 10:00 UTC |
| User | `user1@sentinellab.local` |
| IP | `203.0.113.25` |
| Location | New York |
| Computer | `DESKTOP-LAB01` |
| ResultType | `0` |

The event was selected for further investigation because it was followed by endpoint activity on the same computer.

---

## Endpoint Activity Review

The endpoint dataset contained three process events.

Filtering for PowerShell returned:

| Time | Computer | User | Parent Process | Process |
|---|---|---|---|---|
| 10:08 UTC | DESKTOP-LAB01 | user1 | winword.exe | powershell.exe |
| 13:00 UTC | DESKTOP-LAB02 | user2 | explorer.exe | powershell.exe |

The `user1` event was the primary endpoint finding.

---

## Primary Endpoint Event

The event occurred at:

**2026-09-15 10:08 UTC**

Observed command:

    powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBtAHAAbwByAHQAYQBuAHQAPQ=

Observed context:

| Field | Value |
|---|---|
| Computer | `DESKTOP-LAB01` |
| User | `user1` |
| Parent Process | `winword.exe` |
| Process | `powershell.exe` |
| Suspicious Parameters | `-ExecutionPolicy Bypass`, `-EncodedCommand` |

---

## Identity-to-Endpoint Correlation

The authentication event and endpoint event share:

- User context: `user1`
- Computer: `DESKTOP-LAB01`

The timestamps are:

    Sign-in: 10:00 UTC
    Endpoint activity: 10:08 UTC

The observed difference is:

**8 minutes**

This provides a temporal relationship between the events.

It does not independently establish causation.

---

## Comparison Activity

### user2

Authentication:

    10:02 UTC
    user2@sentinellab.local
    DESKTOP-LAB02

Endpoint:

    13:00 UTC
    explorer.exe → powershell.exe
    Get-Service

This represents a longer gap and a less unusual process context.

### user3

Authentication:

    10:05 UTC
    user3@sentinellab.local
    DESKTOP-LAB03

Endpoint:

    13:05 UTC
    explorer.exe → cmd.exe
    ipconfig

This activity also occurs several hours after authentication.

---

## Correlation Finding

The strongest event chain is:

    10:00
    user1 successful sign-in
          ↓
    DESKTOP-LAB01
          ↓
    8 minutes
          ↓
    10:08
    winword.exe
          ↓
    powershell.exe
          ↓
    ExecutionPolicy Bypass
    EncodedCommand

The combination of identity, host, timing, parent process, and command-line characteristics makes this the primary suspicious sequence.

---

## Evidence Classification

### Confirmed

- Successful sign-in occurred for `user1`.
- The sign-in was associated with `DESKTOP-LAB01`.
- PowerShell executed on `DESKTOP-LAB01`.
- `winword.exe` launched PowerShell.
- `-ExecutionPolicy Bypass` was present.
- `-EncodedCommand` was present.
- The endpoint activity occurred eight minutes after the sign-in.

### Plausible

- The endpoint activity may be related to the preceding sign-in.
- The sign-in and subsequent endpoint activity may form part of the same security event.

### Unknown

- Whether the sign-in was unauthorized.
- Whether the account was compromised.
- Whether the PowerShell command was malicious.
- What the encoded command contained.
- Whether a payload was downloaded or executed.
- Whether persistence was established.
- Whether data was accessed or exfiltrated.

---

## Investigation Verdict

**Suspicious — Sign-in Followed by Potentially Malicious Endpoint Activity**

The evidence justifies additional investigation but does not confirm compromise.

---

## Recommended SOC Follow-Up

The next investigation stage should examine:

1. MFA and Conditional Access results.
2. Device identity and compliance.
3. Sign-in risk and authentication method.
4. PowerShell Script Block Logging.
5. Process creation and child-process activity.
6. Network connections.
7. File creation and modification.
8. Endpoint security alerts.
9. The decoded PowerShell command.
10. User activity around the authentication event.

---

## Key Lesson

A suspicious sign-in becomes more meaningful when endpoint activity is correlated with it.

However:

**Temporal correlation is not proof of causation.**

The analyst should use the correlation as an investigation lead and continue validating the evidence.
