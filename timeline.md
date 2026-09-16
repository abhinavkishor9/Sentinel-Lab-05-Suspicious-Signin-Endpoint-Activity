# Timeline — Sentinel Lab 05

## Investigation Timeline

| Time | Activity | Result |
|---|---|---|
| 09:00 | Sentinel workspace validated | Workspace available |
| 09:05 | Synthetic sign-in data prepared | Three successful authentication events |
| 09:10 | Sign-in activity reviewed | user1 selected for further investigation |
| 09:15 | Synthetic endpoint data prepared | Three endpoint events created |
| 09:20 | Endpoint activity reviewed | PowerShell executions identified |
| 09:25 | Primary PowerShell event reviewed | user1 / DESKTOP-LAB01 identified |
| 09:30 | Parent process analyzed | winword.exe → powershell.exe |
| 09:35 | Command line reviewed | Bypass + EncodedCommand identified |
| 09:40 | Authentication and endpoint events correlated | Same user and computer |
| 09:45 | Time relationship calculated | 8-minute difference |
| 09:50 | Comparison activity reviewed | user2 and user3 used as baseline context |
| 09:55 | Evidence gaps reviewed | Additional telemetry identified |
| 10:00 | Final verdict assigned | Suspicious — Sign-in Followed by Potentially Malicious Endpoint Activity |

---

## Key Event Sequence

    10:00 UTC
    user1@sentinellab.local
    Successful sign-in
    203.0.113.25
    New York
    DESKTOP-LAB01

    ↓ 8 minutes

    10:08 UTC
    user1
    DESKTOP-LAB01
    winword.exe
    ↓
    powershell.exe
    ↓
    -ExecutionPolicy Bypass
    -EncodedCommand

---

## Comparison Events

### user2

    10:02 UTC
    Successful sign-in
    DESKTOP-LAB02

    ↓ 2 hours 58 minutes

    13:00 UTC
    explorer.exe → powershell.exe
    Get-Service

### user3

    10:05 UTC
    Successful sign-in
    DESKTOP-LAB03

    ↓ 3 hours

    13:05 UTC
    explorer.exe → cmd.exe
    ipconfig

---

## Investigation Milestones

### Identity Review

Three successful sign-ins were identified.

### Endpoint Review

PowerShell execution was identified on two endpoints.

### Primary Finding

The `user1` endpoint event showed:

- `winword.exe` as parent.
- `powershell.exe` as child process.
- `-ExecutionPolicy Bypass`.
- `-EncodedCommand`.

### Correlation

The same user and computer were present in both the sign-in and endpoint activity.

### Temporal Analysis

The endpoint event occurred eight minutes after authentication.

### Evidence Assessment

The correlation was considered suspicious, but causation and compromise remained unconfirmed.

---

## Final Assessment

**Verdict:** Suspicious — Sign-in Followed by Potentially Malicious Endpoint Activity

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Primary Evidence:**

    user1 sign-in
    →
    DESKTOP-LAB01
    →
    8 minutes
    →
    winword.exe → powershell.exe
    →
    Bypass + EncodedCommand

**Evidence Gap:**

No MFA, Conditional Access, sign-in risk, PowerShell Script Block, network, file, child-process, or endpoint-security telemetry was available.

**Final SOC Principle:**

> **Correlate the evidence, but do not assume causation.**
