# Troubleshooting Notes — Sentinel Lab 05

## Issue 1 — Persistent Sign-in Telemetry Was Unavailable

### Problem

The Sentinel workspace did not contain the required persistent Entra sign-in telemetry for the lab.

### Resolution

Synthetic authentication events were created with KQL `datatable()`.

This allowed the identity investigation to proceed without presenting simulated events as real Entra telemetry.

---

## Issue 2 — Persistent Endpoint Telemetry Was Unavailable

### Problem

The workspace also did not contain the endpoint process telemetry required for the correlation exercise.

### Resolution

Synthetic endpoint events were created with a second KQL `datatable()`.

The synthetic dataset included:

- User
- Computer
- Parent process
- Process
- Command line
- Timestamp

---

## Issue 3 — Synthetic Data Is Temporary

### Problem

The `datatable()` exists only within the query where it is defined.

It does not create a permanent Sentinel table.

### Resolution

Each investigation query must include the complete synthetic dataset needed for that query.

This keeps the lab reproducible while clearly documenting the telemetry limitation.

---

## Issue 4 — Identity and Endpoint Data Used Different User Formats

### Problem

The sign-in dataset used:

    user1@sentinellab.local

The endpoint dataset used:

    user1

### Resolution

The user context was interpreted consistently during the manual correlation.

In a production investigation, a normalized identity field or reliable account identifier should be used to correlate the sources.

---

## Issue 5 — Same Computer Does Not Prove Same Activity

### Observation

Both events were associated with:

    DESKTOP-LAB01

This strengthens the correlation but does not prove that the sign-in caused the endpoint activity.

### Resolution

The computer match was treated as supporting evidence rather than proof of causation.

---

## Issue 6 — Short Time Difference Does Not Prove Compromise

### Observation

The endpoint activity occurred only eight minutes after authentication.

### Resolution

The timing was treated as a correlation signal.

The investigation did not conclude that the account was compromised solely because of the short time interval.

---

## Issue 7 — PowerShell Activity Requires Context

### Problem

PowerShell is commonly used for legitimate administration.

### Resolution

The investigation considered additional context:

- Parent process.
- Command line.
- User.
- Computer.
- Timing.
- Relationship to authentication activity.

The combination of these indicators increased suspicion more than PowerShell execution alone.

---

## Issue 8 — Suspicious Parameters Are Not Proof

### Observation

The primary PowerShell event contained:

    -ExecutionPolicy Bypass

and:

    -EncodedCommand

### Resolution

These were treated as suspicious characteristics.

They were not treated as independent proof of malicious execution.

---

## Issue 9 — No Follow-On Telemetry

### Problem

The synthetic dataset did not contain:

- Network connections.
- File activity.
- Child processes.
- PowerShell Script Block Logging.
- Endpoint alerts.
- MFA results.
- Conditional Access data.
- Sign-in risk.

### Resolution

These were documented as evidence gaps rather than filling the gaps with assumed activity.

---

## Final Troubleshooting Outcome

The lab successfully demonstrated cross-source correlation using synthetic Sentinel telemetry.

The primary finding was:

    Successful sign-in
    ↓
    user1 / DESKTOP-LAB01
    ↓
    8 minutes
    ↓
    winword.exe → powershell.exe
    ↓
    ExecutionPolicy Bypass + EncodedCommand

The investigation remained evidence-based and did not classify the system as definitively compromised.
