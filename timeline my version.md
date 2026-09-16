# Timeline 

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

