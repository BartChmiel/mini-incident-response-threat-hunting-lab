# MITRE ATT&CK Mapping

This file documents how the lab detections map to MITRE ATT&CK. The mappings are kept simple so each finding can be reviewed quickly during triage.

| Behavior | Technique | Rationale |
| --- | --- | --- |
| Repeated failed logons for the same account and source | T1110 - Brute Force | Repeated authentication attempts may indicate password guessing or credential stuffing. |
| Successful login after multiple failures | T1078 - Valid Accounts, T1110 - Brute Force | A successful login after failures may indicate compromised valid credentials. |
| Encoded or hidden PowerShell execution | T1059.001 - PowerShell, T1027 - Obfuscated Files or Information | Encoded commands and hidden windows are common signs of script execution and obfuscation. |
| After-hours login from external or remote source | T1078 - Valid Accounts | Unusual timing can indicate abuse of valid credentials. |
| Privileged group change or special privileges | T1098 - Account Manipulation | Adding users to privileged groups or assigning special privileges can support persistence or escalation. |
| Suspicious outbound connection on unusual ports | T1071 - Application Layer Protocol, T1105 - Ingress Tool Transfer | Suspicious outbound traffic may indicate command-and-control or tool transfer activity. |

## Notes

- The mappings describe suspicious behavior, not confirmed compromise.
- Findings should be validated with surrounding context before containment.
- Useful enrichment sources include identity provider logs, VPN logs, EDR telemetry, DNS/proxy logs, and change management records.
