# MITRE ATT&CK Mapping

This lab uses a small set of ATT&CK mappings to keep the investigation notes practical and audit-ready.

| Behavior | Technique | Rationale |
| --- | --- | --- |
| Repeated failed logons for the same account and source | T1110 - Brute Force | Repeated authentication attempts may indicate password guessing or credential stuffing. |
| Successful login after multiple failures | T1078 - Valid Accounts, T1110 - Brute Force | A successful login after failures may indicate compromised valid credentials. |
| Encoded or hidden PowerShell execution | T1059.001 - PowerShell, T1027 - Obfuscated Files or Information | Encoded commands and hidden windows are common signs of script execution and obfuscation. |
| After-hours login from external or remote source | T1078 - Valid Accounts | Unusual timing can indicate abuse of valid credentials. |
| Privileged group change or special privileges | T1098 - Account Manipulation | Adding users to privileged groups or assigning special privileges can support persistence or escalation. |
| Suspicious outbound connection on unusual ports | T1071 - Application Layer Protocol, T1105 - Ingress Tool Transfer | Suspicious outbound traffic may indicate command-and-control or tool transfer activity. |

## Notes

- Technique mappings are intentionally conservative.
- A finding should not be treated as confirmed malicious without context enrichment.
- Recommended enrichment sources include identity provider logs, VPN logs, EDR telemetry, DNS/proxy logs, and change management records.

