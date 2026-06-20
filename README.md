# Mini Incident Response and Threat Hunting Lab

Personal cybersecurity project  
May 2026 - Present

## Overview

Small SOC-style incident response and threat hunting lab built around structured JSON/CSV logs. The dataset simulates authentication, endpoint, and network security events, and the Python code turns those logs into detections, findings, timelines, and triage notes.

The project covers the same workflow I would follow when reviewing a small SIEM-style alert queue:

- Load sample authentication, endpoint, and network telemetry.
- Run Python/Pandas detections for common suspicious behaviors.
- Create findings with affected users, hosts, source IPs, indicators, and severity.
- Build a consolidated timeline for analyst review.
- Generate Markdown triage notes with false-positive considerations, escalation decisions, and recommended next steps.
- Map the detection scenarios to MITRE ATT&CK techniques.

## Detection Coverage

| Detection | Data source | Example ATT&CK mapping |
| --- | --- | --- |
| Brute-force authentication attempts | `data/auth_logs.csv` | T1110 - Brute Force |
| Successful login after repeated failures | `data/auth_logs.csv` | T1078 - Valid Accounts, T1110 - Brute Force |
| Suspicious PowerShell execution | `data/endpoint_events.jsonl` | T1059.001 - PowerShell |
| After-hours successful logins | `data/auth_logs.csv` | T1078 - Valid Accounts |
| Privilege and account administration events | `data/auth_logs.csv` | T1098 - Account Manipulation |
| Suspicious outbound network activity | `data/network_events.csv` | T1071 - Application Layer Protocol, T1105 - Ingress Tool Transfer |

## Outputs

The generated report files are kept in `reports/` as an example of the review output:

- `findings.csv` - normalized findings from all detections.
- `timeline.csv` - combined authentication, endpoint, and network activity ordered by time.
- `triage_notes.md` - Markdown investigation notes with evidence, MITRE mapping, escalation decision, and next steps.

## Project Structure

```text
mini-incident-response-threat-hunting-lab/
  data/
    auth_logs.csv
    endpoint_events.jsonl
    network_events.csv
  docs/
    mitre_mapping.md
  reports/
    README.md
  src/
    ir_lab/
      __init__.py
      detections.py
      triage.py
    run_hunt.py
  tests/
    test_detections.py
  requirements.txt
```

## Quick Start

Create a virtual environment and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the hunting workflow:

```powershell
python .\src\run_hunt.py --data-dir .\data --output-dir .\reports
```

Expected outputs:

- `reports/findings.csv`
- `reports/timeline.csv`
- `reports/triage_notes.md`

Run the basic test suite:

```powershell
python -m unittest discover -s tests
```

If `pip install pandas` says the package is already installed but the script still reports `Missing dependency: pandas`, install through the same interpreter that runs the lab:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe .\src\run_hunt.py --data-dir .\data --output-dir .\reports
```

## Example Workflow

1. Ingest structured sample logs from `data/`.
2. Run detection logic in `src/ir_lab/detections.py`.
3. Normalize suspicious events into finding records.
4. Reconstruct an investigation timeline.
5. Generate triage notes in Markdown for analyst review.

## Sample Data Notes

The dataset is small on purpose and uses documentation IP ranges such as `203.0.113.0/24` and `198.51.100.0/24`, so the indicators are not real-world infrastructure.

Possible next additions:

- More Windows Event ID concepts.
- Sigma-style rule metadata.
- Additional endpoint telemetry.
- Identity provider or VPN logs.
- Unit tests and CI checks.
- Dashboarding in Jupyter or Streamlit.
