# Mini Incident Response and Threat Hunting Lab

Personal cybersecurity project, in progress  
May 2026 - Present

## Overview

This lab simulates a small incident response and threat hunting workflow using structured JSON/CSV logs for authentication, endpoint, and network security events.

The current implementation includes:

- Sample authentication, endpoint, and network telemetry.
- Python/Pandas detections for common suspicious behaviors.
- MITRE ATT&CK mapping for each finding type.
- Markdown triage notes with timeline reconstruction, affected entities, indicators, severity, false-positive considerations, and next steps.
- CSV outputs for detected findings and consolidated timeline review.

## Detection Coverage

| Detection | Data source | Example ATT&CK mapping |
| --- | --- | --- |
| Brute-force authentication attempts | `data/auth_logs.csv` | T1110 - Brute Force |
| Successful login after repeated failures | `data/auth_logs.csv` | T1078 - Valid Accounts, T1110 - Brute Force |
| Suspicious PowerShell execution | `data/endpoint_events.jsonl` | T1059.001 - PowerShell |
| After-hours successful logins | `data/auth_logs.csv` | T1078 - Valid Accounts |
| Privilege and account administration events | `data/auth_logs.csv` | T1098 - Account Manipulation |
| Suspicious outbound network activity | `data/network_events.csv` | T1071 - Application Layer Protocol, T1105 - Ingress Tool Transfer |

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
3. Normalize suspicious events into audit-ready finding records.
4. Reconstruct an investigation timeline.
5. Generate triage notes in Markdown for analyst review.

## Analyst Notes

The dataset is intentionally small and uses documentation IP address ranges such as `203.0.113.0/24` and `198.51.100.0/24`. These are safe placeholders, not real indicators.

This project is designed as a portfolio lab and can be expanded with:

- More Windows Event ID concepts.
- Sigma-style rule metadata.
- Additional endpoint telemetry.
- More realistic identity provider logs.
- Unit tests and CI checks.
- Dashboarding in Jupyter or Streamlit.
