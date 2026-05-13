from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from ir_lab.detections import Finding


def _string(value: object) -> str:
    if pd.isna(value):
        return ""
    return str(value)


def findings_to_frame(findings: list[Finding]) -> pd.DataFrame:
    return pd.DataFrame([finding.to_row() for finding in findings])


def build_timeline(
    auth_logs: pd.DataFrame,
    endpoint_events: pd.DataFrame,
    network_events: pd.DataFrame,
) -> pd.DataFrame:
    auth_timeline = pd.DataFrame(
        {
            "timestamp": auth_logs["timestamp"],
            "source": "auth",
            "host": auth_logs["host"],
            "user": auth_logs["user"],
            "source_ip": auth_logs["source_ip"],
            "event": auth_logs.apply(
                lambda row: (
                    f"{row['event_id']} {row['event_type']} {row['outcome']} "
                    f"({row.get('details', '')})"
                ),
                axis=1,
            ),
        }
    )

    endpoint_timeline = pd.DataFrame(
        {
            "timestamp": endpoint_events["timestamp"],
            "source": "endpoint",
            "host": endpoint_events["host"],
            "user": endpoint_events["user"],
            "source_ip": "",
            "event": endpoint_events.apply(
                lambda row: (
                    f"{row['event_id']} process={row['process_name']} "
                    f"parent={row['parent_process']} command={row['command_line']}"
                ),
                axis=1,
            ),
        }
    )

    network_timeline = pd.DataFrame(
        {
            "timestamp": network_events["timestamp"],
            "source": "network",
            "host": network_events["host"],
            "user": "",
            "source_ip": network_events["source_ip"],
            "event": network_events.apply(
                lambda row: (
                    f"{row['action']} {row['protocol']} to {row['dest_ip']}:"
                    f"{row['dest_port']} bytes_out={row['bytes_out']} "
                    f"category={row['category']} dns={_string(row.get('dns_query', ''))}"
                ),
                axis=1,
            ),
        }
    )

    timeline = pd.concat([auth_timeline, endpoint_timeline, network_timeline])
    return timeline.sort_values("timestamp").reset_index(drop=True)


def _severity_rank(severity: str) -> int:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    return order.get(severity, 0)


def _bullet_list(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def render_triage_notes(findings: list[Finding], timeline: pd.DataFrame) -> str:
    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    severity_counts = Counter(finding.severity for finding in findings)
    highest_severity = "None"
    if findings:
        highest_severity = max(findings, key=lambda item: _severity_rank(item.severity)).severity

    lines = [
        "# Incident Triage Notes",
        "",
        f"Generated at: {generated_at}",
        "",
        "## Executive Summary",
        "",
        f"- Total findings: {len(findings)}",
        f"- Highest severity: {highest_severity}",
        f"- Severity breakdown: {dict(severity_counts)}",
        "",
        "## Timeline Reconstruction",
        "",
    ]

    for _, row in timeline.iterrows():
        lines.append(
            f"- {row['timestamp'].isoformat()} [{row['source']}] "
            f"host={row['host']} user={row['user']} src={row['source_ip']} - {row['event']}"
        )

    lines.extend(["", "## Findings", ""])

    for finding in findings:
        lines.extend(
            [
                f"### {finding.finding_id}: {finding.detection_name}",
                "",
                f"Severity: {finding.severity}",
                f"Time: {finding.timestamp}",
                f"Affected user: {finding.user or 'N/A'}",
                f"Affected host: {finding.host or 'N/A'}",
                f"Source IP: {finding.source_ip or 'N/A'}",
                "",
                "Description:",
                "",
                finding.description,
                "",
                "MITRE ATT&CK Mapping:",
                "",
                _bullet_list(finding.mitre_attack),
                "",
                "Indicators:",
                "",
                _bullet_list(finding.indicators),
                "",
                "Evidence:",
                "",
                _bullet_list(finding.evidence),
                "",
                "False-Positive Considerations:",
                "",
                _bullet_list(finding.false_positive_considerations),
                "",
                "Recommended Next Steps:",
                "",
                _bullet_list(finding.recommended_next_steps),
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def write_outputs(
    findings: list[Finding],
    timeline: pd.DataFrame,
    output_dir: Path,
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    findings_path = output_dir / "findings.csv"
    timeline_path = output_dir / "timeline.csv"
    triage_path = output_dir / "triage_notes.md"

    findings_to_frame(findings).to_csv(findings_path, index=False)
    timeline.to_csv(timeline_path, index=False)
    triage_path.write_text(render_triage_notes(findings, timeline), encoding="utf-8")

    return {
        "findings": findings_path,
        "timeline": timeline_path,
        "triage_notes": triage_path,
    }
