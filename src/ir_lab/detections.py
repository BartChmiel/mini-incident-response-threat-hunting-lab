from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import pandas as pd


@dataclass
class Finding:
    finding_id: str
    detection_name: str
    severity: str
    timestamp: str
    user: str
    host: str
    source_ip: str
    description: str
    mitre_attack: list[str]
    indicators: list[str]
    evidence: list[str]
    false_positive_considerations: list[str]
    recommended_next_steps: list[str]

    def to_row(self) -> dict[str, str]:
        row = asdict(self)
        for key in [
            "mitre_attack",
            "indicators",
            "evidence",
            "false_positive_considerations",
            "recommended_next_steps",
        ]:
            row[key] = " | ".join(row[key])
        return row


def load_auth_logs(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def load_endpoint_events(path: Path) -> pd.DataFrame:
    df = pd.read_json(path, lines=True)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def load_network_events(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def _next_id(prefix: str, current_count: int) -> str:
    return f"{prefix}-{current_count + 1:04d}"


def _string(value: object) -> str:
    if pd.isna(value):
        return ""
    return str(value)


def _contains_any(value: object, needles: Iterable[str]) -> bool:
    text = _string(value).lower()
    return any(needle in text for needle in needles)


def detect_brute_force(
    auth_logs: pd.DataFrame,
    finding_offset: int = 0,
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Finding]:
    findings: list[Finding] = []
    failures = auth_logs[
        (auth_logs["event_id"] == 4625) | (auth_logs["outcome"].str.lower() == "failure")
    ].copy()

    if failures.empty:
        return findings

    window = pd.Timedelta(minutes=window_minutes)
    for (user, source_ip), group in failures.groupby(["user", "source_ip"]):
        ordered = group.sort_values("timestamp")
        for _, start_row in ordered.iterrows():
            start_time = start_row["timestamp"]
            window_rows = ordered[
                (ordered["timestamp"] >= start_time)
                & (ordered["timestamp"] <= start_time + window)
            ]
            if len(window_rows) < threshold:
                continue

            first_seen = window_rows["timestamp"].min()
            last_seen = window_rows["timestamp"].max()
            host_list = sorted(window_rows["host"].astype(str).unique())
            findings.append(
                Finding(
                    finding_id=_next_id("IR", finding_offset + len(findings)),
                    detection_name="Brute-force authentication attempts",
                    severity="High" if len(window_rows) >= threshold + 3 else "Medium",
                    timestamp=last_seen.isoformat(),
                    user=_string(user),
                    host=", ".join(host_list),
                    source_ip=_string(source_ip),
                    description=(
                        f"{len(window_rows)} failed logons for user {user} from "
                        f"{source_ip} within {window_minutes} minutes."
                    ),
                    mitre_attack=["T1110 - Brute Force"],
                    indicators=[
                        f"user={user}",
                        f"source_ip={source_ip}",
                        "event_id=4625",
                    ],
                    evidence=[
                        f"first_failure={first_seen.isoformat()}",
                        f"last_failure={last_seen.isoformat()}",
                        f"failure_count={len(window_rows)}",
                        f"hosts={', '.join(host_list)}",
                    ],
                    false_positive_considerations=[
                        "Service account password rotation or expired credentials can create repeated failures.",
                        "Validate whether the source IP belongs to a known scanner, VPN, or admin jump host.",
                    ],
                    recommended_next_steps=[
                        "Review source IP reputation and ownership.",
                        "Check whether the targeted account had a recent password change.",
                        "Look for a successful login from the same source after the failures.",
                    ],
                )
            )
            break

    return findings


def detect_success_after_failures(
    auth_logs: pd.DataFrame,
    finding_offset: int = 0,
    min_failures: int = 3,
    window_minutes: int = 15,
) -> list[Finding]:
    findings: list[Finding] = []
    failures = auth_logs[
        (auth_logs["event_id"] == 4625) | (auth_logs["outcome"].str.lower() == "failure")
    ].copy()
    successes = auth_logs[
        (auth_logs["event_id"] == 4624) & (auth_logs["outcome"].str.lower() == "success")
    ].copy()

    if failures.empty or successes.empty:
        return findings

    window = pd.Timedelta(minutes=window_minutes)
    for _, success in successes.sort_values("timestamp").iterrows():
        prior = failures[
            (failures["user"] == success["user"])
            & (failures["source_ip"] == success["source_ip"])
            & (failures["timestamp"] >= success["timestamp"] - window)
            & (failures["timestamp"] < success["timestamp"])
        ]
        if len(prior) < min_failures:
            continue

        findings.append(
            Finding(
                finding_id=_next_id("IR", finding_offset + len(findings)),
                detection_name="Successful login after repeated failures",
                severity="High",
                timestamp=success["timestamp"].isoformat(),
                user=_string(success["user"]),
                host=_string(success["host"]),
                source_ip=_string(success["source_ip"]),
                description=(
                    f"Successful login for {success['user']} after {len(prior)} "
                    f"failed attempts from {success['source_ip']}."
                ),
                mitre_attack=[
                    "T1078 - Valid Accounts",
                    "T1110 - Brute Force",
                ],
                indicators=[
                    f"user={success['user']}",
                    f"source_ip={success['source_ip']}",
                    "event_id_sequence=4625->4624",
                ],
                evidence=[
                    f"success_time={success['timestamp'].isoformat()}",
                    f"prior_failure_count={len(prior)}",
                    f"first_failure={prior['timestamp'].min().isoformat()}",
                    f"logon_type={success.get('logon_type', '')}",
                ],
                false_positive_considerations=[
                    "A legitimate user may mistype a password several times before succeeding.",
                    "Risk increases when the source IP is external or unusual for the account.",
                ],
                recommended_next_steps=[
                    "Confirm whether the account owner performed the login.",
                    "Review MFA, VPN, and identity provider logs for the same time window.",
                    "Check endpoint and network activity immediately after the successful login.",
                ],
            )
        )

    return findings


def detect_suspicious_powershell(
    endpoint_events: pd.DataFrame,
    finding_offset: int = 0,
) -> list[Finding]:
    findings: list[Finding] = []
    if endpoint_events.empty:
        return findings

    suspicious_terms = [
        "-enc",
        "-encodedcommand",
        "downloadstring",
        "iex",
        "invoke-expression",
        "executionpolicy bypass",
        "windowstyle hidden",
        "frombase64string",
        "new-object net.webclient",
    ]

    powershell = endpoint_events[
        endpoint_events["process_name"].str.lower().isin(["powershell.exe", "pwsh.exe"])
    ].copy()

    for _, row in powershell.sort_values("timestamp").iterrows():
        if not _contains_any(row["command_line"], suspicious_terms):
            continue

        command_line = _string(row["command_line"])
        strong_indicator = _contains_any(
            command_line,
            ["-enc", "-encodedcommand", "downloadstring", "windowstyle hidden"],
        )
        findings.append(
            Finding(
                finding_id=_next_id("IR", finding_offset + len(findings)),
                detection_name="Suspicious PowerShell execution",
                severity="High" if strong_indicator else "Medium",
                timestamp=row["timestamp"].isoformat(),
                user=_string(row["user"]),
                host=_string(row["host"]),
                source_ip="",
                description=(
                    f"PowerShell command on {row['host']} used suspicious execution "
                    "patterns commonly seen in script-based intrusion activity."
                ),
                mitre_attack=[
                    "T1059.001 - PowerShell",
                    "T1027 - Obfuscated Files or Information",
                ],
                indicators=[
                    f"host={row['host']}",
                    f"user={row['user']}",
                    f"process={row['process_name']}",
                    f"parent_process={row['parent_process']}",
                ],
                evidence=[
                    f"event_id={row.get('event_id', '')}",
                    f"command_line={command_line}",
                    f"sha256={row.get('sha256', '')}",
                ],
                false_positive_considerations=[
                    "Administrators may use PowerShell with encoded commands for automation.",
                    "Compare parent process, user, and host role against known administrative workflows.",
                ],
                recommended_next_steps=[
                    "Decode encoded PowerShell content if present.",
                    "Collect process tree, script block logs, and related command history.",
                    "Check for network connections or file writes following this execution.",
                ],
            )
        )

    return findings


def detect_after_hours_logins(
    auth_logs: pd.DataFrame,
    finding_offset: int = 0,
    timezone: str = "Europe/Warsaw",
    business_start_hour: int = 7,
    business_end_hour: int = 19,
) -> list[Finding]:
    findings: list[Finding] = []
    successes = auth_logs[
        (auth_logs["event_id"] == 4624) & (auth_logs["outcome"].str.lower() == "success")
    ].copy()

    if successes.empty:
        return findings

    successes["local_timestamp"] = successes["timestamp"].dt.tz_convert(timezone)
    for _, row in successes.sort_values("timestamp").iterrows():
        local_time = row["local_timestamp"]
        is_weekend = local_time.weekday() >= 5
        is_outside_hours = (
            local_time.hour < business_start_hour or local_time.hour >= business_end_hour
        )
        if not (is_weekend or is_outside_hours):
            continue

        severity = "Medium"
        if _string(row.get("logon_type", "")).lower() in {"remoteinteractive", "network"}:
            severity = "High"

        findings.append(
            Finding(
                finding_id=_next_id("IR", finding_offset + len(findings)),
                detection_name="After-hours successful login",
                severity=severity,
                timestamp=row["timestamp"].isoformat(),
                user=_string(row["user"]),
                host=_string(row["host"]),
                source_ip=_string(row["source_ip"]),
                description=(
                    f"Successful {row.get('logon_type', '')} login outside the configured "
                    f"business window in {timezone}."
                ),
                mitre_attack=["T1078 - Valid Accounts"],
                indicators=[
                    f"user={row['user']}",
                    f"host={row['host']}",
                    f"source_ip={row['source_ip']}",
                    f"local_time={local_time.isoformat()}",
                ],
                evidence=[
                    f"event_id={row.get('event_id', '')}",
                    f"utc_time={row['timestamp'].isoformat()}",
                    f"logon_type={row.get('logon_type', '')}",
                    f"details={row.get('details', '')}",
                ],
                false_positive_considerations=[
                    "On-call, maintenance, backup, and international user activity may be legitimate.",
                    "Validate the user's normal schedule and approved change windows.",
                ],
                recommended_next_steps=[
                    "Confirm whether the activity matches an approved work schedule.",
                    "Review geolocation, VPN, and MFA context for the source.",
                    "Correlate with endpoint process and network activity after login.",
                ],
            )
        )

    return findings


def detect_privilege_events(
    auth_logs: pd.DataFrame,
    finding_offset: int = 0,
) -> list[Finding]:
    findings: list[Finding] = []
    privileged_event_ids = {4672, 4720, 4728, 4732}
    privilege_terms = ["admin", "privilege", "sebackup", "sedebug"]
    candidates = auth_logs[
        auth_logs["event_id"].isin(privileged_event_ids)
        | auth_logs["privilege"].fillna("").str.lower().apply(
            lambda value: any(term in value for term in privilege_terms)
        )
    ].copy()

    for _, row in candidates.sort_values("timestamp").iterrows():
        event_id = int(row["event_id"])
        severity = "High" if event_id in {4720, 4728, 4732} else "Medium"
        findings.append(
            Finding(
                finding_id=_next_id("IR", finding_offset + len(findings)),
                detection_name="Privilege or account administration event",
                severity=severity,
                timestamp=row["timestamp"].isoformat(),
                user=_string(row["user"]),
                host=_string(row["host"]),
                source_ip=_string(row["source_ip"]),
                description=(
                    f"Privilege-related Windows event {event_id} observed for "
                    f"{row['user']} on {row['host']}."
                ),
                mitre_attack=["T1098 - Account Manipulation"],
                indicators=[
                    f"user={row['user']}",
                    f"host={row['host']}",
                    f"event_id={event_id}",
                    f"privilege={row.get('privilege', '')}",
                ],
                evidence=[
                    f"time={row['timestamp'].isoformat()}",
                    f"event_type={row.get('event_type', '')}",
                    f"details={row.get('details', '')}",
                ],
                false_positive_considerations=[
                    "Domain administrators and service accounts may legitimately receive special privileges.",
                    "Group membership changes may be expected during onboarding or maintenance windows.",
                ],
                recommended_next_steps=[
                    "Verify change ticket or administrator approval.",
                    "Review group membership history for the affected account.",
                    "Check for suspicious activity before and after the privilege event.",
                ],
            )
        )

    return findings


def detect_suspicious_network_activity(
    network_events: pd.DataFrame,
    finding_offset: int = 0,
) -> list[Finding]:
    findings: list[Finding] = []
    if network_events.empty:
        return findings

    suspicious_ports = {4444, 8080, 8443}
    suspicious_categories = {"unknown", "malware", "command-and-control"}
    candidates = network_events[
        network_events["dest_port"].isin(suspicious_ports)
        | network_events["category"].str.lower().isin(suspicious_categories)
    ].copy()

    for _, row in candidates.sort_values("timestamp").iterrows():
        severity = "High" if int(row["dest_port"]) == 4444 else "Medium"
        findings.append(
            Finding(
                finding_id=_next_id("IR", finding_offset + len(findings)),
                detection_name="Suspicious outbound network activity",
                severity=severity,
                timestamp=row["timestamp"].isoformat(),
                user="",
                host=_string(row["host"]),
                source_ip=_string(row["source_ip"]),
                description=(
                    f"Outbound connection from {row['host']} to {row['dest_ip']}:"
                    f"{row['dest_port']} categorized as {row['category']}."
                ),
                mitre_attack=[
                    "T1071 - Application Layer Protocol",
                    "T1105 - Ingress Tool Transfer",
                ],
                indicators=[
                    f"source_ip={row['source_ip']}",
                    f"dest_ip={row['dest_ip']}",
                    f"dest_port={row['dest_port']}",
                    f"dns_query={_string(row.get('dns_query', ''))}",
                ],
                evidence=[
                    f"time={row['timestamp'].isoformat()}",
                    f"protocol={row.get('protocol', '')}",
                    f"action={row.get('action', '')}",
                    f"bytes_out={row.get('bytes_out', '')}",
                    f"category={row.get('category', '')}",
                ],
                false_positive_considerations=[
                    "Unusual ports may be used by legitimate internal tools or development services.",
                    "Documentation IP ranges in this lab represent placeholders, not real bad infrastructure.",
                ],
                recommended_next_steps=[
                    "Identify the process responsible for the connection.",
                    "Check DNS, proxy, and endpoint telemetry around the same timestamp.",
                    "Block or monitor the destination if it is not business-approved.",
                ],
            )
        )

    return findings


def run_all_detections(
    auth_logs: pd.DataFrame,
    endpoint_events: pd.DataFrame,
    network_events: pd.DataFrame,
) -> list[Finding]:
    findings: list[Finding] = []
    detection_steps = [
        lambda offset: detect_brute_force(auth_logs, offset),
        lambda offset: detect_success_after_failures(auth_logs, offset),
        lambda offset: detect_suspicious_powershell(endpoint_events, offset),
        lambda offset: detect_after_hours_logins(auth_logs, offset),
        lambda offset: detect_privilege_events(auth_logs, offset),
        lambda offset: detect_suspicious_network_activity(network_events, offset),
    ]

    for step in detection_steps:
        findings.extend(step(len(findings)))

    return findings
