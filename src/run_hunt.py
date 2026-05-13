from __future__ import annotations

import argparse
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run mini incident response and threat hunting detections."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="Directory containing auth, endpoint, and network sample logs.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports"),
        help="Directory where CSV and Markdown reports will be written.",
    )
    return parser.parse_args()


def main() -> int:
    try:
        import pandas  # noqa: F401
    except ModuleNotFoundError:
        print(
            "Missing dependency: pandas. Install requirements first with "
            "`pip install -r requirements.txt`.",
            file=sys.stderr,
        )
        return 1

    from ir_lab.detections import (
        load_auth_logs,
        load_endpoint_events,
        load_network_events,
        run_all_detections,
    )
    from ir_lab.triage import build_timeline, write_outputs

    args = parse_args()
    data_dir = args.data_dir

    auth_logs = load_auth_logs(data_dir / "auth_logs.csv")
    endpoint_events = load_endpoint_events(data_dir / "endpoint_events.jsonl")
    network_events = load_network_events(data_dir / "network_events.csv")

    findings = run_all_detections(auth_logs, endpoint_events, network_events)
    timeline = build_timeline(auth_logs, endpoint_events, network_events)
    output_paths = write_outputs(findings, timeline, args.output_dir)

    print(f"Generated {len(findings)} findings.")
    for name, path in output_paths.items():
        print(f"{name}: {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

