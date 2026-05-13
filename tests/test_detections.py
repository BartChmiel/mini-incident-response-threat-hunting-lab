from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ir_lab.detections import (  # noqa: E402
    load_auth_logs,
    load_endpoint_events,
    load_network_events,
    run_all_detections,
)


class DetectionWorkflowTests(unittest.TestCase):
    def test_sample_dataset_produces_expected_detection_types(self) -> None:
        data_dir = PROJECT_ROOT / "data"

        findings = run_all_detections(
            load_auth_logs(data_dir / "auth_logs.csv"),
            load_endpoint_events(data_dir / "endpoint_events.jsonl"),
            load_network_events(data_dir / "network_events.csv"),
        )

        detection_names = {finding.detection_name for finding in findings}

        self.assertIn("Brute-force authentication attempts", detection_names)
        self.assertIn("Successful login after repeated failures", detection_names)
        self.assertIn("Suspicious PowerShell execution", detection_names)
        self.assertIn("After-hours successful login", detection_names)
        self.assertIn("Privilege or account administration event", detection_names)
        self.assertIn("Suspicious outbound network activity", detection_names)
        self.assertGreaterEqual(len(findings), 6)


if __name__ == "__main__":
    unittest.main()

