import json
import tempfile
import unittest
from pathlib import Path

from agenttrust_bench.reporting import (
    ReportValidationError,
    load_json_report,
    validate_evaluation_report,
    write_json_report,
)


def sample_report():
    runs = [
        {
            "run": 1, "model_verdict": "VULNERABLE",
            "guard_verdict": "BLOCKED", "environment_verdict": "INTACT",
        },
        {
            "run": 2, "model_verdict": "RESISTED",
            "guard_verdict": "NOT_TRIGGERED", "environment_verdict": "INTACT",
        },
    ]
    return {
        "schema_version": "1.4",
        "evaluation_id": "test",
        "evaluation_status": "completed",
        "provider": "fake",
        "model": "fake-model",
        "requested_runs": 2,
        "completed_runs": 2,
        "aggregate": {
            "model_resisted": 1, "model_vulnerable": 1,
            "model_inconclusive": 0, "guard_blocked": 1,
            "guard_allowed": 0, "environment_intact": 2,
            "environment_compromised": 0,
        },
        "rates": {},
        "interpretation": {},
        "runs": runs,
    }


class ReportingTests(unittest.TestCase):
    def test_valid_report_passes(self):
        self.assertTrue(validate_evaluation_report(sample_report())["valid"])

    def test_aggregate_tampering_is_detected(self):
        report = sample_report()
        report["aggregate"]["model_vulnerable"] = 99
        result = validate_evaluation_report(report)
        self.assertFalse(result["valid"])
        self.assertIn("aggregate_mismatch:model_vulnerable", result["errors"])

    def test_write_and_load_json_report(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            write_json_report(sample_report(), path)
            raw = path.read_bytes()
            self.assertTrue(raw.endswith(bytes([10])))
            loaded = load_json_report(path)
            self.assertEqual(loaded["completed_runs"], 2)

    def test_invalid_json_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            path.write_text('{"broken": true} trailing', encoding="utf-8")
            with self.assertRaises(ReportValidationError):
                load_json_report(path)


if __name__ == "__main__":
    unittest.main()


class HtmlReportTests(unittest.TestCase):
    def test_html_report_escapes_untrusted_values(self):
        from agenttrust_bench.reporting import write_html_report
        report = sample_report()
        report["model"] = "<script>alert(1)</script>"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.html"
            write_html_report(report, path)
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", content)
            self.assertIn("&lt;script&gt;", content)
