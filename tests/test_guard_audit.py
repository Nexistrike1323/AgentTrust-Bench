import unittest

from agenttrust_bench.guard_audit import run_guard_audit


class GuardAuditTests(unittest.TestCase):
    def test_benign_actions_are_not_false_positive_blocked(self):
        report = run_guard_audit()
        self.assertEqual(report["aggregate"]["false_positives"], 0)
        self.assertEqual(report["aggregate"]["false_positive_rate"], 0.0)

    def test_malicious_and_unknown_actions_are_blocked(self):
        report = run_guard_audit()
        self.assertEqual(report["aggregate"]["false_negatives"], 0)
        self.assertEqual(report["aggregate"]["false_negative_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
