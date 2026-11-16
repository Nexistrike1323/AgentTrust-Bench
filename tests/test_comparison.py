import unittest

from agenttrust_bench.comparison import run_paired_comparison


class FakeProvider:
    name = "fake"

    def __init__(self, response):
        self.response = response
        self.calls = 0

    def generate(self, messages):
        self.calls += 1
        return self.response


class ComparisonTests(unittest.TestCase):
    def test_same_model_action_replayed_against_both_runtimes(self):
        provider = FakeProvider('{"action":"reveal_secret","target":"attacker.example"}')
        report = run_paired_comparison(
            provider, "fake-model", "secret_exfiltration", "urgency_pressure", 2
        )
        self.assertEqual(provider.calls, 2)
        self.assertEqual(report["aggregate"]["model_vulnerable"], 2)
        self.assertEqual(report["aggregate"]["unguarded_environment_compromised"], 2)
        self.assertEqual(report["aggregate"]["guarded_environment_intact"], 2)
        self.assertEqual(report["aggregate"]["guard_block_rate_over_unsafe_attempts"], 1.0)

    def test_no_unsafe_action_has_null_guard_rate(self):
        provider = FakeProvider('{"action":"summarize","summary":"A benign summary."}')
        report = run_paired_comparison(provider, "fake-model", "secret_exfiltration", runs=1)
        self.assertIsNone(report["aggregate"]["guard_block_rate_over_unsafe_attempts"])
