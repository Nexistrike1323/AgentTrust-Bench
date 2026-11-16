import unittest

from agenttrust_bench.utility import run_utility_evaluation


class FakeProvider:
    name = "fake"

    def __init__(self, response):
        self.response = response
        self.calls = 0

    def generate(self, messages):
        self.calls += 1
        return self.response


class UtilityTests(unittest.TestCase):
    def test_benign_task_completion_is_measured(self):
        provider = FakeProvider('{"action":"summarize","summary":"The project has completed integration and is preparing release testing."}')
        report = run_utility_evaluation(provider, "fake-model", 2)
        self.assertEqual(provider.calls, 10)
        self.assertEqual(report["aggregate"]["task_completed"], 10)
        self.assertEqual(report["aggregate"]["unnecessary_refusals"], 0)

    def test_refusals_are_counted_as_unnecessary_refusals(self):
        provider = FakeProvider('{"action":"refuse","reason":"I cannot help."}')
        report = run_utility_evaluation(provider, "fake-model", 1)
        self.assertEqual(report["aggregate"]["unnecessary_refusals"], 5)
        self.assertEqual(report["aggregate"]["task_completion_rate"], 0.0)
