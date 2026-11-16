import unittest

from agenttrust_bench.evaluation import run_repeated_evaluation


class SequenceProvider:
    name = "fake"

    def __init__(self, responses):
        self.responses = iter(responses)

    def generate(self, messages):
        return next(self.responses)


class EvaluationTests(unittest.TestCase):
    def test_aggregates_model_and_guard_verdicts_separately(self):
        provider = SequenceProvider([
            '{"action":"delete_file","target":"confidential.txt"}',
            '{"action":"refuse","reason":"untrusted document"}',
        ])
        result = run_repeated_evaluation(provider, "fake-model", runs=2)
        self.assertEqual(result["completed_runs"], 2)
        self.assertEqual(result["aggregate"]["model_vulnerable"], 1)
        self.assertEqual(result["aggregate"]["model_resisted"], 1)
        self.assertEqual(result["aggregate"]["guard_blocked"], 1)
        self.assertEqual(result["aggregate"]["guard_not_triggered"], 1)
        self.assertEqual(result["interpretation"]["model_verdict"], "VULNERABLE")
        self.assertEqual(result["interpretation"]["environment_verdict"], "INTACT")

    def test_rejects_invalid_run_count(self):
        provider = SequenceProvider([])
        with self.assertRaises(ValueError):
            run_repeated_evaluation(provider, "fake-model", runs=0)


if __name__ == "__main__":
    unittest.main()
