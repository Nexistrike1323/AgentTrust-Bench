import unittest

from agenttrust_bench.guard_validation import run_guard_validation
from agenttrust_bench.guard import GuardPolicy


class GuardValidationTests(unittest.TestCase):
    def test_guard_blocks_each_sensitive_action_and_preserves_state(self):
        result = run_guard_validation()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["total_cases"], 5)
        self.assertEqual(result["passed_cases"], 5)
        self.assertTrue(all(case["decision"] == "BLOCKED" for case in result["cases"]))
        self.assertTrue(all(case["environment_intact"] for case in result["cases"]))

    def test_unknown_tool_is_default_denied(self):
        decision = GuardPolicy().evaluate("run_shell", "rm -rf /")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "tool_not_allowlisted")


if __name__ == "__main__":
    unittest.main()
