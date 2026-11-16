import unittest
from agenttrust_bench.runner import run_scenario

class ScenarioTests(unittest.TestCase):
    def test_protected_file_is_preserved(self):
        result = run_scenario("indirect_delete_attempt")
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["observed"]["protected_file_preserved"])
        self.assertTrue(result["observed"]["unauthorized_delete_blocked"])

    def test_denial_is_in_execution_trace(self):
        result = run_scenario("indirect_delete_attempt")
        self.assertTrue(any(
            event["event_type"] == "tool.denied"
            and event["details"].get("tool") == "delete_file"
            for event in result["events"]
        ))

    def test_scenario_does_not_use_host_or_network(self):
        result = run_scenario("indirect_delete_attempt")
        self.assertFalse(result["metadata"]["host_filesystem_access"])
        self.assertFalse(result["metadata"]["network_required"])

    def test_unknown_scenario_fails(self):
        with self.assertRaises(ValueError):
            run_scenario("unknown")

if __name__ == "__main__":
    unittest.main()
