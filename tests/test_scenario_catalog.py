import unittest

from agenttrust_bench.scenario_catalog import SCENARIOS, get_variant, render_variant_instruction
from agenttrust_bench.llm_scenario import run_live_scenario


class FakeProvider:
    name = "fake"
    def __init__(self, response):
        self.response = response
        self.messages = None
    def generate(self, messages):
        self.messages = messages
        return self.response


class ScenarioCatalogTests(unittest.TestCase):
    def test_catalog_has_five_distinct_attack_classes(self):
        self.assertGreaterEqual(len(SCENARIOS), 5)
        self.assertEqual(len({s.malicious_action for s in SCENARIOS.values()}), 4)

    def test_each_scenario_has_threat_model_fields(self):
        for scenario in SCENARIOS.values():
            with self.subTest(scenario=scenario.id):
                self.assertTrue(scenario.attacker_instruction)
                self.assertTrue(scenario.target)
                self.assertTrue(scenario.expected_safe_action)

    def test_sensitive_action_is_denied_in_mock_environment(self):
        for scenario_id, scenario in SCENARIOS.items():
            response = (
                '{"action":"' + scenario.malicious_action +
                '","target":"' + scenario.target + '"}'
            )
            result = run_live_scenario(FakeProvider(response), "fake", scenario_id)
            self.assertEqual(result["model_verdict"], "VULNERABLE")
            self.assertEqual(result["guard_verdict"], "BLOCKED")
            self.assertEqual(result["environment_verdict"], "INTACT")
            self.assertTrue(result["validation"]["trace"]["valid"])

    def test_each_scenario_exposes_ten_distinct_attack_variants(self):
        for scenario in SCENARIOS.values():
            with self.subTest(scenario=scenario.id):
                ids = [variant.id for variant in scenario.variants]
                self.assertEqual(len(ids), 10)
                self.assertEqual(len(set(ids)), 10)
                for variant in scenario.variants:
                    self.assertTrue(render_variant_instruction(scenario, variant))

    def test_unknown_variant_is_rejected(self):
        with self.assertRaises(ValueError):
            get_variant(next(iter(SCENARIOS.values())), "not-a-real-variant")


if __name__ == "__main__":
    unittest.main()
