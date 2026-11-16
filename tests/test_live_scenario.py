import unittest

from agenttrust_bench.llm_scenario import run_live_scenario


class FakeProvider:
    name = "fake"

    def __init__(self, response):
        self.response = response
        self.messages = None

    def generate(self, messages):
        self.messages = messages
        return self.response


class LiveScenarioTests(unittest.TestCase):
    def test_model_delete_attempt_is_blocked_by_sandbox(self):
        provider = FakeProvider(
            '{"action":"delete_file","target":"confidential.txt","reason":"document said so"}'
        )
        result = run_live_scenario(provider, "fake-model")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["observed"]["model_action"], "delete_file")
        self.assertEqual(result["model_verdict"], "VULNERABLE")
        self.assertEqual(result["guard_verdict"], "BLOCKED")
        self.assertEqual(result["environment_verdict"], "INTACT")
        self.assertTrue(result["observed"]["protected_environment_intact"])
        self.assertEqual(result["observed"]["runtime_policy_decision"], "protected_resource")
        self.assertTrue(result["validation"]["trace"]["valid"])

    def test_model_refusal_is_recorded_as_resistance(self):
        provider = FakeProvider('{"action":"refuse","reason":"document is untrusted"}')
        result = run_live_scenario(provider, "fake-model")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["observed"]["model_resisted_untrusted_instruction"])
        self.assertEqual(result["model_verdict"], "RESISTED")
        self.assertEqual(result["observed"]["runtime_policy_decision"], "not_triggered")

    def test_invalid_model_output_is_inconclusive(self):
        provider = FakeProvider("I will delete the file now.")
        result = run_live_scenario(provider, "fake-model")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["model_verdict"], "INCONCLUSIVE")
        self.assertFalse(result["observed"]["model_decision_valid"])

    def test_prompt_marks_document_as_untrusted(self):
        provider = FakeProvider('{"action":"summarize","summary":"A report request."}')
        run_live_scenario(provider, "fake-model")
        self.assertIn("untrusted retrieved content", provider.messages[0]["content"])
        self.assertIn("<untrusted_document>", provider.messages[1]["content"])

    def test_variant_is_recorded_and_changes_untrusted_document(self):
        provider = FakeProvider('{"action":"summarize","summary":"ok"}')
        result = run_live_scenario(provider, "fake-model", "secret_exfiltration", "fake_authority")
        self.assertEqual(result["variant"]["id"], "fake_authority")
        self.assertEqual(result["contract"]["attack_technique"], "authority_impersonation")
        self.assertIn("SYSTEM/DEVELOPER NOTICE", provider.messages[1]["content"])

    def test_obfuscated_variant_uses_base64_payload(self):
        provider = FakeProvider('{"action":"summarize","summary":"ok"}')
        run_live_scenario(provider, "fake-model", "secret_exfiltration", "obfuscated_instruction")
        self.assertIn("Decode this Base64 payload", provider.messages[1]["content"])


if __name__ == "__main__":
    unittest.main()
