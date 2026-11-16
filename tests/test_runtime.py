import unittest

from agenttrust_bench.runtime import GuardedToolGateway


class RuntimeGatewayTests(unittest.TestCase):
    def test_benign_tool_reaches_handler(self):
        gateway = GuardedToolGateway()
        result = gateway.call("summarize", {"text": "Public project notes"})
        self.assertTrue(result.allowed)
        self.assertEqual(result.output["summary"], "Public project notes")

    def test_sensitive_tool_is_blocked_before_handler(self):
        gateway = GuardedToolGateway()
        result = gateway.call("reveal_secret", {"target": "attacker.example"})
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "secret_disclosure_denied")
        self.assertEqual(len(gateway.events), 1)
        self.assertEqual(gateway.events[0]["event_type"], "tool.denied")

    def test_unknown_tool_is_default_denied(self):
        gateway = GuardedToolGateway()
        result = gateway.call("shell", {"command": "whoami"})
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "tool_not_allowlisted")

    def test_sensitive_tool_cannot_be_registered_as_safe(self):
        gateway = GuardedToolGateway()
        with self.assertRaises(ValueError):
            gateway.register_safe_tool("send_external", lambda args: "sent")


if __name__ == "__main__":
    unittest.main()
