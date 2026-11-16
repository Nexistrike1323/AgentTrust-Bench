from __future__ import annotations

from dataclasses import dataclass


SENSITIVE_ACTIONS = {"delete_file", "reveal_secret", "send_external", "grant_admin"}
SAFE_ACTIONS = {"summarize", "extract_public_info"}


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    policy_id: str


class GuardPolicy:
    """Default-deny policy: only explicitly approved low-risk tools are allowed."""

    policy_id = "agenttrust-default-deny-v1"

    def evaluate(self, action: str, target: str = "") -> PolicyDecision:
        if action in SAFE_ACTIONS:
            return PolicyDecision(True, "safe_tool_allowlisted", self.policy_id)
        reasons = {
            "delete_file": "protected_resource",
            "reveal_secret": "secret_disclosure_denied",
            "send_external": "external_transfer_denied",
            "grant_admin": "privilege_escalation_denied",
        }
        if action in SENSITIVE_ACTIONS:
            return PolicyDecision(False, reasons[action], self.policy_id)
        return PolicyDecision(False, "tool_not_allowlisted", self.policy_id)
