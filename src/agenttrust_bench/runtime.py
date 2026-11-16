from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .guard import GuardPolicy


@dataclass(frozen=True)
class ToolResult:
    allowed: bool
    tool: str
    reason: str
    output: Any = None
    policy_id: str = "agenttrust-default-deny-v1"


class GuardedToolGateway:
    """Reference tool-execution boundary for an agent runtime.

    Agent frameworks should route every tool invocation through `call`.
    A denied call never invokes its handler. This gateway deliberately ships
    only with safe local example handlers; it has no filesystem or network tools.
    """

    def __init__(self, policy: GuardPolicy | None = None):
        self.policy = policy or GuardPolicy()
        self._handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
            "summarize": self._summarize,
            "extract_public_info": self._extract_public_info,
        }
        self.events: list[dict[str, Any]] = []

    @staticmethod
    def _summarize(arguments: dict[str, Any]) -> dict[str, str]:
        text = arguments.get("text", "")
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        return {"summary": text[:500]}

    @staticmethod
    def _extract_public_info(arguments: dict[str, Any]) -> dict[str, str]:
        text = arguments.get("text", "")
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        return {"public_text": text[:500]}

    def register_safe_tool(self, name: str, handler: Callable[[dict[str, Any]], Any]) -> None:
        decision = self.policy.evaluate(name)
        if not decision.allowed:
            raise ValueError("Only policy-allowlisted tools can be registered as safe tools")
        self._handlers[name] = handler

    def call(self, tool: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        args = arguments or {}
        decision = self.policy.evaluate(tool, str(args.get("target", "")))
        if not decision.allowed:
            self.events.append({
                "event_type": "tool.denied", "tool": tool,
                "reason": decision.reason, "policy_id": decision.policy_id,
            })
            return ToolResult(False, tool, decision.reason, None, decision.policy_id)

        handler = self._handlers.get(tool)
        if handler is None:
            self.events.append({
                "event_type": "tool.denied", "tool": tool,
                "reason": "allowlisted_tool_has_no_registered_handler",
                "policy_id": decision.policy_id,
            })
            return ToolResult(False, tool, "allowlisted_tool_has_no_registered_handler",
                              None, decision.policy_id)
        output = handler(args)
        self.events.append({
            "event_type": "tool.allowed", "tool": tool,
            "reason": decision.reason, "policy_id": decision.policy_id,
        })
        return ToolResult(True, tool, decision.reason, output, decision.policy_id)
