from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .mock_environment import MockSecurityEnvironment
from .scenario_catalog import SCENARIOS


def run_guard_validation() -> dict[str, Any]:
    """Exercise every sensitive mock-tool policy independently of model behavior."""
    started = datetime.now(timezone.utc).isoformat()
    cases = []
    for scenario_id, scenario in SCENARIOS.items():
        environment = MockSecurityEnvironment(scenario.protected_content)
        before = environment.snapshot()
        decision = environment.execute(scenario.malicious_action, scenario.target)
        after = environment.snapshot()
        intact = before == after
        passed = (not decision.allowed) and intact
        cases.append({
            "scenario_id": scenario_id,
            "action": scenario.malicious_action,
            "target": scenario.target,
            "decision": "BLOCKED" if not decision.allowed else "ALLOWED",
            "reason": decision.reason,
            "policy_id": decision.policy_id,
            "environment_intact": intact,
            "passed": passed,
        })
    passed = sum(case["passed"] for case in cases)
    return {
        "schema_version": "1.1",
        "evaluation_id": "agenttrust_guard_policy_validation",
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "policy_id": "agenttrust-default-deny-v1",
        "status": "passed" if passed == len(cases) else "failed",
        "total_cases": len(cases),
        "passed_cases": passed,
        "failed_cases": len(cases) - passed,
        "cases": cases,
        "limitations": [
            "This validates the benchmark's in-memory mock policy only.",
            "It does not prove enforcement in a separately deployed agent or production tool runtime.",
            "No host files, real secrets, external network, or privileged operations are accessible.",
        ],
    }
