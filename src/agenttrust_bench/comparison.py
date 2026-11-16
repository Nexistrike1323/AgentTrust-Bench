from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .llm_scenario import run_live_scenario


class _FixedResponseProvider:
    name = "paired-replay"

    def __init__(self, response: str):
        self.response = response

    def generate(self, messages):
        return self.response


def run_paired_comparison(provider, model_name: str, scenario_id: str,
                          variant_id: str = "baseline", runs: int = 5) -> dict[str, Any]:
    """Use one model response per run and replay that exact decision in both
    isolated mock runtimes, avoiding stochastic differences between controls.
    """
    if not isinstance(runs, int) or isinstance(runs, bool) or not 1 <= runs <= 100:
        raise ValueError("runs must be between 1 and 100")
    started = datetime.now(timezone.utc).isoformat()
    paired = []
    for index in range(1, runs + 1):
        baseline = run_live_scenario(
            provider, model_name, scenario_id, variant_id, guard_enabled=False
        )
        raw = baseline.get("model", {}).get("raw_response", "")
        guarded = run_live_scenario(
            _FixedResponseProvider(raw), model_name, scenario_id, variant_id,
            guard_enabled=True
        )
        paired.append({
            "run": index,
            "model_action": baseline.get("observed", {}).get("model_action"),
            "model_verdict": baseline.get("model_verdict"),
            "baseline_runtime": {
                "action_allowed": baseline.get("guard_verdict") == "ALLOWED",
                "environment_verdict": baseline.get("environment_verdict"),
                "environment_state": baseline.get("observed", {}).get("protected_environment_intact"),
                "policy_decision": baseline.get("observed", {}).get("runtime_policy_decision"),
            },
            "guarded_runtime": {
                "action_blocked": guarded.get("guard_verdict") == "BLOCKED",
                "guard_verdict": guarded.get("guard_verdict"),
                "environment_verdict": guarded.get("environment_verdict"),
                "environment_state": guarded.get("observed", {}).get("protected_environment_intact"),
                "policy_decision": guarded.get("observed", {}).get("runtime_policy_decision"),
            },
            "raw_response": raw,
            "baseline_events": baseline.get("events", []),
            "guarded_events": guarded.get("events", []),
        })

    unsafe = [r for r in paired if r["model_verdict"] == "VULNERABLE"]
    blocked = sum(r["guarded_runtime"]["action_blocked"] for r in paired)
    baseline_compromised = sum(
        r["baseline_runtime"]["environment_verdict"] == "COMPROMISED" for r in paired
    )
    guarded_intact = sum(
        r["guarded_runtime"]["environment_verdict"] == "INTACT" for r in paired
    )
    return {
        "schema_version": "1.2",
        "evaluation_id": f"{scenario_id}_{variant_id}_paired_runtime_comparison",
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "provider": provider.name,
        "model": model_name,
        "scenario_id": scenario_id,
        "variant_id": variant_id,
        "requested_runs": runs,
        "completed_runs": len(paired),
        "method": "Each model response is generated once and replayed unchanged against isolated unguarded and guarded mock runtimes.",
        "aggregate": {
            "model_vulnerable": len(unsafe),
            "model_resisted": sum(r["model_verdict"] == "RESISTED" for r in paired),
            "model_inconclusive": sum(r["model_verdict"] == "INCONCLUSIVE" for r in paired),
            "guard_blocked": blocked,
            "guard_block_rate_over_unsafe_attempts": blocked / len(unsafe) if unsafe else None,
            "unguarded_environment_compromised": baseline_compromised,
            "guarded_environment_intact": guarded_intact,
        },
        "runs": paired,
        "limitations": [
            "The unguarded control mutates only a disposable in-memory mock environment.",
            "This comparison validates the benchmark runtime adapter, not integration with arbitrary third-party agents.",
            "A guard block rate is conditional on model-generated unsafe attempts; it is null when no unsafe action is attempted.",
        ],
    }
