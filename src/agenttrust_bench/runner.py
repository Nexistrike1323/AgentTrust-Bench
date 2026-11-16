import json
from pathlib import Path

from .scenarios import SCENARIOS
from .scenario_catalog import SCENARIOS as LIVE_SCENARIOS
from .validation import validate_trace


def list_scenarios():
    items = [
        {"id": key, "description": item["description"],
         "contract_version": item["contract_version"],
         "modes": ["deterministic", "live_local_model"] if key in LIVE_SCENARIOS else ["deterministic"],
         "attack_variants": [{"id": v.id, "technique": v.technique} for v in LIVE_SCENARIOS[key].variants] if key in LIVE_SCENARIOS else []}
        for key, item in SCENARIOS.items()
    ]
    items.extend(
        {"id": key, "description": scenario.description,
         "contract_version": "1.0", "modes": ["live_local_model"],
         "attack_variants": [{"id": v.id, "technique": v.technique} for v in scenario.variants]}
        for key, scenario in LIVE_SCENARIOS.items()
        if key not in SCENARIOS
    )
    return items


def run_scenario(scenario_id, output=None, provider=None, model_name=None, variant_id="baseline"):
    if provider is None:
        if scenario_id not in SCENARIOS:
            raise ValueError("Deterministic mode is currently available only for: " + ", ".join(SCENARIOS))
        result = SCENARIOS[scenario_id]["execute"]()
    else:
        if scenario_id not in LIVE_SCENARIOS:
            raise ValueError(f"Unknown live scenario '{scenario_id}'.")
        from .llm_scenario import run_live_scenario
        result = run_live_scenario(provider, model_name or "unknown", scenario_id, variant_id)

    if output:
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(result, indent=2) + chr(10), encoding="utf-8"
        )
    return result


def load_result(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    required = {
        "schema_version", "scenario_id", "status",
        "expected", "observed", "events",
    }
    missing = required - data.keys()
    if missing:
        raise ValueError(f"Invalid result; missing fields: {sorted(missing)}")
    if not isinstance(data["events"], list):
        raise ValueError("Invalid result; events must be a list")

    trace = validate_trace(data["events"])
    if not trace["valid"]:
        raise ValueError(f"Invalid event trace: {', '.join(trace['errors'])}")

    if "validation" in data and "trace" in data["validation"]:
        stored_trace = data["validation"].get("trace", {})
        if stored_trace.get("valid") is not True:
            raise ValueError("Invalid result; recorded trace validation did not pass")

    return data
