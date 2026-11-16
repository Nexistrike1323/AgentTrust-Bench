from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ReportValidationError(ValueError):
    pass


def validate_evaluation_report(report: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version", "evaluation_id", "evaluation_status",
        "provider", "model", "requested_runs", "completed_runs",
        "aggregate", "rates", "interpretation", "runs",
    }
    missing = sorted(required - report.keys())
    errors: list[str] = []
    if missing:
        errors.append("missing_fields:" + ",".join(missing))
        return {"valid": False, "errors": errors}

    requested = report["requested_runs"]
    completed = report["completed_runs"]
    runs = report["runs"]
    if not isinstance(requested, int) or not isinstance(completed, int):
        errors.append("run_counts_must_be_integers")
    else:
        if completed != len(runs):
            errors.append("completed_runs_does_not_match_run_records")
        if completed > requested:
            errors.append("completed_runs_exceeds_requested_runs")

    if not isinstance(runs, list):
        errors.append("runs_must_be_a_list")
        runs = []

    allowed_model = {"RESISTED", "VULNERABLE", "INCONCLUSIVE"}
    allowed_guard = {"BLOCKED", "ALLOWED", "MIXED", "NOT_TRIGGERED", "DENIED_OTHER_REASON"}
    allowed_environment = {"INTACT", "COMPROMISED", "INCONCLUSIVE"}
    for index, run in enumerate(runs, start=1):
        if not isinstance(run, dict):
            errors.append(f"run_{index}_must_be_an_object")
            continue
        if run.get("model_verdict") not in allowed_model:
            errors.append(f"run_{index}_invalid_model_verdict")
        if run.get("guard_verdict") not in allowed_guard:
            errors.append(f"run_{index}_invalid_guard_verdict")
        if run.get("environment_verdict") not in allowed_environment:
            errors.append(f"run_{index}_invalid_environment_verdict")

    aggregate = report["aggregate"]
    if not isinstance(aggregate, dict):
        errors.append("aggregate_must_be_an_object")
    else:
        expected = {
            "model_resisted": sum(r.get("model_verdict") == "RESISTED" for r in runs if isinstance(r, dict)),
            "model_vulnerable": sum(r.get("model_verdict") == "VULNERABLE" for r in runs if isinstance(r, dict)),
            "model_inconclusive": sum(r.get("model_verdict") == "INCONCLUSIVE" for r in runs if isinstance(r, dict)),
            "guard_blocked": sum(r.get("guard_verdict") == "BLOCKED" for r in runs if isinstance(r, dict)),
            "guard_allowed": sum(r.get("guard_verdict") == "ALLOWED" for r in runs if isinstance(r, dict)),
            "environment_intact": sum(r.get("environment_verdict") == "INTACT" for r in runs if isinstance(r, dict)),
            "environment_compromised": sum(r.get("environment_verdict") == "COMPROMISED" for r in runs if isinstance(r, dict)),
        }
        for key, value in expected.items():
            if aggregate.get(key) != value:
                errors.append(f"aggregate_mismatch:{key}")

    return {"valid": not errors, "errors": errors}


def write_json_report(report: dict[str, Any], path: str | Path) -> None:
    validation = validate_evaluation_report(report)
    if not validation["valid"]:
        raise ReportValidationError(";".join(validation["errors"]))
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + chr(10),
        encoding="utf-8",
    )


def load_json_report(path: str | Path) -> dict[str, Any]:
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportValidationError(f"invalid_json_report:{exc}") from exc
    validation = validate_evaluation_report(report)
    if not validation["valid"]:
        raise ReportValidationError(";".join(validation["errors"]))
    return report
\


def write_html_report(report: dict[str, Any], path: str | Path) -> None:
    """Write a self-contained HTML summary. All dynamic text is HTML-escaped."""
    import html

    validation = validate_evaluation_report(report)
    if not validation["valid"]:
        raise ReportValidationError(";".join(validation["errors"]))

    def esc(value: Any) -> str:
        return html.escape(str(value), quote=True)

    aggregate_rows = "".join(
        f"<tr><th>{esc(key.replace('_', ' ').title())}</th><td>{esc(value)}</td></tr>"
        for key, value in report["aggregate"].items()
    )
    run_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('run'))}</td>"
        f"<td>{esc(item.get('model_verdict'))}</td>"
        f"<td>{esc(item.get('guard_verdict'))}</td>"
        f"<td>{esc(item.get('environment_verdict'))}</td>"
        f"<td>{esc(item.get('model_action'))}</td>"
        "</tr>"
        for item in report["runs"]
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentTrust-Bench Evaluation</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:40px auto;padding:0 20px;color:#202124}}
h1,h2{{line-height:1.2}} table{{border-collapse:collapse;width:100%;margin:16px 0 28px}}
th,td{{text-align:left;padding:9px 12px;border:1px solid #ddd}} th{{background:#f4f5f6}}
.meta{{color:#555}} code{{background:#f2f2f2;padding:2px 5px}}
</style></head><body>
<h1>AgentTrust-Bench Evaluation</h1>
<p class="meta">Scenario: <code>{esc(report.get('scenario_id'))}</code> | Variant: <code>{esc(report.get('variant_id', 'baseline'))}</code> |
Provider: <code>{esc(report.get('provider'))}</code> |
Model: <code>{esc(report.get('model'))}</code></p>
<p>Runs completed: <strong>{esc(report.get('completed_runs'))}</strong> /
{esc(report.get('requested_runs'))}</p>
<h2>Interpretation</h2>
<table><tbody>
<tr><th>Model</th><td>{esc(report['interpretation'].get('model_verdict'))}</td></tr>
<tr><th>Guard</th><td>{esc(report['interpretation'].get('guard_verdict'))}</td></tr>
<tr><th>Environment</th><td>{esc(report['interpretation'].get('environment_verdict'))}</td></tr>
</tbody></table>
<h2>Aggregate counts</h2><table><tbody>{aggregate_rows}</tbody></table>
<h2>Individual runs</h2>
<table><thead><tr><th>Run</th><th>Model</th><th>Guard</th><th>Environment</th><th>Action</th></tr></thead>
<tbody>{run_rows}</tbody></table>
<p class="meta">Generated by AgentTrust-Bench. Interpret results only within the stated scenario and model configuration.</p>
</body></html>"""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")



def write_custom_report(report: dict[str, Any], path: str | Path) -> str:
    """Write JSON plus a compact HTML view for non-standard evaluation schemas."""
    import html
    import json

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + chr(10), encoding="utf-8")
    html_path = destination.with_suffix(".html")
    title = html.escape(str(report.get("evaluation_id", "AgentTrust-Bench report")))
    aggregate = report.get("aggregate", {})
    rows = "".join(
        f"<tr><th>{html.escape(str(k).replace('_', ' ').title())}</th><td>{html.escape(str(v))}</td></tr>"
        for k, v in aggregate.items()
    )
    doc = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>{title}</title><style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:36px auto;padding:0 18px;color:#202124}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:9px;text-align:left}}
th{{background:#f4f5f6;width:55%}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
</style><h1>{title}</h1><h2>Aggregate results</h2><table>{rows}</table>
<h2>Method and limitations</h2><pre>{html.escape(str(report.get('method', report.get('limitations', ''))))}</pre>
</html>"""
    html_path.write_text(doc, encoding="utf-8")
    return str(html_path)
