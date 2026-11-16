import argparse
import json
import sys
from pathlib import Path

from .runner import list_scenarios, load_result, run_scenario


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agenttrust-bench")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")

    run = sub.add_parser("run")
    run.add_argument("--scenario", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--provider", choices=["ollama"], default=None)
    run.add_argument("--model", default=None)
    run.add_argument("--runs", type=int, default=1)
    run.add_argument("--variant", default="baseline", help="Attack variant id; see list output")
    run.add_argument("--html-output", default=None, help="Optional HTML report path for repeated live evaluations")

    guard_test = sub.add_parser("guard-test", help="Validate default-deny mock guard policy")
    guard_test.add_argument("--output", default="guard_validation.json")

    compare = sub.add_parser("compare", help="Paired guarded vs unguarded mock-runtime comparison")
    compare.add_argument("--scenario", required=True)
    compare.add_argument("--variant", default="baseline")
    compare.add_argument("--model", required=True)
    compare.add_argument("--runs", type=int, default=5)
    compare.add_argument("--output", required=True)

    utility = sub.add_parser("utility-test", help="Measure completion on benign tasks")
    utility.add_argument("--model", required=True)
    utility.add_argument("--runs", type=int, default=1)
    utility.add_argument("--output", required=True)

    guard_audit = sub.add_parser("guard-audit", help="Measure policy false positives and false negatives")
    guard_audit.add_argument("--output", default="guard_audit.json")

    inspect = sub.add_parser("inspect")
    inspect.add_argument("result_file")
    args = parser.parse_args(argv)

    try:
        if args.command == "list":
            print(json.dumps(list_scenarios(), indent=2))
            return 0

        if args.command == "guard-audit":
            from .guard_audit import run_guard_audit
            from .reporting import write_custom_report
            result = run_guard_audit()
            html_path = write_custom_report(result, args.output)
            print(json.dumps({
                "aggregate": result["aggregate"],
                "json_output": args.output,
                "html_output": html_path,
            }, indent=2))
            return 0

        if args.command == "guard-test":
            from .guard_validation import run_guard_validation
            result = run_guard_validation()
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({k: result[k] for k in ("status", "total_cases", "passed_cases", "failed_cases", "policy_id", "output") if k in result} | {"output": args.output}, indent=2))
            return 0 if result["status"] == "passed" else 1

        if args.command in {"compare", "utility-test"}:
            if not args.model:
                raise ValueError("--model is required")
            from .providers import OllamaProvider
            provider = OllamaProvider(model=args.model)
            if args.command == "compare":
                from .comparison import run_paired_comparison
                result = run_paired_comparison(
                    provider, args.model, args.scenario, args.variant, args.runs
                )
            else:
                from .utility import run_utility_evaluation
                result = run_utility_evaluation(provider, args.model, args.runs)
            from .reporting import write_custom_report
            html_path = write_custom_report(result, args.output)
            print(json.dumps({
                "evaluation_id": result["evaluation_id"],
                "completed_runs": result.get("completed_runs", result.get("requested_cases")),
                "aggregate": result["aggregate"],
                "json_output": args.output,
                "html_output": html_path,
            }, indent=2))
            return 0

        if args.command == "run":
            if args.runs < 1 or args.runs > 100:
                raise ValueError("--runs must be between 1 and 100")

            provider = None
            model_name = None
            if args.provider == "ollama":
                if not args.model:
                    raise ValueError("--model is required when --provider ollama is selected")
                from .providers import OllamaProvider
                provider = OllamaProvider(model=args.model)
                model_name = args.model

            if provider is not None and args.runs > 1:
                from .evaluation import run_repeated_evaluation
                result = run_repeated_evaluation(provider, model_name, args.runs, args.scenario, args.variant)
                from .reporting import write_json_report
                write_json_report(result, args.output)
                if args.html_output:
                    from .reporting import write_html_report
                    write_html_report(result, args.html_output)
                print(json.dumps({
                    "html_output": args.html_output,
                    "evaluation_id": result["evaluation_id"],
                    "evaluation_status": result["evaluation_status"],
                    "completed_runs": result["completed_runs"],
                    "output": args.output,
                    "aggregate": result["aggregate"],
                    "interpretation": result["interpretation"],
                }, indent=2))
                return 0

            if args.runs > 1 and provider is None:
                raise ValueError("--runs > 1 currently requires --provider ollama")

            result = run_scenario(
                args.scenario, args.output, provider=provider, model_name=model_name, variant_id=args.variant
            )
            print(json.dumps({
                "scenario_id": result["scenario_id"],
                "status": result["status"],
                "model_verdict": result.get("model_verdict"),
                "guard_verdict": result.get("guard_verdict"),
                "environment_verdict": result.get("environment_verdict"),
                "security_invariants_passed": result.get("security_invariants_passed"),
                "event_count": len(result["events"]),
                "output": args.output,
                "execution_mode": result.get("metadata", {}).get("execution_mode"),
                "observed": result.get("observed"),
            }, indent=2))
            if result.get("metadata", {}).get("execution_mode") == "deterministic_simulation":
                return 0 if result["status"] == "passed" else 1
            return 0 if result["status"] == "completed" else 1

        if args.command == "inspect":
            print(json.dumps(load_result(args.result_file), indent=2))
            return 0

    except (ValueError, OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2
