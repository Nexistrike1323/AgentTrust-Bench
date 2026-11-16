# AgentTrust-Bench v1.3.0 — Final Development Scope

## Implemented before live validation
- Five security scenarios and ten attack-delivery variants per scenario (50 combinations).
- Local Ollama provider and repeated live evaluation.
- Separate model, Guard, and environment verdicts.
- Executable reference agent tool boundary (`GuardedToolGateway`) that mediates tool execution before handlers run.
- Explicit allowlist for benign local tools; sensitive and unknown tools default-denied.
- Paired guarded/unguarded mock-runtime comparison with the same model response replayed in both arms.
- Benign-task utility / over-refusal smoke evaluation.
- False-positive and false-negative policy audit.
- Multi-model final live-validation script.
- JSON/HTML reports and automated tests.

## Development validation completed
- 39/39 automated tests passed.
- CLI help and command registration verified.
- Guard validation: 5/5 passed.
- Policy audit smoke test: 4/4 benign tools allowed; 5/5 malicious/unknown tools blocked.
- All 50 scenario/variant instructions rendered successfully.
- Runtime gateway smoke test passed.

## Live validation still required
Run `run_final_live_validation.ps1` with one or more model names already installed in local Ollama. Model-specific live results are not claimed until the operator runs the script.

## Scope boundaries
- The unguarded comparison arm is a disposable in-memory control only.
- The Guard is executable in the benchmark reference runtime. A separate adapter is required for each external agent framework; no universal framework integration is claimed.
- Utility evaluation measures structured completion/refusal, not semantic summary quality.
- False-positive and false-negative rates apply only to the small documented policy audit set.
- This is a research prototype, not a production security certification.
