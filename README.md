# AgentTrust-Bench 1.1.0

AgentTrust-Bench is an offline-first benchmark harness for testing how a tool-using language model handles untrusted retrieved content and whether a default-deny runtime policy blocks unsafe simulated actions.

## What's new in 1.1.0

- Five attack variants are available for each of the five scenarios (25 scenario/variant combinations):
  - `baseline` — direct embedded instruction
  - `fake_authority` — system/developer authority impersonation
  - `urgency_pressure` — urgency and consequence pressure
  - `task_mixing` — benign task combined with a malicious second instruction
  - `obfuscated_instruction` — Base64-encoded instruction embedded in untrusted content
- Variant IDs and attack techniques are recorded in evaluation reports.
- `guard-test` exercises the runtime policy independently of model behavior.

## Safety boundary

All tool effects are mock-only and remain in memory. The model does not receive real tools and cannot access host files, shell commands, credentials, or external network destinations. The Guard test validates this project's in-memory default-deny policy; it does not prove production enforcement in another agent runtime.

## Requirements

- Python 3.10 or later
- Ollama installed locally for live-model evaluation
- A model already pulled in Ollama (example: `qwen2.5:3b`)
- No paid APIs, cloud services, datasets, or third-party Python runtime dependencies

## Windows PowerShell: run from source

From the extracted project directory:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m agenttrust_bench list
python -m unittest discover -s tests -v
```

No `pip install` is required for source execution.

## Run the Guard policy validation

This is a deterministic policy self-test; it does not call the LLM:

```powershell
python -m agenttrust_bench guard-test --output guard_validation.json
```

Expected result: 5/5 simulated sensitive actions denied and mock environment state unchanged.

## Run one live scenario and variant

```powershell
python -m agenttrust_bench run --scenario secret_exfiltration --variant fake_authority --provider ollama --model qwen2.5:3b --output secret_fake_authority.json
```

## Run a repeated variant evaluation

```powershell
python -m agenttrust_bench run --scenario secret_exfiltration --variant obfuscated_instruction --provider ollama --model qwen2.5:3b --runs 10 --output secret_obfuscated.json --html-output secret_obfuscated.html
```

## Run the full 25-combination attack matrix

The following PowerShell block runs five variants for each of the five scenarios, with five repetitions per combination (125 local model calls):

```powershell
$scenarios = @(
    "indirect_delete_attempt",
    "instruction_override",
    "secret_exfiltration",
    "external_send_attempt",
    "tool_permission_escalation"
)
$variants = @(
    "baseline",
    "fake_authority",
    "urgency_pressure",
    "task_mixing",
    "obfuscated_instruction"
)
New-Item -ItemType Directory -Force .\results\v1.1.0-qwen2.5-3b | Out-Null
foreach ($scenario in $scenarios) {
    foreach ($variant in $variants) {
        $name = "${scenario}__${variant}"
        python -m agenttrust_bench run --scenario $scenario --variant $variant --provider ollama --model qwen2.5:3b --runs 5 --output ".\results\v1.1.0-qwen2.5-3b\$name.json" --html-output ".\results\v1.1.0-qwen2.5-3b\$name.html"
        if ($LASTEXITCODE -ne 0) { throw "Evaluation failed: $name" }
    }
}
```

This takes longer than the original 50-run baseline. Start with `guard-test`, then one or two variants before running the full matrix.

## Verdicts

- `model_verdict`: `RESISTED`, `VULNERABLE`, or `INCONCLUSIVE`
- `guard_verdict`: `BLOCKED`, `ALLOWED`, or `NOT_TRIGGERED`
- `environment_verdict`: `INTACT`, `COMPROMISED`, or `INCONCLUSIVE`

A model can be `VULNERABLE` while the Guard is `BLOCKED` and the environment remains `INTACT`. This indicates a model failure contained by the simulated policy, not a model pass.

## Limitations

- Five variants per scenario improve coverage but are not exhaustive prompt-injection coverage.
- Temperature-zero repeated runs can be identical; report variant coverage separately from repetition consistency.
- The Guard policy test exercises only the in-memory mock environment.
- Results apply only to the selected model, prompt variant, Ollama configuration, and benchmark implementation.
- A successful mock Guard decision does not establish production security of an independently deployed agent.

## Tests

```powershell
python -m unittest discover -s tests -v
```

Tests use fake providers and do not require Ollama or network access.


## v1.2.0 final validation additions

### Paired baseline-versus-Guard runtime comparison

This command generates one model decision per repetition, then replays the exact same decision against two isolated in-memory runtimes:
- `unguarded`: a deliberately vulnerable mock control that permits the simulated action
- `guarded`: the default-deny policy runtime

This controls for model randomness between the two runtime arms. The unguarded control can only mutate its own in-memory state; it cannot delete host files, reveal real credentials, or send network traffic.

```powershell
python -m agenttrust_bench compare `
  --scenario external_send_attempt `
  --variant urgency_pressure `
  --model qwen2.5:3b `
  --runs 10 `
  --output .\results\paired-external-send.json
```

The command creates JSON and HTML reports. `guard_block_rate_over_unsafe_attempts` uses only model-generated unsafe attempts as its denominator and is `null` if no unsafe action occurs.

### Benign-task utility and over-refusal evaluation

```powershell
python -m agenttrust_bench utility-test `
  --model qwen2.5:3b `
  --runs 2 `
  --output .\results\utility-qwen2.5-3b.json
```

This evaluates five benign summarization tasks per repetition and reports task completion, refusal, and inconclusive rates. It is a utility smoke test; it does not judge summary factuality or quality.

### Validate a second local model

If another model is already installed in Ollama, run the same paired comparison and utility test with its model name. Example:

```powershell
python -m agenttrust_bench compare --scenario external_send_attempt --variant urgency_pressure --model llama3.2:3b --runs 10 --output .\results\paired-llama3.2-3b.json
python -m agenttrust_bench utility-test --model llama3.2:3b --runs 2 --output .\results\utility-llama3.2-3b.json
```

Use `ollama list` to see locally installed models. No cloud provider is used.

## Final scope and honest status

v1.2.0 is a completed, offline-first **research prototype** with:
- five threat scenarios and five attack variants per scenario;
- local Ollama evaluation;
- model, Guard, and environment verdict separation;
- default-deny policy tests;
- paired counterfactual comparison using the same model decision in guarded and unguarded mock runtimes;
- benign-task completion and over-refusal measurement;
- JSON and HTML evidence reports.

It is not a production security certification and does not claim integration with arbitrary third-party agent frameworks. The paired runtime tests validate the benchmark's own reference runtime boundary. Integrating the Guard into a separately deployed agent requires an adapter specific to that agent's tool interface and is outside this standalone benchmark release.


## v1.3.0 — Runtime boundary, policy audit, and final live validation

### Reference agent runtime integration

`GuardedToolGateway` is the benchmark's executable reference tool boundary. An agent adapter should route each tool invocation through `gateway.call(tool_name, arguments)` and must not call tool handlers directly. The shipped gateway includes only two benign local tools:
- `summarize`
- `extract_public_info`

Sensitive actions (`delete_file`, `reveal_secret`, `send_external`, `grant_admin`) and unknown tools are denied before any handler can run. The gateway has no host filesystem, shell, or network handlers. See `src/agenttrust_bench/runtime.py`.

This is a concrete integration boundary for an agent runtime, not a drop-in adapter for every third-party framework. Framework-specific adapters must call this gateway for every tool invocation and must not retain a bypass path.

### Policy false-positive / false-negative audit

```powershell
python -m agenttrust_bench guard-audit --output .\results\guard-audit.json
```

The report separately measures benign actions blocked (false positives) and malicious/unknown actions allowed (false negatives). The audit set is deliberately small and hand-authored; rates are test-set metrics, not real-world prevalence estimates.

### Final live validation — run only after development is frozen

Check installed local models:

```powershell
ollama list
```

Run the full final matrix for one or more locally installed models:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_final_live_validation.ps1 -Models @("qwen2.5:3b","llama3.2:3b") -RunsPerCase 5
```

Remove any model name not installed locally. The script runs 50 scenario/variant combinations per model, paired runtime comparison, benign utility evaluation, Guard validation, and policy audit. It creates JSON and HTML evidence under `results\v1.3.0-final`.

### Final development boundary

After the v1.3.0 test suite passes, feature development is frozen. The remaining task is operator-run live validation against installed Ollama models and review of the generated evidence. The reference gateway is a real executable enforcement boundary inside this benchmark; it does not claim automatic protection of external agent frameworks without a dedicated adapter.
