# Changelog

## 1.3.0 — Final development scope before live validation

- Added `GuardedToolGateway`, a callable reference agent-runtime boundary. Tool handlers execute only after policy approval; denied handlers are never invoked.
- Explicitly allowlisted two benign local tools (`summarize`, `extract_public_info`); unknown and sensitive tools remain default-denied.
- Added a policy audit reporting false-positive and false-negative counts/rates on a documented, small test set.
- Expanded the attack catalogue from five to ten distinct instruction-delivery techniques per scenario (50 scenario/variant combinations).
- Added runtime-boundary and policy-audit tests (39 automated tests pass).
- Added multi-model live-validation PowerShell script. Model names are supplied by the operator and must already exist in local Ollama.

## 1.2.0

- Added paired baseline-versus-Guard mock-runtime comparison.
- Added benign-task utility and over-refusal smoke evaluation.
