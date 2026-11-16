param(
    [string[]]$Models = @("qwen2.5:3b"),
    [int]$RunsPerCase = 5
)

$ErrorActionPreference = "Stop"
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
    "obfuscated_instruction",
    "quoted_instruction",
    "delimiter_confusion",
    "roleplay_persona",
    "multi_step_delegation",
    "multilingual_wrapper"
)

$env:PYTHONPATH = "$PWD\src"
New-Item -ItemType Directory -Force .\results\v1.3.0-final | Out-Null

Write-Host "Checking local Ollama models..." -ForegroundColor Cyan
ollama list

foreach ($model in $Models) {
    $safeModel = $model -replace '[^a-zA-Z0-9._-]', '_'
    $outDir = ".\results\v1.3.0-final\$safeModel"
    New-Item -ItemType Directory -Force $outDir | Out-Null

    foreach ($scenario in $scenarios) {
        foreach ($variant in $variants) {
            $name = "${scenario}__${variant}"
            Write-Host "[$model] $name" -ForegroundColor Cyan
            python -m agenttrust_bench run `
                --scenario $scenario `
                --variant $variant `
                --provider ollama `
                --model $model `
                --runs $RunsPerCase `
                --output "$outDir\$name.json" `
                --html-output "$outDir\$name.html"
            if ($LASTEXITCODE -ne 0) { throw "Failed: $model / $name" }
        }
    }

    python -m agenttrust_bench compare `
        --scenario external_send_attempt `
        --variant urgency_pressure `
        --model $model `
        --runs 10 `
        --output "$outDir\paired-runtime-comparison.json"
    if ($LASTEXITCODE -ne 0) { throw "Paired comparison failed for $model" }

    python -m agenttrust_bench utility-test `
        --model $model `
        --runs 2 `
        --output "$outDir\benign-utility.json"
    if ($LASTEXITCODE -ne 0) { throw "Utility evaluation failed for $model" }
}

python -m agenttrust_bench guard-test --output .\results\v1.3.0-final\guard-validation.json
if ($LASTEXITCODE -ne 0) { throw "Guard validation failed" }

python -m agenttrust_bench guard-audit --output .\results\v1.3.0-final\guard-audit.json
if ($LASTEXITCODE -ne 0) { throw "Guard audit failed" }

Write-Host "`nFINAL LIVE VALIDATION COMPLETED" -ForegroundColor Green
Write-Host "Reports: .\results\v1.3.0-final"
