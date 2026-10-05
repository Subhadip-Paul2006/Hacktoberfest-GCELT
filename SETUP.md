# NSAT — Network Security Audit & Threat Assessment: Setup

## Table of Contents

- [Prerequisites and checkout status](#prerequisites-and-checkout-status)
- [Installation](#installation)
- [Run doctor and audit](#run-doctor-and-audit)
- [Active validation and oversight](#active-validation-and-oversight)
- [Reports](#reports)
- [AI configuration](#ai-configuration)
- [Explain, chat, and remediation](#explain-chat-and-remediation)
- [PDF remediation report](#pdf-remediation-report)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Authorized use](#authorized-use)
- [Documentation](#documentation)

## Prerequisites and checkout status

- Python 3.11 or later.
- Git, if cloning the repository.
- Optional: an approved provider endpoint and credentials for GLM/Kimi-assisted functions.
- A running test application only for active validation.

**Packaging caveat:** the current checkout does not include a root `pyproject.toml`, `setup.py`, or root dependency file. Consequently a clean `pip install -e .` and a dependency-complete setup cannot be guaranteed from the tracked repository contents. Ask the maintainer for the project’s supported dependency/install manifest, or use an already prepared environment. Do not install guessed dependencies into production environments.

## Installation

Clone the repository and create a virtual environment:

```powershell
git clone <repository-url>
cd network-agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On macOS/Linux, activate with `source .venv/bin/activate`. The `nsat` executable requires this package and its declared Python dependencies to be installed. Because this checkout lacks packaging metadata, there is no verified repository command to complete that step. Once maintainers provide it, follow that install instruction rather than inferring a requirements list from imports.

The phase regression files are under `tests/`; do not assume pytest or runtime dependencies are installed unless declared by your environment.

## Run doctor and audit

After the CLI is available:

```console
nsat --help
nsat doctor
nsat audit PATH
```

`doctor` reports Python/Git, language analyzer, and optional external-tool availability. `audit` runs local project discovery and deterministic scanners. To emit JSON to stdout or restrict to discovery, see `nsat audit --help` for `--json-out` and `--phase1-only`.

## Active validation and oversight

Only test an application you own or are explicitly authorized to assess. Start the target using its own documented development command, then bound NSAT to that URL:

```console
nsat validate PATH --target http://127.0.0.1:8000 --authorized
```

The authorization flag is an acknowledgement by the operator; it does not establish that permission exists. An audit can combine optional checks:

```console
nsat audit PATH --active --target http://127.0.0.1:8000 --authorized --oversight
```

Developer oversight can also be invoked without active checks:

```console
nsat oversight PATH
```

## Reports

Generate human-readable Markdown to a chosen path:

```console
nsat report PATH --format markdown --output audit-report.md --no-save
```

JSON is available with `--format json`. Terminal is the default. The CLI currently accepts `sarif` and `html`, but the report manager does not implement those output renderers; do not use them as production exports. Default generated audit artifacts are stored under `reports/` unless `--no-save` is set. Reports may contain sensitive repository context.

AI-assisted executive narrative:

```console
nsat ai-report PATH --output executive-report.md
```

This command requires a configured, available provider for AI narrative; review the result and deterministic findings separately.

## AI configuration

Copy `.env.example` to `.env` and replace the example credentials locally. Never commit `.env` or real credentials.

```dotenv
AI_ENABLED=true
GLM_API_KEY=<provider-issued-key>
GLM_BASE_URL=<approved-compatible-api-base-url>
GLM_MODEL=z-ai/glm-5.3
KIMI_API_KEY=<provider-issued-key>
KIMI_BASE_URL=<approved-compatible-api-base-url>
KIMI_MODEL=moonshotai/kimi-k3
```

Defaults are configurable and may not match your provider account. The code also recognizes selected NVIDIA/OpenAI-compatible fallback environment names; exact precedence is implemented in `nsat/ai/config.py`. GLM is used for security reasoning/report/chat; Kimi is the remediation model. `AI_ENABLED=false` disables these providers. AI use may send the constructed, redacted context to the configured endpoint; use only an endpoint authorized for your data and review sensitive context before enabling it.

## Explain, chat, and remediation

`explain` and `chat` build security context by running local analysis. `fix` reuses the latest saved audit context for the project when available and otherwise builds a fresh model. For example:

```console
nsat explain FINDING_ID PATH --no-ai
nsat chat PATH --ask "Explain the evidence and uncertainty for the highest priority finding"
nsat fix FINDING_ID PATH --dry-run
```

Review the proposed diff carefully. When ready, `nsat fix FINDING_ID PATH` prompts for approval; `--yes` bypasses that prompt and should be reserved for controlled automation. Applying a patch creates snapshot state under the target project’s `.nsat` directory and runs available verification checks. To inspect recorded outcomes later:

```console
nsat verify FINDING_ID PATH
```

The `verify` command displays remediation history; it does not start a new verification run. During `fix`, the engine performs available syntax/test checks and a relevant rescan. If a failure triggers rollback, newer user edits are protected by hash checks and may result in a rollback conflict. The `--force` rollback option can override those protections; inspect the current files and backup first.

## PDF remediation report

The separate report CLI consumes JSON model inputs; it does not run a scan or apply a patch:

```console
python -m nsat.remediation_report --help
python -m nsat.remediation_report --finding finding.json --proposal proposal.json --output remediation.pdf
python -m nsat.remediation_report --list
```

The `finding.json` and `proposal.json` files must contain data valid for the corresponding Pydantic models. Snapshot metadata is optional with `--snapshot`. By default, PDFs are written beneath `reports/remediations/`. Treat them as sensitive review artifacts.

## Configuration

Core project settings are YAML fields `project`, `analysis`, `scanners`, and `ai`; see `nsat/core/config.py` for current defaults/validation. Supply a custom file with CLI `--config PATH` where supported, or put `nsat.yaml`/`nsat.yml` in the target project. Although `nsat.toml` is probed, the loader parses YAML; use YAML. Provider secrets/configuration are separate environment settings described above. `nsat config` displays the CLI’s configuration output.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `nsat` command not found | Confirm the package is installed in the active environment; the current repo lacks install metadata. |
| `doctor` reports missing analyzer/tool | Some tools are optional. Review its output; do not infer that a missing optional tool disables every native check. |
| AI provider unavailable | Check `AI_ENABLED`, the relevant key/base URL/model, network access, and provider account. Never paste a key into an issue. |
| Target rejected or no validation results | Confirm URL, that the local service is running, and that you have authorization; check target-scope/agent result output. |
| Finding context unavailable | `explain` and `chat` build analysis context from the target; `fix` builds fresh context if no saved AI-enabled audit context is available. |
| Patch or rollback conflict | Stop; inspect current file, snapshot metadata, and remediation history. Do not force-rollback until newer edits are backed up and reviewed. |
| PDF generation fails | Check valid finding/proposal JSON, optional snapshot JSON, and installed report dependencies. |

## Authorized use

Use NSAT against source and systems within your authority. Active checks can issue HTTP requests and may affect application logs or state despite bounded behavior. Obtain permission, use a test environment where practical, scope to a known URL, and stop if the target is unexpected. See [SECURITY.md](SECURITY.md).

## Documentation

- [README](README.md) · [PRD](PRD.md) · [TRD](TRD.md) · [Architecture](ARCHITECTURE.md)
- [Phases](Phases.md) · [AI Instructions](AI_INSTRUCTION.md) · [Agent Instructions](AGENTS.md)
- [Contributing](CONTRIBUTING.md) · [Security Policy](SECURITY.md)
