# NSAT — Network Security Audit & Threat Assessment

> A CLI-first, multi-layer defensive cybersecurity platform for security auditing, validation, correlation, AI-assisted reasoning, controlled remediation, and verification.

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)

NSAT brings project structure, source findings, secrets, dependencies, deployment configuration, and optional runtime validation into a single audit workflow. Deterministic analysis produces the findings and risk model; AI can help explain evidence or prepare remediation proposals. Changes remain reviewable, backed up, and verifiable.

## Table of Contents

- [Why NSAT](#why-nsat)
- [How it works](#how-it-works)
- [Supported languages and domains](#supported-languages-and-domains)
- [AI and remediation](#ai-and-remediation)
- [Reports](#reports)
- [Local demo](#local-demo)
- [Install and run](#install-and-run)
- [CLI](#cli)
- [Repository map](#repository-map)
- [Limitations and roadmap](#limitations-and-roadmap)
- [Security scope](#security-scope)
- [License](#license)
- [Documentation](#documentation)

## Why NSAT

Security scanners often report isolated observations. A code issue, a reachable service, and a credential exposure may matter more together than separately. NSAT discovers project context, runs its implemented native scanners, optionally validates a running application with bounded probes, checks developer-oversight patterns, correlates findings, and ranks risk.

The analysis should rely on evidence such as syntax and structural patterns, imports, framework/configuration clues, source and sink relationships, and network evidence. Names like `a()`, `x()`, `foo()`, `handler2()`, and `tmp()` may be unhelpful clues; names or comments alone do not establish that code is secure or vulnerable. Analyzer depth and rule coverage vary by language, so results require engineering review.

## How it works

```text
DISCOVER → SCAN → NORMALIZE → DEDUPLICATE → VALIDATE* → OVERSIGHT* → CORRELATE → RANK → EXPLAIN → REMEDIATE* → VERIFY*
```

`*` Optional or separately invoked stages. The core audit discovers project intelligence and a security surface, then runs SAST, secret, dependency, container, and host scanners. Findings use a canonical model and signature-based deduplication. Active validation requires a running target and explicit authorization; oversight can be enabled in an audit/report or invoked directly. Correlation and risk are built for unified reports and AI-assisted workflows. Remediation is a separate, user-reviewed workflow.

The product journey and implementation boundaries are described in [Architecture](ARCHITECTURE.md), [PRD](PRD.md), and [TRD](TRD.md).

## Supported languages and domains

Analyzer adapters are present for the primary MVP languages **C++, Python, Rust, Go, PHP, JavaScript, and TypeScript**. **Java** is also present as an existing compatibility analyzer. Detection and security rule coverage are not uniform and do not imply complete language support.

Implemented scan areas include structural source checks, secrets, dependencies, container configuration, host/project indicators, network bindings discovered from project evidence, and web validation against an explicitly supplied target. The `nsat host` and `nsat network` commands are placeholders in this checkout; they do not provide a general host or network inventory service. See [limitations](PRD.md#limitations) before relying on a result.

## AI and remediation

The AI layer is downstream of deterministic findings. The configured **GLM-5.3** provider supports explanations, report narratives, and security chat. The configured **Kimi K3** provider is used for remediation planning when enabled and available. Both use environment-driven, OpenAI-compatible request settings in the implementation; actual base URL and credentials must come from the operator. AI output is a proposal or narrative, not an authoritative finding.

For remediation, NSAT prepares a finding-specific proposal, previews the patch, creates a backup before applying an approved change, checks file integrity, applies the patch, runs available targeted syntax/tests, rescans, and records the outcome. Failure can trigger rollback. Rollback checks for newer edits and avoids overwriting user changes when a conflict is detected; `--force` exists and should only be used after reviewing the consequences.

## Reports

The main `nsat report` command produces terminal, JSON, or Markdown output and accepts `sarif` and `html` format values in the current CLI; those two formats are not fully implemented by the report manager yet. Markdown and JSON are the reliable file formats currently exposed by the implementation. The separate `python -m nsat.remediation_report` command generates a PDF human-readable remediation/change artifact from finding and proposal JSON, with optional snapshot metadata. It does not replace the audit engine.

## Local demo

The repository includes `demo-vuln-app/`, a local demonstration target. Its server binds to loopback on port 8000. After installing that demo’s own requirements and ensuring the NSAT CLI is available, run the server in one terminal:

```powershell
python -m pip install -r demo-vuln-app/requirements.txt
python demo-vuln-app/server.py
```

Then run an audit from the repository root in another terminal:

```powershell
nsat audit demo-vuln-app --oversight
nsat validate demo-vuln-app --target http://127.0.0.1:8000 --authorized
nsat report demo-vuln-app --format markdown --output audit-report.md --no-save
```

Only use active validation on this local demo or another target you are authorized to assess. This project has been described as a hackathon MVP in earlier repository material; this documentation makes no sponsorship, endorsement, selection, or award claim.

## Install and run

Requires Python 3.11 or newer. Create a virtual environment after cloning:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

This checkout has no root `pyproject.toml`, `setup.py`, or `requirements.txt`, so a supported installation command cannot currently be documented. The `nsat` CLI requires the package and its runtime dependencies. See [SETUP.md](SETUP.md) for the onboarding limitation and the command to run once the maintainer supplies a packaging manifest.

Run a local audit and report:

```powershell
nsat audit .
nsat report . --format markdown --output audit-report.md --no-save
```

For an application you own or are authorized to assess, run it locally, then explicitly authorize bounded validation:

```powershell
nsat validate . --target http://127.0.0.1:8000 --authorized
```

Full environment, AI, remediation, and troubleshooting steps are in [SETUP.md](SETUP.md). These commands reflect `nsat/cli/main.py`; consult `nsat --help` for the installed checkout’s exact options.

## CLI

| Command | Purpose |
| --- | --- |
| `nsat doctor` | Report Python, Git, analyzer, and optional-tool availability. |
| `nsat audit [PATH]` | Discover and scan a local project; optional active validation, oversight, AI, JSON, and Phase 1-only modes. |
| `nsat validate PATH --target URL --authorized` | Run the validation swarm against an authorized running application. |
| `nsat oversight [PATH]` | Run discovery/scanning and developer-oversight checks. |
| `nsat report [PATH]` | Build correlated risk context and render a report. |
| `nsat ai-report [PATH]` | Generate an AI-assisted executive report when configured. |
| `nsat explain [FINDING_ID] [PATH]` | Run a local analysis and explain a selected finding. |
| `nsat chat [PATH]` | Build local analysis context and ask security questions. |
| `nsat fix [FINDING_ID] [PATH]` | Preview or apply a remediation; also accepts rollback options. |
| `nsat verify [FINDING_ID] [PATH]` | Display remediation/verification history; `nsat fix` performs verification after applying a patch. |
| `nsat config` | Display configuration help/output. |
| `nsat host`, `nsat network`, `nsat monitor` | Registered placeholders; not implemented in this release. |

## Repository map

```text
nsat/                 CLI, core discovery, analyzers, scanners, and domain engines
  core/               Configuration, project discovery, orchestration, and surface models
  analyzers/           Language-specific structural adapters
  scanners/            SAST, secrets, dependencies, containers, host, and web checks
  normalization/       Canonical finding and evidence model
  swarm/               Optional bounded active-validation agents
  oversight/            Developer-oversight engine and rules
  correlation/          Relationships, attack paths, blast radius, and risk
  ai/                   GLM/Kimi adapters, context, explain, chat, and narrative reports
  remediation/           Proposal, patch, snapshot, rollback, and verification
  reporting/             Terminal, JSON, and Markdown audit reports
  remediation_report/    Standalone PDF remediation/change report
tests/                  Phase regression and PDF report tests
demo-vuln-app/           Local demonstration target
```

## Limitations and roadmap

Findings are bounded by current rules and analyzer depth; they are not proof that a project is secure. Some advertised CLI formats and registered commands are placeholders. AI providers require operator credentials and network access. Runtime validation is restricted to targets for which the operator has authorization. Future work should be identified explicitly in [Phases](Phases.md); cloud posture management, broader scanners, and additional integrations are not claimed as implemented here.

## Security scope

Use NSAT only on source trees, systems, and running applications you own or have explicit permission to assess. The active-validation authorization flag is an operator acknowledgement, not proof of legal authority. Review every proposed patch and PDF before sharing; reports may contain sensitive paths and security context. See [SECURITY.md](SECURITY.md).

## License

The repository previously identified itself as MIT-licensed but did not contain a license file. A standard MIT license is included; its copyright holder remains a placeholder pending maintainer confirmation.

## Documentation

- [PRD](PRD.md)
- [TRD](TRD.md)
- [Architecture](ARCHITECTURE.md)
- [Phases](Phases.md)
- [Setup](SETUP.md)
- [AI Instructions](AI_INSTRUCTION.md)
- [Agent Instructions](AGENTS.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
