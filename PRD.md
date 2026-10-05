# NSAT — Network Security Audit & Threat Assessment

## Table of Contents

- [Executive summary](#executive-summary)
- [Problem statement](#problem-statement)
- [Users and use cases](#users-and-use-cases)
- [Vision and principles](#vision-and-principles)
- [User journey](#user-journey)
- [Functional requirements](#functional-requirements)
- [Security requirements](#security-requirements)
- [Languages and security domains](#languages-and-security-domains)
- [Chatbot](#chatbot)
- [AI and remediation](#ai-and-remediation)
- [MVP, non-goals, and limitations](#mvp-non-goals-and-limitations)
- [Roadmap and success criteria](#roadmap-and-success-criteria)
- [Documentation](#documentation)

## Executive summary

NSAT is a CLI-first, multi-layer defensive cybersecurity platform for security auditing, validation, correlation, AI-assisted reasoning, controlled remediation, and verification. It helps a developer or security engineer move from project discovery and deterministic checks to evidence review, risk context, an optional AI explanation, and a controlled remediation cycle.

The implementation is Python-based. It combines project intelligence, language adapters, native scanners, optional active-validation agents, developer-oversight rules, correlation and risk models, AI provider adapters, remediation safeguards, and audit/PDF reporting. The code in `nsat/` is authoritative; capabilities below describe this checkout, not a guarantee of complete security coverage.

## Problem statement

Repository security tools commonly surface separate source, dependency, secret, and configuration observations. A developer must determine which observations matter, whether runtime evidence supports them, and what change is safe. This is harder in unfamiliar, mixed-language, generated, or poorly named repositories. An AI-only approach adds a separate risk: plausible-sounding claims can lack evidence.

NSAT addresses that workflow by keeping deterministic discovery/scanning/correlation as the factual basis, attaching provenance and evidence to findings, and using AI only for bounded reasoning tasks. Remediation is presented for review, backed up, and checked after application.

## Users and use cases

| Persona | Need | NSAT use |
| --- | --- | --- |
| Application developer | Understand and fix a local code/config issue | Audit, inspect finding evidence, preview a fix, verify it. |
| AppSec/DevSecOps engineer | Review multiple risk domains together | Produce a correlated report and optionally validate an authorized test service. |
| Maintainer/contributor | Extend analyzers or rules safely | Follow module conventions, add focused tests, document limits. |
| Reviewer/lead | Understand a proposed security change | Review the remediation PDF/change artifact and its verification/backup context. |

Typical use cases are local repository triage; limited validation of a running service with permission; developer oversight checks; deterministic reporting; evidence-grounded explanation/chat; and a human-approved, reversible remediation attempt.

## Vision and principles

The product goal is to make a security audit more actionable by connecting project context, findings, risk, and verification in one CLI workflow.

- **Evidence first:** observed scanner evidence is distinct from inference and recommendation.
- **Deterministic foundation:** AI does not create the canonical security facts or replace scanners.
- **Structural context:** use AST/structure, imports, framework/configuration evidence, network surface, and observed source/sink relationships where available. Names such as `a()`, `x()`, `foo()`, `handler2()`, and `tmp()` are not sufficient evidence by themselves.
- **Defensive scope:** active checks target only systems the operator is authorized to assess.
- **Preserve user work:** a patch is reviewed, guarded by snapshots/hash checks, and rollback must not overwrite newer user edits on conflict.
- **Honest coverage:** language and rule coverage vary; missing findings do not prove absence of vulnerabilities.

## User journey

```text
DISCOVER → SCAN → NORMALIZE → DEDUPLICATE → VALIDATE (optional) → OVERSIGHT (optional)
   → CORRELATE → RANK → EXPLAIN → REMEDIATE (review/approval) → VERIFY
```

Discovery inventories project structure and language/framework evidence. Native scanners produce findings, which are normalized and deduplicated. A separately opted-in validation swarm can make bounded requests to an authorized running target. Oversight checks add design/deployment observations. Correlation assembles relationships, attack paths, blast-radius context, and risk. An explanation/report can then be generated. Remediation stages are user-controlled; verification checks syntax, targeted tests where available, and a relevant rescan, with rollback handling on failure.

## Functional requirements

These requirements describe shipped behavior and known boundaries.

| Area | Requirement / current behavior |
| --- | --- |
| Project intelligence | Discover project files and infer languages, frameworks, entry points, network/database/auth and security-operation evidence using `nsat/core/`. |
| Language analyzers | Provide adapters for C++, Python, Rust, Go, PHP, JavaScript/TypeScript, and Java. Findings/rule coverage vary. |
| Static scanning | Run native SAST, secret, dependency, container, and host scanners through `Phase2Orchestrator`. Scanner errors are logged and the remaining scan continues. |
| Canonical findings | Represent findings with the `CanonicalFinding` model, evidence and a deterministic signature used for deduplication. |
| Active validation | Run swarm agents through `nsat validate` or `audit --active --target`; scope validation checks the explicit authorization acknowledgement. Do not interpret it as legal authorization. |
| Developer oversight | Run implemented oversight rules through `nsat oversight` or the audit/report option. |
| Correlation | Build relationships, attack paths, blast-radius and risk context for unified reports and downstream AI/remediation. Do not claim arbitrary graph discovery beyond implemented rules. |
| AI reasoning | GLM-5.3 adapter supports report/explanation/chat tasks; AI can be disabled or unavailable. Deterministic evidence remains the source of truth. |
| Remediation | Plan a finding-scoped patch, support dry run and approval, snapshot/hash protection, patch application, targeted test/rescan, and rollback outcomes. Verification runs as part of `fix`; `verify` displays recorded history. |
| Reporting | Main CLI provides terminal/JSON/Markdown flows. `sarif` and `html` are accepted choices but are not rendered as those formats by the current report manager. A separate PDF remediation report is generated from finding/proposal JSON. |
| Configuration | Core project config is YAML, loaded from an explicit path, target `nsat.yaml`/`nsat.yml` (also probes `nsat.toml` but parses YAML), cwd YAML, or `~/.nsat/config.yaml`. AI provider credentials use environment variables / `.env`. |
| CLI placeholders | `host`, `network`, and `monitor` are registered but not implemented in this release. |

### CLI use cases

```console
nsat doctor
nsat audit PATH
nsat audit PATH --active --target http://127.0.0.1:8000 --authorized --oversight
nsat validate PATH --target http://127.0.0.1:8000 --authorized
nsat report PATH --format markdown --output audit.md --no-save
nsat ai-report PATH --output executive.md
nsat explain FINDING_ID PATH --no-ai
nsat chat PATH --ask "Summarize the highest priority evidence"
nsat fix FINDING_ID PATH --dry-run
nsat verify FINDING_ID PATH
```

See the CLI help and [SETUP](SETUP.md) for option details.

## Security requirements

- Require explicit operator acknowledgement and a supplied target for active validation; explain that the flag is not proof of authorization.
- Keep local static analysis useful when AI providers are disabled or unreachable.
- Redact recognizable secret patterns from contexts/reports and minimize outbound provider context; disclose that pattern-based redaction is incomplete.
- Restrict remediation to the finding’s affected path and preserve backups/hash checks.
- On rollback conflict, preserve newer user edits unless the operator explicitly overrides the guard.
- Do not claim that a clean scan means a secure project; disclose partial scanner failures and coverage limitations.

## Chatbot

`nsat chat PATH` builds an analysis model for the target and accepts either a one-shot `--ask` question or an interactive session. It may use GLM-5.3 when configured and has deterministic fallback behavior in its implementation. Responses should be bounded by supplied evidence, separate observed facts from inference, and make missing context clear. Chat does not create authoritative findings or apply remediation.

## Languages and security domains

Primary MVP analyzer set: C++, Python, Rust, Go, PHP, JavaScript, and TypeScript. Java is retained as additional compatibility support. An adapter being present does not mean equal parser depth, rule count, or validation coverage.

Implemented modules cover source-pattern checks, secrets, dependency manifests, container configuration, host/project indicators, network binding evidence, web probes, active validation, and developer oversight. Cloud posture management, general-purpose Nmap scanning, broad malware detection, and comprehensive runtime monitoring are not product requirements for the current implementation.

## AI and remediation

The system has two bounded responsibilities:

```text
Security Reasoning Model (GLM-5.3)
  → explain findings, support security chat, produce report narrative

Remediation Model (Kimi K3)
  → help analyze the root cause and draft a finding-specific proposal
```

Actual provider base URLs, API keys, and model overrides are read from environment settings; `.env.example` shows repository defaults. Do not assume a model is available merely because a default model name exists. Provider/model failure must not convert an AI inference into a deterministic finding. See [AI_INSTRUCTION.md](AI_INSTRUCTION.md).

Remediation should preserve the affected project’s work. The normal flow is context → proposal → dry-run review → snapshot/backup → hash precondition → approval → apply → available syntax/targeted-test checks → rescan → outcome. On failure, rollback can restore the backup only when integrity checks allow. A rollback conflict means newer user changes are preserved. `--force` is an exceptional override requiring review.

## MVP, non-goals, and limitations

### MVP in this checkout

- CLI project discovery and multi-domain native scanning.
- Seven primary MVP language adapters, plus Java compatibility support.
- Optional bounded web validation, oversight, correlation/risk context, and reports.
- Optional GLM/Kimi provider integrations.
- Controlled patch proposal/application lifecycle and a separate PDF remediation report layer.

### Non-goals

- Unauthorized exploitation, destructive testing, brute force, denial of service, or stealth activity.
- Guaranteeing that a repository is secure or finding every vulnerability.
- Replacing a human reviewer or a full specialist scanner suite.
- Cloud CSPM, IDE integrations, complete data-flow analysis across every language, or runtime endpoint monitoring unless and until implemented.

### Limitations

Analyzer and rule coverage varies. Active probes are limited and must be authorized. AI depends on configured endpoints and may fail. The main report’s SARIF/HTML choices are not reliable exporters yet. Host/network/monitor CLI commands are placeholders. Root packaging/dependency manifests are not present in this checkout, which limits reproducible onboarding. See [Phases](Phases.md) for status distinctions.

## Roadmap and success criteria

Future work should be based on implementation and maintainer priorities, not implied by docs: packaging/onboarding, deeper language-specific analysis, report format completion, broader test coverage, and carefully scoped integrations are candidate areas, not shipped features.

Success means a new contributor can set up the project from declared dependencies, run a local audit, understand finding provenance and limits, inspect an approved remediation proposal, and verify whether the change resolved its target without losing newer work. Each language/rule addition should have focused tests and documented coverage.

## Documentation

- [README](README.md) · [TRD](TRD.md) · [Architecture](ARCHITECTURE.md) · [Phases](Phases.md)
- [Setup](SETUP.md) · [AI Instructions](AI_INSTRUCTION.md) · [Agent Instructions](AGENTS.md)
- [Contributing](CONTRIBUTING.md) · [Security Policy](SECURITY.md)
