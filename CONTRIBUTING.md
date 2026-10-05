# Contributing to NSAT — Network Security Audit & Threat Assessment

## Table of Contents

- [Welcome](#welcome)
- [Project philosophy](#project-philosophy)
- [Development setup](#development-setup)
- [Repository structure](#repository-structure)
- [Add a language analyzer](#add-a-language-analyzer)
- [Add a security rule or scanner](#add-a-security-rule-or-scanner)
- [Add AI providers or report formats](#add-ai-providers-or-report-formats)
- [Tests and documentation](#tests-and-documentation)
- [Security-sensitive contributions](#security-sensitive-contributions)
- [Commits, issues, and pull requests](#commits-issues-and-pull-requests)
- [Review and good first contributions](#review-and-good-first-contributions)
- [Documentation](#documentation)

## Welcome

Contributions that improve accurate, explainable, defensive security engineering are welcome. Before starting, read the [README](README.md), [architecture](ARCHITECTURE.md), and [setup guide](SETUP.md). The repository currently lacks root package/dependency metadata; coordinate with maintainers for the supported development environment rather than inventing a dependency install recipe.

## Project philosophy

- Keep deterministic evidence as the source of truth; AI explanations and patches are suggestions.
- Make boundaries and coverage limits clear.
- Prefer focused, reviewable changes over broad refactors.
- Preserve the target user’s files and local work.
- Require authorization and bounded behavior for active checks.
- Avoid claims that findings are exhaustive or false-positive-free.

## Development setup

Use Python 3.11+, a virtual environment, and the maintainer-provided dependencies. Test files are organized by phase under `tests/`. Do not modify or run broad destructive operations on a target repository. To identify relevant tests, inspect filenames such as `tests/test_phase2.py` or `tests/test_phase4c.py`; run commands only when the environment has the required dependencies.

## Repository structure

| Path | Responsibility |
| --- | --- |
| `nsat/cli/` | Click CLI and presentation helpers |
| `nsat/core/` | Config, discovery, project intelligence, surfaces, orchestration |
| `nsat/analyzers/` | Language analyzer interface and adapters |
| `nsat/scanners/` | Native source, secret, dependency, container, host, network, web modules |
| `nsat/normalization/` | Canonical finding/evidence model |
| `nsat/swarm/` | Active validation planner, coordinator, agents |
| `nsat/oversight/` | Oversight engine and rules |
| `nsat/correlation/` | Relationships, attack paths, risk, blast radius |
| `nsat/ai/` | Providers, context construction, explain/chat/report generation |
| `nsat/remediation/` | Plans, patches, snapshots, rollback, verification |
| `nsat/reporting/` | Main audit report exporters |
| `nsat/remediation_report/` | Separate PDF remediation/change report |
| `tests/` | Phase regression suites and fixtures |

## Add a language analyzer

1. Read `nsat/analyzers/base.py` and at least one adjacent-language implementation.
2. Add an adapter following the interface for extensions, detection, and structural/security evidence extraction.
3. Register it in `nsat/analyzers/__init__.py` and align enabled-language configuration if needed.
4. Add representative safe/unsafe fixtures and focused tests, including malformed input and generic identifiers.
5. State what is parsed, what is heuristic, and which rule coverage is not present.

Do not claim full AST/taint support based on a detector or lightweight structural extraction.

## Add a security rule or scanner

Return `CanonicalFinding` objects with source scanner and evidence. Follow an existing scanner/rule convention and wire a new Phase 2 scanner deliberately in `nsat/core/orchestrator.py`; a file existing under `nsat/scanners/` does not automatically enter the primary scan. Deduplicate deterministically where appropriate. Scanner failures should be bounded, understandable, and must not silently imply that analysis completed successfully.

For active validation, use the existing `TargetScope`, bounded request client, redaction, and authorization flow. Never add destructive probes, credential attacks, uncontrolled concurrency, or a route to scan arbitrary targets without explicit scope.

## Add AI providers or report formats

Implement provider behavior via `nsat/ai/provider.py` (`LLMProvider`) and follow the current GLM/Kimi configuration patterns. Keep prompts evidence-bound, minimize context, redact secrets, report uncertainty, and handle timeout/unavailable cases. Never treat model output as a finding without deterministic evidence.

For a report format, add a real renderer/exporter, CLI behavior, tests, and documentation together. Do not list SARIF/HTML as supported until generated artifacts have the promised format and are validated.

## Tests and documentation

Add focused tests for new behavior and regression cases; follow phase test conventions. Include negative cases, failure paths, safety boundaries, and preservation of unrelated user changes where relevant. Do not put live secrets or network targets in fixtures.

Update the appropriate product/technical/setup/architecture docs when behavior changes. Verify links, commands, module names, models, and supported languages against the implementation. Mark planned behavior as planned. Documentation must not claim a capability based only on an old PRD.

## Security-sensitive contributions

Do not include credentials, real customer code, private endpoints, or exploit payloads in commits/issues. Follow [SECURITY.md](SECURITY.md) for private vulnerability reports. Remediation changes must preserve backup/hash checks and avoid overwriting concurrent user edits. Review outbound AI context and report redaction behavior; regex redaction is not a guarantee that every secret is detected.

## Commits, issues, and pull requests

- Use concise commit subjects describing the change; avoid claiming a phase is complete without evidence.
- For issues, include NSAT version/commit, OS/Python version, sanitized command and output, expected behavior, and a minimal reproduction. Remove paths/secrets first.
- For pull requests, describe motivation, scope, implementation, tests actually run, limitations, and documentation changes. Link relevant issues where available.
- Keep unrelated formatting, generated bytecode, reports, and local state out of a change.

## Review and good first contributions

Reviewers should check evidence quality, safety boundaries, model/source agreement, error handling, tests, and docs. Promising focused contributions include documenting analyzer coverage, adding a test for a current rule, clarifying setup once a dependency manifest is available, or implementing an advertised-but-missing report format with tests.

## Documentation

- [README](README.md) · [PRD](PRD.md) · [TRD](TRD.md) · [Architecture](ARCHITECTURE.md)
- [Phases](Phases.md) · [Setup](SETUP.md) · [AI Instructions](AI_INSTRUCTION.md)
- [Agent Instructions](AGENTS.md) · [Security Policy](SECURITY.md)
