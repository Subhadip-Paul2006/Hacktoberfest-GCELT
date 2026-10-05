# Contributing to NSAT

Welcome, and thank you for your interest in **NSAT — Network Security Audit & Threat Assessment**! NSAT is an open-source, CLI-first, multi-layer defensive security auditing platform. This guide explains how to contribute safely and effectively.

## Table of Contents

- [Welcome](#welcome)
- [Project Philosophy](#project-philosophy)
- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Setting Up the Development Environment](#setting-up-the-development-environment)
- [Repository Structure](#repository-structure)
- [Creating a New Language Analyzer](#creating-a-new-language-analyzer)
- [Creating a New Security Rule](#creating-a-new-security-rule)
- [Creating a Scanner Adapter](#creating-a-scanner-adapter)
- [Adding Tests](#adding-tests)
- [Documentation Contributions](#documentation-contributions)
- [AI / Model Integration Contributions](#ai--model-integration-contributions)
- [Security-Sensitive Contributions](#security-sensitive-contributions)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Issue Guidelines](#issue-guidelines)
- [Review Process](#review-process)
- [What Maintainers Look For](#what-maintainers-look-for)
- [Good First Contributions](#good-first-contributions)
- [Documentation](#documentation)

## Welcome

NSAT is built to be extended. Analyzers, scanners, oversight rules, correlation rules, report formats, and AI providers are all interface-driven, so a contribution can usually be added in one module without touching the rest of the pipeline. Newcomers are welcome — documentation, tests, and small rules are great places to start.

## Project Philosophy

Read these before contributing; they shape every review decision:

1. **Working end-to-end beats partially-built breadth.** A small, robust, tested feature is worth more than a large unfinished one.
2. **Deterministic first, AI second.** Every core capability must work with no network and no LLM. The AI layer only explains; it never produces authoritative findings.
3. **Never depend on naming conventions.** Detect syntax structures, calls, imports, configuration, and source→sink relationships — not variable/function/class names or comments.
4. **Graceful degradation.** If an optional external tool is missing, catch it, log a warning, mark the capability unavailable, and continue with native checks. Never throw unhandled tracebacks.
5. **Defensive safety boundaries.** No exploit generation, no denial-of-service floods, no high-volume brute force. Active probes are bounded, non-destructive, and authorization-gated.

See [AGENTS.md](AGENTS.md) for the full engineering constraints and module boundaries.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## Ways to Contribute

- Report or triage issues.
- Improve documentation and fix broken links.
- Add tests and test fixtures.
- Add a language analyzer, scanner adapter, security rule, or oversight rule.
- Add a report format or improve terminal UX.
- Add an AI provider adapter.
- Harden or extend the correlation, risk, and blast-radius engines.

## Setting Up the Development Environment

```bash
git clone https://github.com/your-org/network-agent.git
cd network-agent

python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -e .

nsat doctor                         # verify environment
pytest -v                           # run the full suite (131 tests)
```

Full setup details are in [SETUP.md](SETUP.md).

## Repository Structure

```text
nsat/
├── cli/            # Click commands & Rich UI
├── core/           # Discovery, orchestrator, surface, config, capability registry
├── analyzers/      # Language analyzers (base interface + per-language)
├── scanners/       # sast, secrets, dependencies, container, host, network, web
├── normalization/  # CanonicalFinding model
├── swarm/          # Active Validation Swarm (coordinator, planner, agents)
├── oversight/      # Developer Oversight engine (rules)
├── correlation/    # Graph, rules, risk, blast radius, location
├── ai/             # LLMProvider abstraction, provider, explainer, chatbot, reports
└── reporting/      # Terminal, JSON, Markdown exporters
```

Data flows in one direction: `CLI → core → analyzers/scanners → normalization → swarm/oversight → correlation → ai → reporting`. Do not introduce circular dependencies. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Creating a New Language Analyzer

1. Create `nsat/analyzers/<lang>_analyzer.py`.
2. Subclass `LanguageAnalyzer` from `nsat/analyzers/base.py` and implement the abstract members: `language_name`, `supported_extensions`, `detect(file_path, content)`, and the `extract_*` methods (`extract_structure`, `extract_frameworks`, `extract_entry_points`, `extract_network_operations`, `extract_database_components`, `extract_auth_indicators`, `extract_security_operations`).
3. Emit security-relevant operations as structured sinks (e.g. `SecurityRelevantOperation(operation_type=..., sink_category=...)`) — do **not** emit findings here; scanners consume the IR and emit `CanonicalFinding`s.
4. Register the analyzer in `nsat/analyzers/__init__.py:get_default_analyzers()`.
5. Add a fixture under `tests/fixtures/sample-<lang>/` and a test.

Target syntax constructs and sinks, not identifier names.

## Creating a New Security Rule

Static SAST patterns live in `nsat/scanners/sast/native_rules.py`. To add a rule:

1. Define the structural pattern (call expression, sink, interpolation) you want to flag.
2. Emit a `CanonicalFinding` with a sequential ID prefix (e.g. `NSAT-<RULE>-###`), a `category`, `severity`, `confidence`, evidence, impact, and recommendation.
3. Ensure the finding flows through normalization and correlation without special-casing.

Oversight rules live in `nsat/oversight/rules/`. Subclass the rule base, implement `audit(repo_path, intel, surface, existing_findings)`, register the rule in `nsat/oversight/engine.py`, and keep detection static and non-crashing (rule errors must be contained).

## Creating a Scanner Adapter

1. Create a module under `nsat/scanners/<domain>/scanner.py`.
2. Subclass `BaseScanner` from `nsat/scanners/base.py` and implement `scanner_name` and `scan(target_path, surface) -> list[CanonicalFinding]`.
3. For external tools, probe availability via `shutil.which` / the capability registry, and fall back to native behavior when absent. Never block startup on an external binary.
4. Wire the scanner into `Phase2Orchestrator.run()` in `nsat/core/orchestrator.py` if it should run in the default pipeline.

## Adding Tests

- Tests live in `tests/` and are grouped by phase (`test_phase1.py` … `test_phase4b.py`).
- Fixtures live in `tests/fixtures/`.
- Prefer integration tests that exercise the real pipeline over trivial getter tests.
- Run `pytest -v` before and after your change; all tests must pass.

## Documentation Contributions

- Every major doc has a Table of Contents with working anchor links and a bottom **Documentation** cross-link section. Keep both intact when editing.
- Use relative Markdown links and verify targets exist.
- Label anything not yet implemented as **Planned**, **Roadmap**, **Future Work**, or **Experimental**. Do not present planned features as completed.
- Keep terminology consistent (see the consistency checklist in [AGENTS.md](AGENTS.md)).

## AI / Model Integration Contributions

- Implement the `LLMProvider` interface (`nsat/ai/provider.py`): `provider_name`, `generate(...)`, `chat(...)`, `health_check()`.
- All AI features must degrade gracefully to deterministic output when no provider is configured.
- Apply secret redaction (see `nsat/ai/context_builder.py`) to anything sent to a model.
- Never let the AI layer fabricate findings, line numbers, ports, or CVEs. See [AI_INSTRUCTION.md](AI_INSTRUCTION.md).

## Security-Sensitive Contributions

- Keep active probes bounded, non-destructive, and behind the authorization gate (`TargetScope` / `--authorized`).
- Do not add exploit generation, DoS/flood capabilities, or high-volume brute force.
- Redact secrets in evidence, reports, logs, and AI context.
- If your change affects the authorization model or could leak discovered secrets, call it out explicitly in the PR and read [SECURITY.md](SECURITY.md).

## Commit Guidelines

- Write clear, imperative commit messages ("Add PHP command-injection sink detection").
- Keep commits focused; avoid mixing unrelated changes.
- Reference an issue where applicable.
- Do not commit secrets, `.env`, or generated reports (see `.gitignore`).

## Pull Request Guidelines

- Open the PR against `main` with a descriptive title and a summary of *what* and *why*.
- Note any behavior change, new dependency, or security implication.
- Ensure `pytest -v` passes and documentation stays accurate and cross-linked.
- Update `Phases.md`/`README.md` status tables if you change what is implemented vs. planned.
- Small, reviewable PRs are preferred over large ones.

## Issue Guidelines

- Use the [bug report](.github/ISSUE_TEMPLATE/bug_report.md) and [feature request](.github/ISSUE_TEMPLATE/feature_request.md) templates.
- For security vulnerabilities, do **not** open a public issue — follow [SECURITY.md](SECURITY.md).
- Include version, OS, the command run, and relevant output.

## Review Process

1. A maintainer reviews for correctness, safety boundaries, philosophy fit, and test coverage.
2. You may be asked for changes; discussion happens on the PR.
3. Once approved and passing tests, a maintainer merges.

## What Maintainers Look For

- Correctness and evidence-based behavior (no name-based heuristics, no fabricated findings).
- Defensive safety boundaries respected.
- Deterministic-first design and graceful degradation.
- Tests and accurate, cross-linked documentation.
- Minimal, focused changes that avoid overengineering.

## Good First Contributions

- Fix a broken link or typo in the docs.
- Add a test fixture and a matching test.
- Add a new oversight rule or SAST pattern.
- Add a scanner adapter for an optional external tool (with native fallback).
- Improve terminal report formatting or CLI help text.

## Documentation

- [README](README.md)
- [PRD](PRD.md)
- [TRD](TRD.md)
- [Architecture](ARCHITECTURE.md)
- [Setup](SETUP.md)
- [Phases](Phases.md)
- [AI Instructions](AI_INSTRUCTION.md)
- [Agent Instructions](AGENTS.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
