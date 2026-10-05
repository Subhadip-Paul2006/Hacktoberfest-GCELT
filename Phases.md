# NSAT — Network Security Audit & Threat Assessment: Phases

## Table of Contents

- [Completed](#completed)
- [Current](#current)
- [Future](#future)
- [Documentation](#documentation)

This is a repository-oriented status summary. Phase names describe implementation history; they are not a guarantee that every capability in early planning drafts shipped. Source code and phase tests are the authority.

## Completed

| Phase | Scope | Evidence in this checkout |
| --- | --- | --- |
| Phase 1 — Foundation + Project Intelligence | CLI foundation, project discovery/classification, language and surface models | `nsat/core/`, `nsat/analyzers/`, `tests/test_phase1.py` |
| Phase 2 — Deterministic Security Scanning | Native source, secrets, dependencies, container and host/project checks; canonical findings | `nsat/scanners/`, `nsat/normalization/`, `tests/test_phase2.py` |
| Phase 3 — Active Validation Swarm | Optional validation agents and bounded target checks | `nsat/swarm/`, `nsat/scanners/web/`, `tests/test_phase3.py` |
| Phase 3.5 — Developer Oversight | Design/deployment and hidden oversight checks | `nsat/oversight/`, `tests/test_phase3_5.py` |
| Phase 4A — Correlation + Risk + Reporting | Correlation model, attack paths/risk context, audit renderers | `nsat/correlation/`, `nsat/reporting/`, `tests/test_phase4.py` |
| Phase 4B — GLM AI | GLM-assisted analysis/report/explanation/chat components | `nsat/ai/`, `tests/test_phase4b.py` |
| Phase 4C — Kimi Remediation + Backup + Rollback + Verification | Proposal, patch, snapshots/hash checks, rollback and targeted verification | `nsat/remediation/`, `tests/test_phase4c.py` |
| PDF Remediation Reporting | Additive human-readable PDF artifact from existing finding/proposal/optional snapshot models | `nsat/remediation_report/`, `tests/test_remediation_report.py` |

The existence of a test module documents a validation area, not broad coverage or a clean test run for all environments.

## Current

### Phase 4D — Final audit / regression / demo readiness

The repository has a `tests/test_phase4c.py` regression suite and a demo target at `demo-vuln-app/`. Treat full regression, clean installation, command-format coverage, and demo readiness as **not verified by this documentation pass**. Do not call Phase 4D complete unless a reproducible verification run and its results are recorded by maintainers.

### Documentation and packaging readiness

Documentation is being aligned to the current implementation. This checkout has no root `pyproject.toml`, `setup.py`, or dependency requirements file in tracked source, so installation from a clean clone is not currently reproducible from the repository alone. That is a repository readiness gap.

## Future

Candidate work, subject to maintainer planning:

- Add and maintain reproducible package/dependency metadata.
- Implement or remove the placeholder `host`, `network`, and `monitor` commands.
- Implement SARIF and HTML renderers before advertising those output formats.
- Expand cross-language security rule depth and tests.
- Improve setup, release, and contributor automation.

Cloud posture, IDE integrations, external scanner integrations, and broader runtime monitoring are not presented as shipped features. Reclassify any item only after the source implementation supports it.

## Documentation

- [README](README.md) · [PRD](PRD.md) · [TRD](TRD.md) · [Architecture](ARCHITECTURE.md)
- [Setup](SETUP.md) · [AI Instructions](AI_INSTRUCTION.md) · [Agent Instructions](AGENTS.md)
- [Contributing](CONTRIBUTING.md) · [Security Policy](SECURITY.md)
