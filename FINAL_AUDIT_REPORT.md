# NSAT Phase 4D Final Audit Report

**Audit date:** 2026-10-05  
**Workspace:** `D:\\network-agent`  
**Disposition:** **NOT DEMO READY**

## Executive Summary

The deterministic audit, local active-validation swarm, oversight, correlation/risk reporting, AI fallbacks, remediation safeguards, and separate PDF renderer all have substantial passing regression coverage. A loopback end-to-end audit completed, and invalid remediation identifiers now return a failing CLI status after a small Phase 4D fix.

The repository is not safe to present or push yet. A prior Git commit contains non-placeholder GLM, Kimi, and NVIDIA API key entries in `.env`. A concurrent workspace commit removed `.env` from current `HEAD`; the ignored local copy remains. That does not remove credentials from existing Git history. Rotate the exposed credentials and arrange history cleanup before distribution. A deterministic command-injection remediation preview also produced a potentially behavior-breaking patch (`[cmd]` as a single executable token); it was not applied.

## Test Results

| Run | Result |
| --- | --- |
| Baseline `python -m pytest -v` | 170 passed, 0 failed, 0 skipped; 4 Starlette deprecation warnings; 425.47s |
| Final `pytest -v` after CLI fix | 171 passed, 0 failed, 0 skipped; 4 Starlette deprecation warnings; 386.05s |

An intervening full run reported 170 passed and one failure because `SETUP.md` was temporarily absent while shared documentation was changing. After the file reappeared, its focused regression test passed, and the final full run passed. The test inventory grew from 170 to 171 during the shared-workspace run.

## End-to-End Workflow

The demo server was started on loopback and stopped after each run. This authorized command completed with `AI_ENABLED=false`:

```powershell
nsat audit demo-vuln-app --active --oversight --target http://127.0.0.1:8000 --authorized --ai --json-out
```

The final run discovered 9 files across Python, Java, JavaScript/TypeScript, and C++; emitted 43 raw findings; ran 10 validation agents and upgraded 3 findings; produced 13 oversight findings, 56 correlated/risk findings, 2 attack paths, and a risk score of 100. The deterministic audit and AI reports generated successfully. A valid remediation dry-run loaded the persisted audit context and produced a proposal without modifying the demo source.

Repeated audits did not produce identical finding totals: an earlier run emitted 41 raw and 54 correlated findings, versus 43 and 56 in the final run. Host exposure findings depend on the machine's currently listening sockets, so this workflow is not fully reproducible across runs or machines.

## Feature Verification: Phase 1–4C

- **Discovery and analyzers:** `nsat doctor` found Python, C++, Rust, Go, PHP, JavaScript/TypeScript, and Java analyzers. Regression tests passed for Python, C++, Java, JS/TS, mixed repositories, meaningless identifiers, malformed Python, and trivial-project filtering. Rust/Go/PHP analyzer availability was confirmed; the checked-in fixture suite has less direct coverage for these three.
- **Scanning and normalization:** SAST, secrets, dependencies, container, host, canonical normalization, deduplication, severity sorting, and secret-evidence redaction tests passed.
- **Active validation:** Scope enforcement, bounded-agent behavior, evidence, finding upgrades, failure isolation, and each implemented agent family passed tests. The local demo run executed 10 agents.
- **Oversight:** URL/log leakage, stack traces, hidden endpoints, cookies, source maps, redirects, CORS, timeouts, TOCTOU, deduplication, and malformed-source tests passed.
- **Correlation and risk:** Related findings, attack paths, risk scores, blast radius, location handling, deterministic scoring, and report structure tests passed. Dynamic host-socket findings affect repeated-run stability.
- **Verification and rollback:** Patch application, stale-hash rejection, failed-test rollback, rollback-conflict handling, scope/path validation, and audit-context ID/redaction tests passed. No patch was applied to the checked-in vulnerable demo.

## AI Verification

- **GLM:** The deterministic six-section AI report completed with AI disabled. Provider success, timeout/failure fallback, context limiting, and redaction are covered by tests. A live GLM response was not deliberately requested by the Phase 4D smoke commands.
- **Kimi:** Configuration, missing-key, timeout, and remediation-context redaction tests passed. No live Kimi remediation request was deliberately made.
- The ignored local `.env` has populated, non-placeholder API key entries. Existing suite tests invoke AI-enabled CLI commands, so those tests may have attempted calls using local credentials. Provider usage cannot be established from the local test output; keep `AI_ENABLED=false` for future local test runs until the exposed keys are rotated.

## Remediation Verification

Snapshot creation, approval/apply flow, test/re-scan verification, automatic rollback, rollback conflicts, and hash/path checks passed in the suite. The CLI dry-run for `NSAT-CMD-001` returned a proposal, but its replacement treats the full command string as `[cmd]`, which can break commands containing arguments. Do not approve that proposal without improving or replacing it. Invalid finding and rollback IDs now produce CLI exit code 1; both error paths were checked directly.

## PDF Layer Compatibility

The PDF remediation-report package is present as a separate `python -m nsat.remediation_report` CLI; it is not registered as a command under root `nsat`. PDF byte/file rendering, XML escaping, deterministic fallback, storage path handling, and report CLI generation passed regression tests. `python -m nsat.remediation_report --list` completed and found no persisted remediation PDFs. The layer did not alter the root CLI or findings during this audit.

## Security Checks

- `.gitignore` contains `.env`; the local file remains present and ignored.
- `.env` contained non-placeholder GLM, Kimi, and NVIDIA key values when inspected and was tracked at the start of this audit. A concurrent commit removed it from current `HEAD`; its ignored local copy was not printed or deleted. **Rotate these credentials and remove them from repository history before any public presentation or push.**
- Secret scanner, correlation, AI-context, remediation-context, and PDF-context redaction tests passed. Placeholder examples in `.env.example` remain masked.
- Active validation was limited to `127.0.0.1` with the authorization flag; no external target was probed.
- `git diff --check` passed. Existing parallel edits and generated/previously dirty bytecode were preserved.

## Documentation Accuracy

The earlier README contained a nonexistent demo path, stale command syntax, unsupported `host`/`network` claims, a fabricated fixed-count transcript, and an automatic-remediation claim. Shared documentation changes appeared during this audit and now describe the current demo/CLI and the separate PDF layer; `SETUP.md`'s accuracy regression passed. Because README, setup, PRD/TRD, contributing, and architecture-related docs were changing concurrently, their complete final diff was preserved rather than rewritten in this audit.

At the start of the audit, `ARCHITECTURE.md`, `Phases.md`, `AI_INSTRUCTION.md`, and `AGENTS.md` were absent; shared changes later introduced several of these files. Confirm the final documentation links and synchronize the remaining product/technical claims with the actual CLI before publishing.

## Known Limitations

- Exposed API keys remain in Git history until the maintainer rotates them and cleans history.
- Deterministic command-injection remediation can break commands with arguments; the demo patch was not applied.
- Host-socket findings vary with the audit machine and cause run-to-run finding-count changes.
- Rust, Go, and PHP analyzers were discovered but have less direct fixture/regression coverage than other analyzers.
- AI provider behavior was tested through fallback/mock paths; no clean live-provider acceptance run was performed.
- PDF reports are generated by a separate CLI and none were persisted by this audit.
- `nsat host`, `nsat network`, and `nsat monitor` remain registered placeholders.

## Final Readiness

**NOT DEMO READY.** Deterministic scanning, authorized local validation, oversight, risk reporting, rollback, and PDF generation are demonstrable. Do not present or push this repository until the tracked credentials are rotated and historical exposure is addressed. Review and correct the command-injection remediation proposal before showing an apply-and-verify demo.

## Subsystem Status

| Subsystem | Status | Evidence |
| --- | --- | --- |
| Foundation | ✅ READY | CLI, discovery, configuration, language tests pass |
| Scanning | ✅ READY | Scanner, normalization, deduplication and redaction tests pass |
| Active validation | ✅ READY | Loopback run: 10 agents executed, 3 upgrades |
| Oversight | ✅ READY | Loopback run: 13 findings; regression checks pass |
| Correlation / risk | ⚠ NEEDS ATTENTION | 2 attack paths; host-dependent count variation |
| GLM AI | ⚠ NEEDS ATTENTION | Deterministic report/fallback pass; live status unverified; key exposed |
| Kimi remediation | ⚠ NEEDS ATTENTION | Safety suite passes; live status unverified; command proposal limitation |
| Verification / rollback | ✅ READY | Patch, hash, test-failure and rollback tests pass |
| Reporting | ✅ READY | Markdown/JSON generation and report tests pass |
| PDF remediation report | ✅ READY | Separate CLI and PDF rendering tests pass |
| CLI / demo | ❌ BLOCKED | Credential history exposure blocks safe presentation |

## Phase 4D Maintainer Summary

```text
Tests: 171 passed / 0 failed / 0 skipped (4 warnings)
End-to-End Audit: PASS
Active Validation: PASS
Developer Oversight: PASS
Correlation + Risk: PASS WITH REPRODUCIBILITY LIMIT
GLM AI: DEGRADED (deterministic fallback; live provider not verified)
Kimi Remediation: DEGRADED (proposal limitation; live provider not verified)
Backup / Rollback: PASS
Verification: PASS
PDF Layer Compatibility: PASS (separate CLI)
CLI: PASS WITH PLACEHOLDERS
Secret Hygiene: FAIL
Documentation: NEEDS ATTENTION (shared docs were changing concurrently)
Final Status: NOT DEMO READY
```

### Files Changed by This Audit

- `nsat/cli/main.py` — invalid finding/rollback IDs now return a non-zero CLI exit status.
- A concurrent commit removed `.env` from current `HEAD`; this audit found that the earlier history still contains non-placeholder provider keys. The ignored local copy remains intact. Rotation/history cleanup is still required.
- `README.md` and other documentation files were concurrently rewritten in the shared checkout and preserved; their full rewrite is not attributed to this audit.
- `FINAL_AUDIT_REPORT.md` — this report.

### Exact Demo and CLI Commands Exercised

```text
nsat --help
nsat --version
nsat doctor
nsat audit demo-vuln-app --active --oversight --target http://127.0.0.1:8000 --authorized --ai --json-out (AI_ENABLED=false)
nsat report demo-vuln-app --format markdown --output <temporary-file> --no-save
nsat ai-report demo-vuln-app --oversight --output <temporary-file> (AI_ENABLED=false)
nsat fix NSAT-CMD-001 demo-vuln-app --dry-run --no-ai (AI_ENABLED=false)
nsat fix NSAT-NOT-A-REAL-ID demo-vuln-app --dry-run --no-ai (exit 1)
nsat fix --rollback NSAT-NOT-A-REAL-REMEDIATION demo-vuln-app --no-ai (exit 1)
python -m nsat.remediation_report --list
```

### Recommendation

NSAT's current MVP demonstrates deterministic defensive scanning and authorized loopback validation, but it is **not safe to present as-is** while real-looking provider credentials remain in Git history and the command-injection fix preview is not trustworthy for general commands.
