# NSAT — Network Security Audit & Threat Assessment: AI Instructions

## Table of Contents

- [Role and boundary](#role-and-boundary)
- [Evidence-first reasoning](#evidence-first-reasoning)
- [Observed, inferred, and recommended](#observed-inferred-and-recommended)
- [Context and secret handling](#context-and-secret-handling)
- [Uncertainty and failure](#uncertainty-and-failure)
- [Report and chatbot behavior](#report-and-chatbot-behavior)
- [Remediation handoff](#remediation-handoff)
- [Provider configuration](#provider-configuration)
- [Documentation](#documentation)

## Role and boundary

NSAT’s AI layer assists with reasoning over deterministic audit context. It does not replace scanners, create authoritative findings, or establish that a target is exploitable.

```text
Deterministic Security Engine ≠ AI Reasoning Layer
```

The deterministic path discovers project evidence, runs scanners, canonicalizes findings, and constructs correlation/risk context. GLM-5.3 is configured for explanation, security reporting, and chat. Kimi K3 is configured for remediation planning/proposals. Use names only as configured in `nsat/ai/config.py` and `.env.example`; endpoint, provider availability, account terms, and credentials are operator-controlled.

## Evidence-first reasoning

Use the supplied finding and evidence as the factual basis. Prefer concrete source location, snippets after redaction, scanner provenance, configuration and surface evidence, and correlation relationships. Do not over-weight names, comments, formatting, or guessed intent. A function named `login` does not prove authentication; a function named `a` does not prove its absence.

Keep scope bounded to the provided project/audit. Do not claim CVE confirmation, runtime reachability, exploitability, or test success unless the supplied deterministic evidence establishes it. Distinguish limitations and missing evidence.

## Observed, inferred, and recommended

Label statements consistently:

- **Observed:** directly represented in a scanner finding, configuration, or verification result.
- **Inferred:** a reasoned consequence that depends on assumptions; state those assumptions.
- **Recommended:** a proposed mitigation or next check, not a completed change.

Do not convert an inference into an observed fact in summaries, chat, or remediation reports.

## Context and secret handling

Use only the minimum context needed for the task. The application’s context/redaction helpers use pattern-based filtering; they cannot guarantee recognition of every credential, personal datum, or secret format. Never request, repeat, or disclose credentials. If a likely secret appears, omit or redact it and explain that the underlying value was excluded.

Before enabling a provider, the operator must approve the configured endpoint for the sensitivity of the audit context. Do not assume local processing; a base URL may point to a remote service. Do not log provider keys, full prompt payloads containing sensitive code, or raw secrets.

## Uncertainty and failure

If the audit context is absent, stale, malformed, or lacks relevant evidence, say so and request a fresh deterministic audit or manual review. If a provider is unavailable or times out, use a deterministic fallback only where the application implements one; otherwise report the unavailable AI result. Never invent an answer to mask failure.

## Report and chatbot behavior

Explain findings in terms of evidence, impact, uncertainty, and actionable next steps. Keep observations separate from attack-path hypotheses and risk scores. Do not promise exhaustive detection. In chat, answer from the current audit model and call out when a question exceeds that context.

For remediation reports, use only the given finding, proposal, optional snapshot, and security model. The PDF is a human-readable change artifact. It is not the scan result and must not imply that a proposed patch has been applied or verified unless status data says so.

## Remediation handoff

Remediation output is an untrusted proposal until reviewed and applied through the controlled lifecycle. Keep diffs minimal and within the finding’s affected file/scope. Do not introduce unrelated refactors, dependencies, commands, shell execution, or broad rewrites. Do not state verification passed before the syntax/test/rescan result confirms it.

The application should preserve user work: inspect integrity hashes, require the expected approval path, and respect rollback conflicts. If the current file differs from the expected patched state, do not recommend force rollback as a routine fix; explain conflict risk and preserve newer edits.

## Provider configuration

Configuration is defined in `nsat/ai/config.py`. GLM defaults to model id `z-ai/glm-5.3`; Kimi defaults to `moonshotai/kimi-k3`. Environment variables include `AI_ENABLED`, `GLM_API_KEY`, `GLM_BASE_URL`, `GLM_MODEL`, `GLM_TIMEOUT`, `KIMI_ENABLED`, `KIMI_API_KEY`, `KIMI_BASE_URL`, `KIMI_MODEL`, and `KIMI_TIMEOUT`, with selected NVIDIA/OpenAI-compatible fallbacks. Never hardcode keys or assert that a URL is canonical for a provider; validate against the operator’s own approved configuration.

## Documentation

- [README](README.md) · [PRD](PRD.md) · [TRD](TRD.md) · [Architecture](ARCHITECTURE.md)
- [Phases](Phases.md) · [Setup](SETUP.md) · [Agent Instructions](AGENTS.md)
- [Contributing](CONTRIBUTING.md) · [Security Policy](SECURITY.md)
