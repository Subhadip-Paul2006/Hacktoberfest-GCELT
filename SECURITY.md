# NSAT — Network Security Audit & Threat Assessment: Security Policy

## Table of Contents

- [Policy](#policy)
- [Responsible disclosure](#responsible-disclosure)
- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Information to include](#information-to-include)
- [What not to publish](#what-not-to-publish)
- [Scope](#scope)
- [Response expectations](#response-expectations)
- [Documentation](#documentation)

## Policy

We appreciate reports that help protect NSAT users and contributors. This file documents the repository’s disclosure process; it is not a guarantee of a particular response time. No official security email or private reporting channel is configured in the repository at the time of writing.

## Responsible disclosure

Please give maintainers a reasonable opportunity to investigate and address an issue before public disclosure. Do not access, modify, or exfiltrate data that is not yours. Do not test against third-party systems without permission. Avoid denial of service, persistence, destructive changes, and privacy violations.

## Reporting a vulnerability

Use the repository host’s **private vulnerability reporting** feature if enabled. If unavailable, contact a repository maintainer through a verified private channel listed by the project owner. Do not post exploit details, credentials, or sensitive reproduction data in a public issue. If no private channel is available, state that in a minimal public issue and request a private contact without publishing exploit steps.

There is currently no verified security contact in repository metadata. Maintainers should replace this process with an official private channel when one is established.

## Information to include

- Affected commit/version, platform, and Python version.
- Impact and preconditions.
- Minimal, non-destructive reproduction steps using a local fixture or authorized test environment.
- Expected and observed behavior, with sanitized logs.
- Any known mitigations or workaround.

## What not to publish

Do not include live secrets, access tokens, private keys, personal data, private source code, public-target instructions, or a weaponized payload. Redact repository paths or hostnames when they expose private information.

## Scope

In scope: vulnerabilities in NSAT’s CLI, scanners, analyzers, provider/context handling, remediation/rollback safeguards, PDF/report generation, and documented security boundaries. Out of scope: vulnerabilities in third-party dependencies reported without an NSAT impact, findings on systems scanned with NSAT, or claims that rely only on unsupported planned features. Dependency issues may still be relevant when a concrete NSAT impact is shown.

## Response expectations

Maintainers should acknowledge receipt, assess impact and reproducibility, coordinate remediation and disclosure, and credit reporters when requested and appropriate. No fixed service-level timeline is published. Do not assume a report is received until acknowledged through a private channel.

## Documentation

- [README](README.md) · [PRD](PRD.md) · [TRD](TRD.md) · [Architecture](ARCHITECTURE.md)
- [Phases](Phases.md) · [Setup](SETUP.md) · [AI Instructions](AI_INSTRUCTION.md)
- [Agent Instructions](AGENTS.md) · [Contributing](CONTRIBUTING.md)
