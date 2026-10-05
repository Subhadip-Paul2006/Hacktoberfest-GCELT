# NSAT — Network Security Audit & Threat Assessment

> **Defensive, CLI-first security auditing, attack-path correlation, and autonomous remediation platform.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://python.org)
[![CLI: Rich-powered](https://img.shields.io/badge/CLI-Rich%20Powered-magenta.svg)](https://github.com/Textualize/rich)
[![Status: Hackathon MVP](https://img.shields.io/badge/Status-Hackathon%20MVP-orange.svg)]()

---

## 1. The Problem

Modern codebases increasingly combine AI-generated ("vibe-coded") logic, complex microservices, and multi-cloud configurations. Traditional security scanners operate in isolated silos:

- **SAST tools** flag raw code lines without context.
- **Secret scanners** find tokens without knowing whether they are reachable.
- **Network scanners** find open ports without knowing what code is listening.
- **Generic AI wrappers** can hallucinate vulnerabilities and often rely on descriptive function or variable names such as `login()` and `user_input`, failing on obfuscated or AI-scaffolded code such as `a()`, `handler2()`, or `tmp`.

---

## 2. The Solution: NSAT

**NSAT** unifies code, secrets, dependencies, network bindings, containers, and host permissions into a single defensive threat engine. It treats security findings not as isolated alerts, but as nodes in an **Attack Surface Graph**, synthesizing multi-hop attack paths and evaluating post-compromise blast radius.

### The 8-Stage Core Pipeline

```text
SCAN ───► NORMALIZE ───► DEDUPLICATE ───► CORRELATE ───► ANALYZE ───► EXPLAIN ───► REMEDIATE ───► VERIFY
```

1. **SCAN:** Discovers project architecture and applies AST-based semantic parsing and security checks.
2. **NORMALIZE:** Translates all findings into a uniform `CanonicalFinding` model.
3. **DEDUPLICATE:** Suppresses noise, such as vendor directories and harmless constants, and merges overlapping scanner results.
4. **CORRELATE:** Constructs an in-memory graph connecting open ports, code-injection sinks, and exposed secrets.
5. **ANALYZE:** Computes the **Post-Compromise Blast Radius** under an "Assume Breach" model.
6. **EXPLAIN:** Delivers technical explanations separated into **[FACT]**, **[INFERENCE]**, and **[RECOMMENDATION]** sections.
7. **REMEDIATE:** Proposes surgical unified diffs and applies approved patches.
8. **VERIFY:** Runs tests and rescans to verify that issues have been eliminated without regressions.

---

## 3. Key Capabilities

- **Language-agnostic semantic AST analysis:** Supports C++, Java, Python, and JavaScript/TypeScript. Detects security-critical source-to-sink data flow even when variable and function names are meaningless.
- **Post-compromise blast radius:** Quantifies what an attacker can reach, including local `.env` secrets, internal databases, mounted `/var/run/docker.sock`, and cloud IAM tokens, after a service is breached.
- **Offline and deterministic first:** Full scanning, correlation, scoring, and patch generation work offline without an internet connection or LLM.
- **Pluggable scanner ecosystem:** Integrates external engines such as Semgrep, Gitleaks, Trivy, Nmap, and osquery, with NSAT-native fallbacks when tools are unavailable.
- **Closed-loop verification:** `nsat fix` applies surgical patches and automatically triggers `nsat verify` to prevent regressions.

---

## 4. Supported Languages (MVP)

| Language | Primary Detection & AST Engine | Target Frameworks & Sinks |
| :--- | :--- | :--- |
| **Python** | Native `ast` + Tree-sitter | FastAPI, Flask, Django; SQL injection, command injection, raw sockets |
| **JavaScript / TypeScript** | Tree-sitter | Express, NestJS, Next.js, React; `eval()`, subprocesses, CORS |
| **Java** | Tree-sitter | Spring Boot, Servlets; weak MD5/SHA-1 cryptography, command execution |
| **C++** | Tree-sitter | Crow, Drogon, Boost.Beast, POSIX sockets; buffer overflows, `popen()` |

---

## 5. Quick Start (Under 2 Minutes)

### Prerequisites

- Python 3.11+
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/Subhadip-Paul2006/Hacktoberfest-GCELT.git
cd Hacktoberfest-GCELT

# Set up a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

### Validate Environment Capabilities

```bash
nsat doctor
```

---

## 6. CLI Usage & Commands

```bash
# 1. Audit a local source repository
nsat audit ./path/to/project

# 2. Audit an authorized local or deployed web application
nsat audit --target http://127.0.0.1:8000

# 3. Audit local host processes, persistence, and sockets
nsat host

# 4. Audit an explicitly authorized network subnet
nsat network 192.168.1.0/24 --authorized

# 5. Explain a specific finding
nsat explain NSAT-PY-001

# 6. Apply a surgical remediation patch and verify it
nsat fix NSAT-PY-001
nsat verify

# 7. Export a full report in SARIF, JSON, or Markdown
nsat report --format sarif --output audit-results.sarif
```

---

## 7. Deterministic Hackathon Demo Walkthrough

NSAT bundles a multi-language vulnerable demo application in `./tests/demo-vuln-app`:

```bash
# Step 1: Run a comprehensive audit
nsat audit ./tests/demo-vuln-app
```

```text
  _  _ ___   _ _____
 | \\| / __| /_\\_   _|  NETWORK SECURITY AUDIT & THREAT ASSESSMENT
 | .` \\__ \\/ _ \\| |    v1.0.0 | Defensive Multi-Layer Security Platform
 |_|\\_|___/_/ \\_\\_| 

[i] Discovered: Python (60%), TypeScript (25%), C++ (15%) | Archetype: REST API
[✔] AST Code Analysis Complete (14 files scanned)
[✔] Secret & Entropy Scanner Complete (2 credentials found)
[✔] Network Exposure Inspector Complete (Port 5432 bound to 0.0.0.0)
[✔] Container Security Complete (Dockerfile runs as root with docker.sock mounted)

[!] CORRELATED ATTACK PATH:
    1. [SAST] SQL Injection in handler2() (src/api/handlers.py:42)
    2. [SECRET] Leaked DB_PASSWORD in config/default.env:8
    3. [NETWORK] PostgreSQL listener exposed on 0.0.0.0:5432
    => CRITICAL IMPACT: Remote unauthenticated database takeover.

[!] POST-COMPROMISE BLAST RADIUS:
    Tier: TIER 3 (HOST & CLUSTER TAKEOVER)
    Root Docker socket accessible via container volume mount.
```

```bash
# Step 2: Surgically fix and verify
nsat fix NSAT-PY-001
nsat verify
```

```text
[+] Applying surgical parameterized query patch to src/api/handlers.py... [APPLIED]
[✔] Re-scanning src/api/handlers.py...
[✔] VERIFIED: Finding NSAT-PY-001 is ELIMINATED. Zero regressions detected.
```

---

## 8. Repository Structure

```text
Hacktoberfest-GCELT/
├── Phases.md               # 4-hour hackathon implementation timebox
├── SETUP.md                # Environment and dependency guide
├── AI_INSTRUCTION.md       # AI reasoning and explainer contract
├── AGENTS.md               # Autonomous coding agent constraints
├── README.md               # Product overview and documentation
├── nsat/
│   ├── cli/                # Click/Typer commands and Rich UI
│   ├── core/               # Orchestrator, discovery, and capability registry
│   ├── analyzers/          # C++, Java, Python, and JS/TS AST adapters
│   ├── scanners/           # SAST, secrets, dependencies, network, host, container
│   ├── normalization/      # CanonicalFinding model and noise filter
│   ├── correlation/        # Graph engine, blast radius, and risk scoring
│   ├── remediation/        # Patch generator, diff applier, and verifier
│   ├── ai/                 # LLM provider abstraction
│   └── reporting/          # Terminal, JSON, Markdown, and SARIF exporters
└── tests/
    └── demo-vuln-app/      # Deterministic multi-language demo testbed
```

---

## 9. Hackathon Scope vs. Future Roadmap

### Hackathon MVP (Current Scope)

- Four-language AST analyzers: C++, Java, Python, and JavaScript/TypeScript.
- Local and container network-binding analysis (`127.0.0.1` vs. `0.0.0.0`).
- Secret, dependency, host-process, and container-security audits.
- Graph correlation and Post-Compromise Blast Radius calculator.
- Surgical unified-diff remediation and automated rescan verification.

### Future Roadmap

- Additional language adapters: Go, Rust, C#, Ruby, and Kotlin.
- Live read-only Cloud Security Posture Management for AWS, Azure, and GCP.
- IDE background extensions for VS Code and JetBrains.
- Automated API schema fuzzing with OpenAPI/Swagger integration.

---

## 10. License & Defensive Security Scope

This tool is distributed under the **MIT License**.

**Defensive Security Notice:** NSAT is strictly engineered for defensive vulnerability assessment, internal posture auditing, and authorized remediation. Active network checks require explicit authorization from the system or network owner. Do not use NSAT to scan systems or networks without permission.
