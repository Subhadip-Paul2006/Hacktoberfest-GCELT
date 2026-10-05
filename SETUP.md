# NSAT User Setup & Security Audit Guide

**Project:** NSAT — Network Security Audit & Threat Assessment  
**Architecture:** Deterministic Security Surface Engine + Phase 4A Threat Graph & Risk Correlation + Phase 4B GLM-5.3 AI Reasoning Layer  
**Core Motto:** *Deterministic First, AI Second. Smallest Robust Implementation over Largest Possible Feature Set.*

---

## A. Requirements

### Supported Runtime
- **Python 3.11+** (tested on Python 3.11, 3.12, and 3.13)
- **Git** (for version control and diff patching)
- Operating Systems: Linux, macOS, Windows (PowerShell / Command Prompt)

### Optional External Tools
NSAT operates 100% autonomously out of the box using native AST engines, Shannon entropy secret detectors, and asyncio socket scanners. If external tools are present in `$PATH`, NSAT leverages them for enhanced coverage; otherwise, it degrades gracefully with zero tracebacks:
- `semgrep` (supplementary static AST scanning)
- `gitleaks` (supplementary git history secret scanning)
- `trivy` / `osv-scanner` (external CVE vulnerability databases)
- `nmap` (advanced raw network probing)
- `osqueryi` (host OS process inspection)

### AI Requirements
- **GLM-5.3** (Zhipu AI / NVIDIA NIM / OpenAI-compatible proxy gateway)
- Strictly optional. When `AI_ENABLED=false` or when credentials are missing, NSAT operates with 100% deterministic precision.

### Target Authorization
Active validation probes (`--active`, `nsat validate`) and runtime scans (`--target`) require explicit authorization:
- Local loopback (`127.0.0.1`, `localhost`) is enabled by default.
- Any remote target requires the `--authorized` flag to prevent unauthorized security testing.

---

## B. Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Subhadip-Paul2006/Hacktoberfest-GCELT.git
cd Hacktoberfest-GCELT
```

### 2. Set Up Virtual Environment
**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install NSAT
```bash
pip install --upgrade pip
pip install -e .
```

Verify your installation:
```bash
nsat --version
nsat doctor
```

---

## C. Configuration

NSAT uses environment variables and an optional `.env` file in the root directory.

### Example `.env` Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Edit `.env`:
```env
# AI Reasoning Configuration (GLM-5.3)
AI_ENABLED=true

# API Credentials (Do NOT commit real keys to Git!)
GLM_API_KEY=your_glm_api_key
GLM_BASE_URL=https://integrate.api.nvidia.com/v1
GLM_MODEL=z-ai/glm-5.3

# Optional: Dedicated remediation model (Phase 4C preview)
KIMI_API_KEY=your_kimi_api_key
KIMI_BASE_URL=https://integrate.api.nvidia.com/v1
KIMI_MODEL=moonshotai/kimi-k3
```

> [!NOTE]
> The `GLM_BASE_URL` and `GLM_MODEL` depend on your API provider. NSAT supports NVIDIA NIM, Zhipu AI, and any OpenAI-compatible proxy gateway. Keep GLM and Kimi configurations independent.

---

## D. First Scan (Static Repository Audit)

Audit any local project, repository, or directory:
```bash
nsat audit /path/to/my-project
```

### What NSAT Inspects:
1. **Project Intelligence:** Discovers programming languages, frameworks, entrypoints, and sensitive operations.
2. **Multi-Language AST SAST:** Detects SQL injection, command execution, path traversal, weak crypto, and debug flags without relying on variable names.
3. **Secret Detection:** Detects high-entropy API keys, passwords, private keys, and tokens with automatic redaction.
4. **Dependency Analysis:** Identifies vulnerable packages and known CVE advisories across requirements, package.json, and pom.xml.
5. **Infrastructure & Containers:** Scans Dockerfiles and docker-compose configurations for root user, privilege escalation, and `/var/run/docker.sock` socket mounts.

---

## E. Scan a Local Web Application

When your web service is running locally, scan its runtime endpoint alongside source code:
```bash
# Ensure your app is running on port 8000 first!
nsat audit /path/to/my-project --target http://127.0.0.1:8000
```
NSAT checks HTTP security headers (CSP, HSTS, X-Frame-Options), cookie security flags, server version leaks, and public exposure.

---

## F. Active Validation Swarm

Dynamically verify vulnerabilities using the Phase 3 Active Validation Swarm:
```bash
nsat audit /path/to/my-project \
  --active \
  --target http://127.0.0.1:8000
```
- Executes non-destructive, bounded probes (SQL syntax checks, parameter validation, rate limiting probes).
- Upgrades findings from `POTENTIAL` to `VALIDATED` based on real response evidence.
- *Strictly restricted to authorized environments.*

---

## G. Developer Oversight Audit

Audit subtle business logic loopholes and information leakage:
```bash
nsat audit /path/to/my-project --oversight
```
Detects:
- Sensitive tokens and passwords leaked in URL query parameters (`URL_LEAKAGE`)
- Premature order confirmation without payment verification (`PREMATURE_PAYMENT`)
- Client-controlled prices or quantities (`CLIENT_TRUST`)
- Debug / telemetry endpoints exposed in production routes

---

## H. Full Security Audit

Execute the complete end-to-end security pipeline:
```bash
nsat audit /path/to/my-project \
  --active \
  --oversight \
  --ai \
  --target http://127.0.0.1:8000
```

### Terminal Output Pipeline:
```text
NSAT SECURITY AUDIT

  Project Discovery                  ✓
  Static Security                    ✓
  Active Validation                  ✓
  Developer Oversight                ✓
  Correlation                        ✓
  Risk Analysis                      ✓
  AI Security Analysis               ✓

Overall Risk: CRITICAL (100/100)

GLM-5.3 Analysis:
  Multi-layer analysis revealed severe host-level compromise risks stemming from
  unrestricted Docker socket exposure combined with dynamic command execution.
  Sensitive tokens are transmitted via URL parameters in authentication routes.

Top Attack Path:
  Container Breakout via Mounted Docker Socket -> Host Root Daemon Takeover

Most Important File:
  src/api/handlers.py:40

Recommended Priority:
  P0
```

---

## I. Security Reports

NSAT provides comprehensive reports across formats:

### Terminal Report (12 Deterministic Sections)
```bash
nsat report /path/to/my-project
```

### Machine-Readable JSON Export
```bash
nsat report /path/to/my-project --json
```

### Detailed Markdown Report
```bash
nsat report /path/to/my-project --markdown -o audit-report.md
```

### AI-Assisted Executive Report (GLM-5.3)
```bash
nsat ai-report /path/to/my-project
```
Produces an executive 6-section human-readable narrative explaining:
1. Executive Security Summary
2. Risk Score & Threat Posture Interpretation
3. Priority Findings Breakdown
4. Correlated Multi-Hop Attack Paths
5. Developer-Focused Technical Explanations
6. Phased Remediation Roadmap (P0, P1, P2)

---

## J. Explain Specific Findings

Get deep root-cause analysis and verification instructions for any finding ID:
```bash
nsat explain NSAT-PY-SQLI /path/to/my-project
```

Output:
```text
Finding: NSAT-PY-SQLI -- SQL Injection in Database Query Handler
Severity: CRITICAL
Confidence: 0.95
Status: VALIDATED
Priority: P0

Where:
  File: src/api/handlers.py
  Line: 40
  Function: handler
  Class: Not reliably resolved
  Endpoint: GET /search

What happened:
  Unsanitized user input formatted directly into cursor.execute() query sink.

Why it matters:
  Direct database exfiltration and arbitrary SQL query execution.

Evidence:
  [AST_SINK] Call to cursor.execute() with string interpolation
    Snippet: cur.execute(f"SELECT * FROM users WHERE name = '{x1}'")

Related findings:
  - NSAT-SEC-001 (AMPLIFIES)

Potential attack path:
  Attack Path [AP-02]: Database Compromise via Injection
    -> Parameter Input in GET /search
    -> Unsanitized SQL String Formatting
    -> Credential Datastore Exfiltration

Recommended direction:
  Use parameterized query with placeholder bindings.

What would verify the fix:
  Re-scanning the target file with targeted language AST analyzer to confirm
  that the vulnerable sink signature is no longer present.
```

---

## K. Interactive Security Chatbot

Ask questions directly about your project's security posture:
```bash
nsat chat /path/to/my-project
```

### One-Shot Question:
```bash
nsat chat /path/to/my-project --ask "Why is this project rated critical?"
```

### Focused Chat on a Specific Finding:
```bash
nsat chat /path/to/my-project --finding NSAT-CONT-002
```

### Example Interactive Conversation:
```text
You:
> Why is this project rated critical?

NSAT:
> The project risk score is 100/100 (CRITICAL) because:
  1. Blast radius is Tier 3 (Host/Cluster Takeover) due to /var/run/docker.sock mounted in Dockerfile:18.
  2. 3 CRITICAL severity findings exist, including command injection in src/api/handlers.py:52.
  3. Dynamic active validation confirmed unauthenticated access to administrative sinks.

You:
> Which file should I fix first?

NSAT:
> You should fix 'src/api/handlers.py' first (line 40, function 'handler').
  It contains [P0] finding NSAT-PY-SQLI which directly exposes database records.

You:
> exit
```

---

## L. Understanding NSAT Output Metrics

- **Severity:**
  - `CRITICAL`: Immediate compromise or host breakout (Command injection, mounted docker socket, plaintext root credentials).
  - `HIGH`: Direct data loss, authentication bypass, or logic flaw.
  - `MEDIUM`: Misconfiguration, unauthenticated access, or missing defense-in-depth controls.
  - `LOW`: Missing security headers, lack of rate limiting, or minor information disclosure.
  - `INFORMATIONAL`: Best practice recommendations.
- **Confidence (0.0 to 1.0):**
  - `0.90+`: High precision AST structural match or secret pattern.
  - `0.70 - 0.89`: Probable match requiring contextual verification.
  - `< 0.70`: Heuristic indicator.
- **Validation Status:**
  - `VALIDATED`: Actively confirmed via dynamic non-destructive HTTP/socket probe.
  - `POTENTIAL`: Identified statically; pending runtime verification.
  - `UNVERIFIED`: Static finding in unreachable code or untested route.
- **Priority:**
  - `P0`: Fix immediately before deployment (blocks build).
  - `P1`: High priority patch required in current release cycle.
  - `P2`: Medium priority remediation scheduled in standard sprint.
  - `P3`: Low priority backlog hardening.
- **Blast Radius Tiers:**
  - `Tier 3 (Host/Cluster Takeover)`: Attacker gains control of the host OS, Docker daemon, or Kubernetes cluster.
  - `Tier 2 (Data Exposure / Lateral Pivot)`: Database exfiltration or cloud credential leakage.
  - `Tier 1 (Localized Execution)`: Impact is strictly confined to an isolated worker process.

---

## M. Multi-Language Support

NSAT provides native structural AST parsers for polyglot repositories:
- **C++:** `nsat/analyzers/cpp/` (raw `system()`, `popen()`, unsafe `strcpy`/`sprintf`, wildcard `INADDR_ANY` bindings)
- **Python:** `nsat/analyzers/python/` (built-in `ast` module; taint tracking into `os.system`, `subprocess`, `cursor.execute`)
- **Java:** `nsat/analyzers/java/` (Spring annotations, `Runtime.exec`, insecure `MessageDigest` MD5/SHA-1)
- **JavaScript / TypeScript:** `nsat/analyzers/javascript_typescript/` (`eval()`, `child_process.exec()`, unsafe JSX `dangerouslySetInnerHTML`, CORS wildcard)
- **Rust / Go / PHP:** Native structural regex & token AST scanners

Mixed-language monorepos are analyzed automatically in a single unified audit pass.

---

## N. Auditing Deployed Web Applications

When targeting deployed staging or production environments:
1. **Explicit Authorization:** You must have written permission. Use the `--authorized` flag.
2. **Safe Bounded Probes:** NSAT Active Validation Swarm performs bounded, read-only HTTP probes. It will never perform denial-of-service floods, brute force dictionary attacks, or destructive data modifications.
3. **Perimeter vs Code Visibility:** Remote probing detects visible headers, route behaviors, and TLS configuration. For full correlation, supply the source repository alongside the target URL:
   ```bash
   nsat audit ./my-repo --target https://staging.example.com --authorized --active
   ```

---

## O. Optional External Tools & Fallbacks

| Tool | Capability | When Missing (NSAT Native Fallback) |
| :--- | :--- | :--- |
| `semgrep` | Static AST rules | NSAT native Python/C++/Java AST analyzers run automatically. |
| `gitleaks` | Secret scanner | NSAT native Shannon entropy & regex engine scans files. |
| `trivy` | Container / CVE scanner | NSAT native offline CVE advisory catalog and Dockerfile auditor. |
| `nmap` | Port scanner | NSAT non-privileged `asyncio` TCP socket connector. |
| `osqueryi` | Host auditor | NSAT native `psutil` and OS process inspector. |

---

## P. AI Disabled Mode (100% Offline)

To run NSAT in strictly offline, air-gapped environments:
```bash
export AI_ENABLED=false
nsat audit /path/to/my-project
nsat report /path/to/my-project
```
The deterministic risk score, threat graph, attack paths, and terminal reports continue to function with complete accuracy.

---

## Q. Troubleshooting

### 1. `GLM provider unavailable`
- Ensure `GLM_API_KEY` is set in your environment or `.env` file.
- Verify `GLM_BASE_URL` is accessible from your network.
- NSAT will automatically log a controlled warning and fall back to deterministic reporting.

### 2. `Target path does not exist`
- Verify the relative or absolute path provided to `nsat audit <PATH>`.

### 3. `Permission denied on socket binding`
- On Linux, binding to ports below 1024 requires root privileges. NSAT network checks use standard unprivileged user connections.

### 4. `Target outside authorized scope`
- When passing `--target <URL>`, you must certify authorization with `--authorized`.

---

## R. Security & Authorization Warning

> [!CAUTION]
> NSAT is a dual-use defensive security assessment tool. Active validation probes and runtime network checks must **ONLY** be directed against systems, networks, and repositories that you own or for which you have explicit, documented authorization to test. Unauthorized port scanning, network probing, or vulnerability exploitation is illegal and unethical.
