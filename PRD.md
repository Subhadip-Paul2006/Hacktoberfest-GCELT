# Product Requirements Document (PRD)
# NSAT — Network Security Audit & Threat Assessment

---

## Document Metadata
- **Product Name:** NSAT (Network Security Audit & Threat Assessment)
- **Tagline:** Defensive, multi-layer security auditing, correlation, remediation, and verification platform.
- **Core Pipeline:** `SCAN → NORMALIZE → CORRELATE → ANALYZE → EXPLAIN → REMEDIATE → VERIFY`
- **Document Version:** 1.0.0
- **Status:** Approved Architecture Draft
- **Target Audience:** Hackathon Judges, Security Architects, SecOps Engineers, Developers, and Autonomous Implementation Agents

---

## 1. Executive Summary

Modern software applications are increasingly composed of heterogeneous microservices, legacy modules, AI-generated code snippets ("vibe-coded" systems), third-party dependencies, and multi-cloud infrastructure definitions. Traditional security tooling operates in silos: SAST tools flag isolated code lines; DAST tools fire blind HTTP probes; container scanners inspect static layers; and host audit tools monitor system processes independently.

**NSAT (Network Security Audit & Threat Assessment)** is a defensive, CLI-first security auditing and autonomous remediation platform. Inspired by the architectural rigor of the System Design Audit Tool (SDAT), NSAT breaks security silos by correlating findings across the entire software and infrastructure lifecycle:
1. **Source Code & AST Analysis** (C++, Java, Python, JavaScript, TypeScript)
2. **Secrets & Credential Exposure**
3. **Software Supply Chain & Dependencies**
4. **Network & Web Runtime Exposure**
5. **Host, Container, and Cloud Configuration**
6. **Malware & Abuse Indicators**
7. **Post-Compromise Blast Radius Modeling**

NSAT is engineered to operate **deterministically without requiring an LLM**, while seamlessly utilizing local or cloud LLMs (Gemma, DeepSeek, Qwen, Ollama, OpenAI) for contextual attack-path explanation, risk prioritization, and interactive remediation assistance. Most crucially, NSAT does **not rely on identifier naming conventions**, comments, or code cleanliness; it analyzes structural ASTs, data/control flow, network bindings, and runtime evidence to uncover deep-seated vulnerabilities even in obfuscated, AI-generated, or boilerplate-heavy codebases.

---

## 2. Problem Statement

1. **The AI-Generated & "Vibe-Coded" Code Dilemma:** Developers increasingly commit LLM-generated code with meaningless variable names (`a`, `tmp1`, `handler2`), deeply nested generic abstractions, and boilerplate duplication. Traditional pattern-matching regex and heuristic scanners fail or produce intolerable false-positive/false-negative rates.
2. **Disconnected Point Solutions:** A repository might have a missing rate limiter (SAST), an exposed database port on `0.0.0.0:5432` (Network Scan), and hardcoded default DB credentials (Secret Scan). Individual scanners flag these as low-or-medium issues. None of them identify the lethal attack chain: *Unauthenticated Internet exposure + Hardcoded credential = Immediate full remote database takeover*.
3. **No Closed-Loop Remediation:** Vulnerability scanners output thousands of lines of SARIF or PDF reports and abandon the developer. Developers struggle to patch issues accurately without introducing breaking architectural regressions.
4. **Hallucination Risk in Pure-AI Scanners:** "AI-first" security wrappers often hallucinate CVEs, misread code syntax, or report nonexistent flaws. NSAT enforces ground-truth structural evidence first; AI is applied solely downstream for synthesis and contextual explanation.

---

## 3. Product Vision & Principles

### Vision
To provide engineers and security auditors with a single, unified, battle-hardened CLI tool that transforms raw security findings into actionable attack paths, quantifies post-compromise blast radius, autonomously generates verified surgical code patches, and proves remediation validity through deterministic re-scanning.

### Core Architectural Principles
- **AST and Data Flow over Identifiers:** Semantic rules evaluate source-to-sink data flow, control flow, AST node types, and runtime configs—never relying on descriptive variable or function names.
- **Deterministic Independence (Offline First):** Full scan, normalization, correlation, scoring, and reporting must succeed completely offline without any AI or LLM connection.
- **Multi-Layer Attack Surface Correlation:** Findings from disparate domains (e.g., Code + Network + Host) are combined in an in-memory Attack Graph to surface combined attack chains.
- **Strict Defensive Scope & Safety Boundaries:** Non-offensive, non-destructive. Network scans and probes require explicit authorization flags. No unauthorized brute-forcing, denial of service, or Wi-Fi cracking.
- **Closed-Loop Verification:** "Fix" is never complete until "Verify" proves the vulnerability is eliminated and no regressions were introduced.

---

## 4. Goals & Non-Goals

### Goals
- **Multi-Language AST Support:** Out-of-the-box structural parsing for C++, Java, Python, and JavaScript/TypeScript via a pluggable adapter framework.
- **Unified Canonical Finding Schema:** Normalize disparate scanner outputs (native AST, Semgrep, Trivy, Gitleaks, Nmap, osquery) into a uniform schema.
- **Multi-Vector Correlation Engine:** Connect isolated findings into comprehensive attack paths using an in-memory directed graph.
- **Flagship Post-Compromise Blast Radius Engine:** Model "Assume Compromise"—what an adversary can access if the runtime process or host is breached.
- **Noise Suppression & False-Positive Filter:** Automatically de-duplicate and suppress boilerplate, dead code, test fixtures, and low-confidence regex matches without discarding valid code with generic naming.
- **Surgical Remediation Agent:** Generate bounded, minimal diff patches and execute automated verification re-scans.
- **Multi-Format Reporting:** Produce stunning Hackathon-ready terminal dashboards (via Rich/ANSI), Markdown, JSON, HTML, and SARIF.

### Non-Goals
- **Offensive Exploitation:** NSAT does NOT generate or launch live exploits, payloads, or remote code execution attacks against targets.
- **DDoS / Stress Flooding:** NSAT does NOT perform live volumetric denial-of-service tests. It evaluates resource constraints and unthrottled endpoints statically and via bounded safe probing.
- **Offensive Wi-Fi / Air-Crack:** NSAT assesses LAN and Wi-Fi interface binding defensively (e.g., detecting `0.0.0.0` vs `127.0.0.1` exposure); it does NOT capture handshakes or de-authenticate wireless clients.
- **Arbitrary Repository Refactoring:** The Remediation Agent does not perform wide stylistic refactoring or complete architectural rewrites; fixes are strictly targeted at specific vulnerability sinks.

---

## 5. Target Users & Personas

| Persona | Role | Primary Objective with NSAT |
| :--- | :--- | :--- |
| **DevSecOps / AppSec Engineer** | Security Architect | Run automated CI/CD scans, enforce security gates, generate SARIF reports, and review attack-path graphs before deployment. |
| **Full-Stack Developer** | Software Engineer | Run `nsat audit`, understand structural weaknesses in AI-generated code, and execute `nsat fix` to automatically patch security flaws. |
| **Security Auditor / Consultant** | Penetration Tester / Auditor | Perform rapid defensive posture assessments on client source repos, hosts, and authorized LAN endpoints; model post-compromise blast radius. |
| **Hackathon Judges / Reviewers** | Technical Evaluator | Witness an end-to-end, highly visual, multi-language audit that catches cross-layer vulnerabilities, displays an attack graph, and patches code in real time. |

---

## 6. Primary Use Cases

1. **Auditing AI-Generated or Legacy Repositories:** A developer receives an AI-scaffolded or vendor repository filled with generic variable names (`req1`, `data`, `res`). NSAT parses ASTs, identifies unauthenticated endpoints passing un-sanitized input to database query sinks, and flags SQL injection regardless of naming conventions.
2. **Pre-Deployment Posture & Blast Radius Assessment:** A team is preparing to ship a Dockerized microservice. NSAT audits the Dockerfile, local network bindings, and code. It discovers that the container runs as `root`, mounts `/var/run/docker.sock`, and has `.env` secrets readable by all users, alerting the team to catastrophic container escape risk.
3. **Automated Closed-Loop Remediation:** An audit discovers missing CORS headers, disabled CSRF protection, and unescaped subprocess commands. The developer runs `nsat fix NSAT-PY-0012`, inspects the proposed diff, approves the patch, and NSAT immediately re-scans to verify zero-regression resolution.
4. **Authorized Local Network & Host Threat Sweep:** An administrator runs `nsat host` and `nsat network --target 192.168.1.0/24 --authorized` to detect listening daemons bound to `0.0.0.0`, default management ports, and suspicious persistence mechanisms.

---

## 7. Hackathon Demo Scenario

The live hackathon demonstration executes a 5-minute deterministic, visual narrative using a pre-configured multi-language vulnerable demo repository (`demo-vuln-app`):

```
+-----------------------------------------------------------------------------------+
| 1. DOCTOR: nsat doctor                                                           |
|    - Shows capability registry: AST Parsers, Semgrep, Trivy, Nmap status          |
|                                                                                   |
| 2. AUDIT: nsat audit ./demo-vuln-app                                              |
|    - Instant Language Detection: Python (FastAPI) + TypeScript (React) + C++      |
|    - Structural AST scanning finds SQLi, Command Injection, & Missing Rate Limits|
|    - Detects .env credential exposure and root Dockerfile socket mount            |
|                                                                                   |
| 3. CORRELATE & BLAST RADIUS:                                                      |
|    - Synthesizes Attack Path: Internet -> Public API -> DB Creds -> Internal DB   |
|    - Evaluates Post-Compromise Blast Radius (Full Host & Database Compromise)    |
|                                                                                   |
| 4. EXPLAIN: nsat explain NSAT-0042 --ai                                           |
|    - Structured AI explanation separating Observed Fact, Inference, & Fix         |
|                                                                                   |
| 5. REMEDIATE & VERIFY: nsat fix NSAT-0042                                         |
|    - Displays surgical diff patch; applies patch; re-scans; confirms: FIXED!      |
+-----------------------------------------------------------------------------------+
```

---

## 8. Operating Modes & CLI UX

NSAT features a modern, intuitive, sub-command-driven CLI with unified flags and rich terminal formatting.

### Command Matrix

| Command | Purpose | Required Authorization / Target |
| :--- | :--- | :--- |
| `nsat audit [PATH]` | Static audit of source code, dependencies, secrets, and configurations. | Local filesystem path (default: current directory). |
| `nsat audit --target <URL>` | Dynamic & runtime audit of an authorized HTTP/Web service. | Must provide `--authorized` flag if remote. |
| `nsat network` | Discover and audit open ports, services, and bindings on authorized subnet. | Requires `--target <CIDR>` and `--authorized`. |
| `nsat host` | Audit local OS processes, persistence, mounts, and network sockets. | Local machine execution (elevated permissions optional). |
| `nsat monitor` | Continuous defensive monitoring of file changes and listening sockets. | Local filesystem and network interface. |
| `nsat report` | Generate full audit report in JSON, Markdown, HTML, or SARIF format. | Accepts previous run ID or triggers full pipeline. |
| `nsat explain <ID>` | Deep-dive root cause analysis and impact breakdown of a finding. | Finding ID (`NSAT-XXXX`). Supports optional `--ai`. |
| `nsat fix <ID>` | Generate and apply an automated, surgical remediation patch. | Finding ID (`NSAT-XXXX`). Interactive confirmation. |
| `nsat verify [ID]` | Re-run targeted scanners against patched files to confirm resolution. | Finding ID or all remediated findings. |
| `nsat doctor` | Verify installed external engines, AST parsers, and capabilities. | None. |
| `nsat config` | Manage global/local scan policies, AI API keys, and scope filters. | Key/Value management CLI. |

### CLI Design Specifications
- **Interactive Prompts & Color System:** Built using Rich/Textual with ANSI fallbacks.
  - Red / Bright Magenta: Critical / High Severity Vulnerabilities
  - Yellow / Amber: Medium Severity / Warning Exposure
  - Blue / Cyan: Informational / Project Discovery / Architecture
  - Green: Verification Passed / Secure Controls Detected
- **Quiet & Machine-Readable Modes:** `--json` and `--quiet` flags suppress banners and output pure JSON to `stdout` for CI/CD pipeline automation.

---

## 9. Modular Scan Domains (A through N)

NSAT organizes security evaluation into 14 distinct, pluggable scan domains:

### Domain A: Project & Architecture Discovery
- **Language Detection:** Multi-language percentage breakdown (C++, Java, Python, JavaScript/TypeScript).
- **Framework & Runtime Detection:** Identifies web/RPC frameworks (FastAPI, Flask, Express, Spring Boot, Crow/Drogon, Qt, React, Angular, Next.js).
- **Project Classification:** Inferred without relying on naming (Web Application, REST API, Microservice, Network Daemon, Embedded CLI, Desktop GUI, SDK/Library).
- **Entry Points & Endpoint Mapping:** Discovers HTTP routes, WebSocket handlers, and TCP/UDP listener bindings.

### Domain B: Source Code Structural Security (AST SAST)
- **Injection Vulnerabilities:** SQL injection, Shell/Command execution (`exec`, `system`, `popen`), Path Traversal, SSRF, Template Injection (SSTI).
- **Taint Analysis (Source-to-Sink):** Traces external untrusted inputs (HTTP params, query strings, headers, environment variables, sockets) to dangerous execution sinks.
- **Cryptographic Misuse:** Hardcoded IVs, weak hash algorithms (MD5, SHA1 for passwords), low-iteration PBKDF2, insecure random generators (`rand()`, `Math.random()`, `random.random`).
- **Memory & Concurrency Safety:** Unsafe buffer writes (`strcpy`, `sprintf`), race conditions, missing mutex locks in C++ and Java.

### Domain C: Secret & Credential Analysis
- **High-Entropy Token Detection:** AWS keys, GCP service tokens, GitHub PATs, JWT signing secrets, SSH private keys, database connection strings.
- **Config & Environment Exposure:** Unprotected `.env`, `.env.local`, `.git` directory exposure, committed secrets in version control history.

### Domain D: Dependency & Supply Chain Security
- **Manifest & Lockfile Auditing:** `package-lock.json`, `pom.xml`, `requirements.txt`, `Pipfile.lock`, `CMakeLists.txt`, `conan.lock`.
- **Known CVE Matching:** Queries OSV, GitHub Advisory Database, or local offline vulnerability database.
- **Supply Chain Anomaly Detection:** Insecure package registries, typo-squatting risks, and missing lockfiles.

### Domain E: Network Exposure & Binding Security
- **Socket Binding Verification:** Rigorously differentiates `127.0.0.1` (Local Loopback) from `0.0.0.0` (All Interfaces / LAN / Public Exposure) and specific subnet interfaces.
- **Port & Service Auditing:** Identifies listening TCP/UDP ports, unencrypted legacy protocols (HTTP, Telnet, FTP), and unexpectedly exposed internal management ports.

### Domain F: Web & Runtime Security
- **HTTP Security Headers:** Checks for missing or misconfigured `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`.
- **Cookie Security Flags:** Validates `Secure`, `HttpOnly`, and `SameSite` flags.
- **CORS Misconfiguration:** Identifies wildcard origins (`Access-Control-Allow-Origin: *`) coupled with `Allow-Credentials: true`.
- **Information Leakage:** Debug modes enabled in production (`DEBUG = True`), stack traces in error responses, exposed `.map` source maps.

### Domain G: Authentication & Abuse Resistance
- **Brute-Force & Rate Limiting Controls:** Identifies endpoints lacking rate-limiting middleware, IP throttling, or account lockout mechanisms.
- **Credential & Session Controls:** Evaluates session expiration timeouts, token revocation support, and predictable OTP/PIN generation.
- **Account Enumeration Defense:** Verifies whether authentication endpoints leak user existence through differentiated error messages or timing discrepancies.

### Domain H: DoS & Resource Exhaustion Exposure
- **Static & Runtime Boundary Checks:** Flags unbounded file uploads, missing HTTP request body size limits (`client_max_body_size`), missing read/write socket timeouts.
- **Algorithmic Complexity & Worker Starvation:** Identifies unbounded nested loops over user-supplied lists and unconstrained memory buffers.

### Domain I: LAN & Local Perimeter Exposure
- **Subnet Perimeter Audit:** Detects unsegmented local databases, unauthenticated mDNS/Bonjour broadcasts, exposed SMB shares, and open local IoT/admin interfaces.
- **Target Authorization Gate:** Enforces CIDR and IP boundary validation before triggering any LAN sweep.

### Domain J: Host Security & Configuration
- **Process & Socket Inspection:** Lists active listening daemons, their running user ID, process hierarchy, and binary paths.
- **Persistence Mechanisms:** Audits systemd services, cron jobs, Windows Scheduled Tasks, and LaunchDaemons for unauthorized or world-writable persistence.
- **Privilege & Permission Auditing:** Discovers SUID binaries, world-writable executable scripts, and permissive sudo rules.

### Domain K: Keylogger & Credential Monitoring Indicators
- **Suspicious Process & Hook Indicators:** Detects processes loading input capture libraries (`pynput`, `xdotool`, low-level Windows API keyboard hooks `SetWindowsHookEx`).
- **Anomalous Process Signatures:** Identifies unsigned executables operating from temporary or hidden paths (`/tmp`, `C:\Users\...\AppData\Local\Temp`).

### Domain L: Ransomware & Tampering Indicators
- **Abnormal File Modification Rates:** Flags background file write bursts with sudden entropy shifts.
- **Security Control Tampering:** Detects modifications or disabling of local firewalls, logging daemons, or endpoint protection services.

### Domain M: Container & Docker Security
- **Dockerfile & Compose Auditing:** Detects containers running as `root`, privileged container execution (`--privileged`), exposed host namespaces (`--net=host`, `--pid=host`).
- **Host Socket & Volume Mounting:** Identifies catastrophic mounts such as `/var/run/docker.sock`, `/etc`, or `/proc` inside container specs.

### Domain N: Cloud & Deployment Extensibility
- **Infrastructure-as-Code (IaC) Auditing:** Extensible rules for Terraform, Kubernetes manifests, and Helm charts (e.g., permissive SecurityGroups, public S3 buckets).

---

## 10. Flagship Feature: Post-Compromise Blast Radius

The core differentiator of NSAT is its **"Assume Compromise"** analysis engine. Instead of evaluating vulnerabilities as isolated defects, NSAT calculates the theoretical maximum lateral movement and data access an attacker achieves if a single component is breached.

```
+-------------------------------------------------------------------------------+
|                       POST-COMPROMISE BLAST RADIUS GRAPH                      |
|                                                                               |
|  [ Ingress Entry Point: Web API (FastAPI) ]                                    |
|         |                                                                     |
|         v (Unsanitized file upload sink / CVE-2024-XXXX)                       |
|  [ Process Execution as: 'appuser' (uid=1001) ]                              |
|         |                                                                     |
|         +---> Discovered Local Asset: .env File (Permissions: 0644)           |
|         |        |                                                            |
|         |        +---> Extracted DB_PASSWORD & AWS_SECRET_ACCESS_KEY          |
|         |                                                                     |
|         +---> Discovered Mounted Socket: /var/run/docker.sock                |
|         |        |                                                            |
|         |        +---> Immediate Host Root Escalation (Blast Radius: CRITICAL)|
|         |                                                                     |
|         +---> Reachable Local Network: 172.18.0.0/16 (Internal Docker Subnet) |
|                  |                                                            |
|                  +---> Unauthenticated Redis Cache (:6379)                     |
|                  +---> Internal PostgreSQL DB (:5432)                         |
+-------------------------------------------------------------------------------+
```

The Blast Radius engine assigns a **Blast Radius Tier**:
- **TIER 1 (Localized):** Vulnerability impact is strictly limited to the execution context; no lateral credentials or sockets are accessible.
- **TIER 2 (Service/Data Level):** Access leaks internal database credentials or downstream microservice tokens.
- **TIER 3 (Host/Cluster Takeover):** Access leaks root Docker socket, cloud IAM instance profiles, or SUID privilege escalation paths.

---

## 11. False-Positive & Noise Suppression Strategy

Vulnerability scanners fail in real-world adoption when they overwhelm developers with noise. NSAT implements a deterministic **Noise Reduction & Confidence Matrix**:

### Suppression Criteria (Automatic Filtering)
1. **Vendor & Package Directories:** Automatically excludes `node_modules/`, `vendor/`, `target/`, `.venv/`, `dist/`, and third-party build artifacts from static code rule evaluation (handled strictly by dependency analyzers).
2. **Test Fixtures & Documentation Samples:** Non-security-relevant tests (e.g., standard unit test mocks, README code snippets) are classified as low-priority and filtered out of primary security reports unless explicitly flagged.
3. **Dead / Unreachable Code:** If AST call-graph traversal proves a function is unreferenced and has no external export/route binding, its severity is downgraded or filtered.
4. **Harmless Constants:** Hardcoded test strings (`test123`, `foo`, `localhost`) are filtered using entropy and context checks.

### Critical Anti-Suppression Rule (AI-Generated & Obfuscated Code)
> **MANDATORY:** NSAT must **NEVER** suppress a finding simply because variable names, function names, or file names are meaningless (e.g., `a()`, `b()`, `x1()`, `tmp()`, `handler2()`). If an un-sanitized external input reaches a dangerous sink (`eval()`, `system()`, SQL query) within an obfuscated or AI-generated function, it must be reported with 100% confidence.

---

## 12. Security Correlation Engine & Attack Graph

Raw findings from disparate scan domains are ingested into an in-memory **Attack Surface Graph** ($G = (V, E)$):
- **Vertices ($V$):** Components, Endpoints, Secrets, Ports, Processes, Sinks, and Vulnerability Findings.
- **Edges ($E$):** Data flows, Network reachability, Credential usage, Process ownership, and Network binding relationships.

### Correlation Synthesis Rules
- **Rule CR-01 (Exposed Credential Pivot):** `Secret Finding (DB_PASS in .env)` + `Network Finding (Port 5432 bound to 0.0.0.0)` = **CRITICAL Attack Path: Direct Public Database Compromise**.
- **Rule CR-02 (Privileged Escape Path):** `Code Finding (Command Injection)` + `Container Finding (/var/run/docker.sock mounted)` = **CRITICAL Attack Path: Remote Code Execution to Host Root Escape**.
- **Rule CR-03 (Unthrottled Endpoint Exhaustion):** `AST Finding (Complex nested DB query)` + `Web Finding (Missing Rate Limiting)` = **HIGH Attack Path: Asymmetric DoS Resource Exhaustion**.

---

## 13. AI / LLM Layer Architecture

NSAT is engineered with strict AI guardrails: **The AI is an explainer and synthesizer, never a source of raw facts.**

### Responsibilities of the AI Layer
1. **Contextual Translation:** Translates technical AST call-chains and correlated attack graphs into plain-English executive explanations.
2. **Root-Cause Reasoning:** Explains *why* the vulnerability exists and how the architectural flaw enables exploitation.
3. **Patch Generation & Review:** Generates surgical diffs based on exact file AST contexts.

### Guardrails & Fact-Checking
Every AI-generated response enforces a rigid three-part output separation:
1. **`[OBSERVED FACT]`**: Explicit line numbers, AST sinks, ports, and configuration values extracted by the scanner.
2. **`[INFERENCE]`**: The synthesized risk, potential lateral movement, and contextual impact.
3. **`[RECOMMENDATION]`**: Concrete architectural or code remediation steps.

---

## 14. Remediation Agent & Verification Workflow

NSAT provides an autonomous, human-in-the-loop remediation workflow:

```
[ SCAN ] ────────> [ IDENTIFIED FINDING ]
                           │
                           ▼
                 [ REMEDIATION AGENT ]
                           │
        ┌──────────────────┴──────────────────┐
        ▼                                     ▼
 [ INLINE CODE FIX ]                [ CONFIGURATION FIX ]
 (e.g., Parameterized SQL)           (e.g., Bind to 127.0.0.1)
        │                                     │
        └──────────────────┬──────────────────┘
                           ▼
                 [ GENERATE DIFF PATCH ]
                           │
                           ▼
              [ USER INTERACTIVE APPROVAL ]
              (nsat fix NSAT-XXXX --apply)
                           │
                           ▼
                  [ APPLY SURGICAL PATCH ]
                           │
                           ▼
              [ TARGETED REGRESSION TEST ]
              (pytest / npm test / cargo test)
                           │
                           ▼
             [ VERIFY: RE-RUN RELEVANT SCAN ]
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
    [ PASS: CLOSED ]                [ FAIL: AUTO-ROLLBACK ]
 (Finding Marked RESOLVED)          (Original Code Restored)
```

- **Scope-Constrained Patches:** Remediation agents are restricted to editing the exact file and lines associated with the finding sink.
- **Automatic Rollback:** If unit tests fail or the re-scan shows the finding persists, NSAT automatically reverts the patch using git stash/diff mechanics.

---

## 15. Functional Requirements Matrix

| ID | Domain | Requirement Description | Priority |
| :--- | :--- | :--- | :--- |
| **FR-01** | Discovery | Detect C++, Java, Python, and JavaScript/TypeScript in mixed repos. | MVP (Must) |
| **FR-02** | AST Analysis | Parse ASTs without depending on variable or function naming conventions. | MVP (Must) |
| **FR-03** | Taint Flow | Track source-to-sink data flow for SQL, Command Injection, and Path Traversal. | MVP (Must) |
| **FR-04** | Secrets | Detect high-entropy API keys, JWT tokens, and private keys in code & configs. | MVP (Must) |
| **FR-05** | Dependencies | Audit package manifests against vulnerability databases (OSV/Advisories). | MVP (Must) |
| **FR-06** | Network Binding| Accurately identify services listening on `0.0.0.0` vs `127.0.0.1`. | MVP (Must) |
| **FR-07** | Containers | Audit Dockerfile and Compose files for root users and privileged mounts. | MVP (Must) |
| **FR-08** | Correlation | Generate an in-memory graph connecting code, network, and secret findings. | MVP (Must) |
| **FR-09** | Blast Radius | Compute post-compromise lateral movement paths and output a risk tier. | MVP (Must) |
| **FR-10** | Noise Control | Suppress vendor dirs, test fixtures, and duplicate scanner outputs. | MVP (Must) |
| **FR-11** | Autonomous Fix | Generate surgical diff patches for identified high/critical findings. | MVP (Must) |
| **FR-12** | Verification | Re-scan patched files automatically to verify issue eradication. | MVP (Must) |
| **FR-13** | Reporting | Render terminal dashboards and export JSON, Markdown, HTML, and SARIF. | MVP (Must) |
| **FR-14** | Offline First | Guarantee 100% functionality of scan, correlation, and fix without an LLM. | MVP (Must) |
| **FR-15** | AI Explainer | Pluggable interface for Ollama, DeepSeek, Gemma, and OpenAI explanations. | MVP (Must) |

---

## 16. Non-Functional Requirements

- **Performance & Latency:** Static audit of a 50,000-line repository must complete in under **15 seconds** locally.
- **Memory Footprint:** Resident memory usage must not exceed **512 MB** during standard codebase AST analysis.
- **Portability & Cross-Platform:** CLI must execute seamlessly across **Linux (Ubuntu 20.04+), macOS (Apple Silicon & Intel), and Windows (PowerShell & WSL)**.
- **Security & Safety:**
  - Network and host scanning routines must never crash target services or flood local buffers.
  - Active network scans require explicit CLI acknowledgement (`--authorized`).
  - No code or telemetry is transmitted to external servers unless the user explicitly configures a cloud LLM provider.

---

## 17. Security & Authorization Boundaries

1. **Local Filesystem Scope:** `nsat audit` is strictly sandboxed to the target directory. It will not inspect parent paths or external files unless explicitly symlinked.
2. **Authorized Network Scope Gate:** When executing `nsat network` or `nsat audit --target <URL>`, the CLI checks:
   - Is the target a local loopback (`127.0.0.1`, `localhost`)? -> Allowed.
   - Is the target an external IP/CIDR/URL? -> **Fails with authorization error** unless `--authorized` is explicitly provided.
3. **Safe Probing Bounds:** Web and network checks operate at a maximum rate of 10 requests per second with strict 3-second timeouts to prevent unintentional load or DoS.

---

## 18. Hackathon MVP Scope vs. Post-Hackathon Roadmap

```
+-----------------------------------------------------------------------------------------+
|                                HACKATHON MVP SCOPE                                      |
|                                                                                         |
| [Languages]      : Python, JavaScript/TypeScript, Java, C++                             |
| [AST Engines]    : Tree-sitter / Native AST parser adapters                            |
| [Scan Domains]   : Code SAST, Secrets, Dependencies, Network Bindings, Docker, Host     |
| [Features]       : Correlation Graph, Post-Compromise Blast Radius, Fix & Verify        |
| [Reporting]      : Rich Terminal UI, JSON, Markdown, SARIF                              |
| [AI Providers]   : Ollama (local), OpenAI-compatible, Gemma, DeepSeek                   |
+-----------------------------------------------------------------------------------------+
                                             │
                                             ▼
+-----------------------------------------------------------------------------------------+
|                                POST-HACKATHON ROADMAP                                   |
|                                                                                         |
| [Languages]      : Go, Rust, C#, Ruby, PHP, Swift, Kotlin                               |
| [Advanced SAST]  : Full inter-procedural call-graph synthesis across microservices      |
| [Cloud Scanners] : Live AWS/Azure/GCP cloud posture discovery (read-only IAM/VPC)       |
| [DAST Engine]    : Automated OpenAPI-driven fuzzing and authenticated session probing   |
| [IDE Extension]  : Real-time VS Code and JetBrains background audit extension           |
+-----------------------------------------------------------------------------------------+
```

---

## 19. Success Metrics & Judge Evaluation Criteria

1. **Deterministic Accuracy:** 100% detection rate on known vulnerability test cases in the demo repository regardless of variable name obfuscation.
2. **Zero-AI Dependency:** Complete execution of `audit`, `correlate`, `report`, and `verify` with the network interface disconnected.
3. **Correlation Value-Add:** Successfully links at least two independent domain findings into a unified, high-severity attack path.
4. **Remediation Precision:** `nsat fix` produces a valid, compile-ready patch that passes test suites and eliminates the finding upon re-scan.
5. **CLI Presentation:** Polished, responsive terminal aesthetics that provide immediate clarity to both technical and executive judges.

---

## 20. End-to-End Demo Script & Terminal Output

### Step 1: Capability Inspection
```bash
$ nsat doctor
```
```
[bold cyan]NSAT Doctor — System Capability Registry[/bold cyan]
├── AST Parsers:
│   ├── Python (Native ast + Tree-sitter)   [OK]
│   ├── JavaScript / TypeScript (Tree-sitter) [OK]
│   ├── Java (Tree-sitter)                  [OK]
│   └── C++ (Tree-sitter)                   [OK]
├── External Engines (Optional):
│   ├── Semgrep                             [AVAILABLE] (v1.65.0)
│   ├── Gitleaks                            [AVAILABLE] (v8.18.0)
│   ├── Trivy                               [AVAILABLE] (v0.49.1)
│   └── Nmap                                [AVAILABLE] (v7.94)
└── AI Reasoning Provider:
    └── Ollama (qwen2.5-coder:7b)           [READY / LOCAL]
```

### Step 2: Audit Execution
```bash
$ nsat audit ./demo-vuln-app
```
```
  _  _ ___   _ _____ 
 | \| / __| /_\_   _|  NETWORK SECURITY AUDIT & THREAT ASSESSMENT
 | .` \__ \/ _ \| |    v1.0.0 | Defensive Multi-Layer Security Platform
 |_|\_|___/_/ \_\_|  

[i] Target: ./demo-vuln-app
[i] Languages Discovered: Python (62%), TypeScript (28%), C++ (10%)
[i] Frameworks: FastAPI, React 18, Crow C++ Daemon
[i] Inferred Archetype: Web Application / REST API Microservice

[✔] AST Code Analysis Complete (14 files parsed)
[✔] Secret Analysis Complete (3 high-entropy tokens detected)
[✔] Dependency Audit Complete (2 known vulnerable packages)
[✔] Network Exposure Analysis Complete (2 listener bindings evaluated)
[✔] Docker & Host Inspection Complete (1 critical socket exposure)

================================================================================
CRITICAL FINDINGS & CORRELATED ATTACK PATHS
================================================================================

[!] ATTACK PATH #1: Direct Internet-to-Database Takeover
    Severity: CRITICAL | Confidence: 96%
    Chain:
      1. [AST SAST] Parameterized Query Bypass in handler2() (Python)
         File: src/api/handlers.py:42
         Evidence: Untrusted 'req_data' reaches raw cursor.execute()
      2. [SECRET] Hardcoded DB_PASSWORD in config/default.env:8
      3. [NETWORK] PostgreSQL listener bound to 0.0.0.0:5432
    Impact: Remote unauthenticated attacker can dump internal user records.

[!] ATTACK PATH #2: Container Escape to Host Takeover
    Severity: CRITICAL | Confidence: 99%
    Chain:
      1. [CONTAINER] Dockerfile runs as 'root' with /var/run/docker.sock mounted
      2. [AST SAST] Unsafe subprocess execution in a() (Python)
         File: src/utils/worker.py:19
    Impact: Arbitrary command injection grants immediate root access to the host.

================================================================================
POST-COMPROMISE BLAST RADIUS SUMMARY
================================================================================
Post-Compromise Tier: TIER 3 (HOST & INFRASTRUCTURE TAKEOVER)
Reachable Assets:
  - Production Database (172.18.0.2:5432) via leaked credentials
  - Host Operating System via /var/run/docker.sock socket breakout
  - Cloud Infrastructure via environment AWS_ACCESS_KEY_ID

Audit completed in 2.14s. 2 Critical, 3 High, 2 Medium findings.
Run 'nsat explain <ID>' for details or 'nsat fix <ID>' to remediate.
```

### Step 3: Surgical Remediation & Verification
```bash
$ nsat fix NSAT-PY-0042
```
```
[?] Finding: NSAT-PY-0042 (SQL Injection in src/api/handlers.py:42)
[i] Target Sink: cursor.execute(f"SELECT * FROM items WHERE id = '{x1}'")

[+] Proposed Surgical Remediation Patch:
--- a/src/api/handlers.py
+++ b/src/api/handlers.py
@@ -41,3 +41,3 @@
-    query = f"SELECT * FROM items WHERE id = '{x1}'"
-    cursor.execute(query)
+    query = "SELECT * FROM items WHERE id = %s"
+    cursor.execute(query, (x1,))

[?] Apply this remediation patch? [Y/n]: y
[✔] Patch successfully applied to src/api/handlers.py
[i] Executing test suite: pytest tests/test_handlers.py ... [PASSED]
[i] Re-scanning src/api/handlers.py ...
[✔] VERIFICATION PASSED: Finding NSAT-PY-0042 is ELIMINATED.
[✔] Zero regressions detected.
```
