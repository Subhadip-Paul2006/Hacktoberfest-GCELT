# Technical Requirements Document (TRD)
# NSAT — Network Security Audit & Threat Assessment

---

## Document Metadata
- **System Name:** NSAT (Network Security Audit & Threat Assessment)
- **Document Version:** 1.0.0
- **Target Implementation Stack:** Python 3.11+, Click/Typer, Rich, Tree-sitter, Pydantic v2, NetworkX, AsyncIO
- **Core Pipeline:** `SCAN → NORMALIZE → CORRELATE → ANALYZE → EXPLAIN → REMEDIATE → VERIFY`
- **Document Status:** Approved Technical Specification for Direct Implementation

---

## 1. Technical Overview & System Goals

NSAT is a modular, CLI-first defensive cybersecurity auditing, attack-path correlation, and automated remediation engine. The system is architected to perform deterministic multi-layer audits across:
1. Static code (AST-based semantic analysis for C++, Java, Python, JavaScript, TypeScript)
2. Secrets & high-entropy tokens
3. Third-party software supply chains & package manifests
4. Local & container network bindings (`127.0.0.1` vs `0.0.0.0`)
5. Host runtime processes, persistence, and filesystem mounts
6. Container configurations (Dockerfiles, Compose manifests)
7. Potential malware & abuse indicators
8. Post-compromise lateral movement & blast radius

The technical design guarantees that:
- **No reliance on identifier naming conventions:** AST node types, structural syntax patterns, and source-to-sink data flow drive vulnerability identification.
- **Zero-AI Hard Dependency:** Full static analysis, finding normalization, graph-based attack path correlation, risk scoring, reporting, and deterministic rule-based patch proposals operate completely offline without an LLM.
- **Pluggable Architecture:** Scanners, language analyzers, risk scoring rules, LLM providers, and reporters are decoupled via clean abstract base classes.

---

## 2. System Architecture & Pipeline Data Flow

The NSAT system executes a seven-stage linear-deterministic pipeline with a feedback loop for verification:

```
[ CLI INGRESS / USER INPUT ]
             │
             ▼
  ┌───────────────────────────────────────────────────────────────┐
  │ 1. TARGET & SCOPE MANAGER                                     │
  │    - Validates target filesystem, URL, or CIDR                │
  │    - Enforces authorization gates for active network probes   │
  └──────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
  ┌───────────────────────────────────────────────────────────────┐
  │ 2. DISCOVERY & CLASSIFICATION ENGINE                          │
  │    - Language detection (bytes, extensions, AST sanity)       │
  │    - Framework & project archetype inference                  │
  └──────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
  ┌───────────────────────────────────────────────────────────────┐
  │ 3. SCANNER ORCHESTRATOR & CAPABILITY REGISTRY                 │
  │    ├── AST Analyzers (C++, Java, Python, JS/TS)               │
  │    ├── Native Secret & Entropy Scanners                       │
  │    ├── Supply Chain / Lockfile Analyzers                      │
  │    ├── Host / OS Process & Socket Collectors                  │
  │    ├── Docker / Container Configuration Auditors              │
  │    └── External Engine Wrappers (Semgrep, Trivy, Nmap, etc.)  │
  └──────────────────────────────┬────────────────────────────────┘
                                 │ (Raw Heterogeneous Findings)
                                 ▼
  ┌───────────────────────────────────────────────────────────────┐
  │ 4. FINDING NORMALIZATION & DEDUPLICATION                      │
  │    - Transforms raw scanner outputs into CanonicalFinding     │
  │    - Noise suppression (vendor dirs, tests, harmless constants│
  │    - Structural hashing & de-duplication                      │
  └──────────────────────────────┬────────────────────────────────┘
                                 │ (Canonical Normalized Findings)
                                 ▼
  ┌───────────────────────────────────────────────────────────────┐
  │ 5. ATTACK GRAPH & CORRELATION ENGINE                          │
  │    - Builds in-memory directed graph (NetworkX)               │
  │    - Synthesizes multi-domain attack paths                    │
  │    - Computes Post-Compromise Blast Radius                    │
  │    - Calculates contextual risk score                         │
  └──────────────────────────────┬────────────────────────────────┘
                                 │ (Correlated Attack Surface Model)
                                 ▼
  ┌───────────────────────────────────────────────────────────────┐
  │ 6. AI EXPLANATION & REPORTING LAYER                           │
  │    - Optional LLM Provider (Ollama, DeepSeek, Gemma, OpenAI)  │
  │    - Enforces [FACT], [INFERENCE], [RECOMMENDATION] bounds    │
  │    - Emits Rich Terminal UI, JSON, Markdown, SARIF, HTML      │
  └──────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
  ┌───────────────────────────────────────────────────────────────┐
  │ 7. REMEDIATION & VERIFICATION LOOP                            │
  │    - Surgical AST/diff patch generation (`nsat fix`)          │
  │    - User interactive approval                                │
  │    - Applies diff patch and runs local test suite             │
  │    - Triggers targeted re-scan to VERIFY resolution           │
  │    - Auto-rollback if regression detected                     │
  └───────────────────────────────────────────────────────────────┘
```

---

## 3. Component Architecture & Modules

```
nsat/
├── __init__.py
├── cli/                        # CLI command definitions & entry points
│   ├── main.py                 # Root CLI dispatcher
│   ├── commands/               # Subcommands: audit, host, network, fix, verify, etc.
│   └── ui/                     # Rich terminal layout, tables, progress spinners
├── core/                       # Core execution engine
│   ├── engine.py               # Pipeline orchestrator
│   ├── scope.py                # Authorization & boundary management
│   ├── discovery.py            # Project archetype & language discovery
│   └── capability.py           # Scanner capability registry
├── analyzers/                  # Language AST & structural analyzers
│   ├── base.py                 # LanguageAnalyzer abstract interface
│   ├── cpp/                    # C++ Tree-sitter analyzer
│   ├── java/                   # Java Tree-sitter analyzer
│   ├── python/                 # Python native ast + Tree-sitter analyzer
│   └── javascript_typescript/  # JS/TS Tree-sitter analyzer
├── scanners/                   # Domain-specific scanner implementations
│   ├── base.py                 # BaseScanner interface
│   ├── sast/                   # Custom AST rule runner
│   ├── secrets/                # High-entropy & regex token scanner
│   ├── dependencies/           # Manifest & OSV CVE matcher
│   ├── network/                # Socket binding & port auditor
│   ├── host/                   # OS process, persistence & permissions auditor
│   ├── container/              # Dockerfile & Docker compose auditor
│   ├── web/                    # HTTP header, cookie & CORS runtime prober
│   └── external/               # Adapters for Semgrep, Trivy, Nmap, Gitleaks
├── correlation/                # Graph correlation & blast radius
│   ├── graph.py                # Attack surface graph data structure
│   ├── rules.py                # Cross-domain correlation rules
│   ├── blast_radius.py         # Post-compromise exposure calculator
│   └── risk.py                 # Contextual risk engine
├── normalization/              # Schema validation & noise filtering
│   ├── models.py               # CanonicalFinding Pydantic schema
│   ├── deduplication.py        # Hashing & duplicate suppression
│   └── noise_filter.py         # Vendor/test/boilerplate suppression
├── remediation/                # Patch generation & verification
│   ├── agent.py                # Remediation patch planner
│   ├── patcher.py              # Surgical unified diff applier
│   └── verifier.py             # Re-scan & test execution engine
├── ai/                         # Optional LLM integration
│   ├── provider.py             # LLMProvider abstract interface
│   ├── ollama.py               # Local Ollama adapter
│   ├── openai_compatible.py    # OpenAI/DeepSeek/vLLM adapter
│   └── prompts.py              # Zero-hallucination structured prompt templates
├── knowledge/                  # Static security rules & signatures
│   ├── rules/                  # YAML/JSON rules by category
│   └── signatures/             # YARA & high-entropy secret patterns
└── reporting/                  # Output generators
    ├── terminal.py             # Rich visual dashboard
    ├── json_exporter.py        # Machine-readable output
    ├── markdown_exporter.py    # Formatted executive summary
    └── sarif_exporter.py       # OASIS SARIF v2.1.0 standard exporter
```

---

## 4. Language Analyzer Architecture & AST Strategy

### 4.1 Tree-sitter Grammar Strategy
To guarantee complete independence from identifier naming conventions, NSAT adopts **Tree-sitter** as the universal multi-language parsing engine, paired with Python's native `ast` module where applicable.

- **Grammars Bundled:** `tree_sitter_python`, `tree_sitter_javascript`, `tree_sitter_typescript`, `tree_sitter_java`, `tree_sitter_cpp`.
- **Query Mechanism:** Tree-sitter S-expression queries are executed against the concrete syntax tree to isolate nodes of interest based on syntax role rather than variable names.

### 4.2 Semantic Source-to-Sink Data Flow Analysis
NSAT detects security vulnerabilities even when variable names are completely obfuscated (`a`, `tmp1`, `handler2`).

```
[ UNTRUSTED SOURCE NODE ]
(e.g., HTTP route parameter, Request body, query string, env var)
                │
                ▼ (Variable assignment / passing as parameter)
[ TRACKED TAINT SYMBOL ] ──(No sanitization/parameterization node found)──┐
                │                                                         │
                ▼                                                         ▼
[ INTERMEDIATE TRANSFORMATION ]                              [ DANGEROUS SINK NODE ]
(e.g., String format / concatenation)                        (e.g., cursor.execute(),
                │                                             subprocess.Popen(),
                └────────────────────────────────────────────> system(), eval(), send())
```

#### Language Detection Matrix
- **Python:** Identifies FastAPI (`@app.get(...)`), Flask (`@app.route(...)`), Django (`urlpatterns = [...]`), raw `socket.bind(...)`.
- **JavaScript / TypeScript:** Identifies Express (`app.get(...)`, `router.post(...)`), NestJS (`@Get(...)`), Fastify, Next.js API routes (`export default function handler(...)`).
- **Java:** Identifies Spring Boot (`@GetMapping`, `@PostMapping`, `@RestController`), Servlet APIs (`doGet`, `doPost`), JAX-RS.
- **C++:** Identifies Crow (`CROW_ROUTE(app, ...)`), Drogon, Boost.Beast HTTP handlers, raw POSIX sockets (`bind(sockfd, ...)`).

---

## 5. Canonical Finding Schema

Every scanner, whether native AST or external engine wrapper, must emit findings into the immutable `CanonicalFinding` model.

### 5.1 JSON Schema Specification
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "NSATCanonicalFinding",
  "type": "object",
  "required": [
    "id",
    "category",
    "severity",
    "confidence",
    "title",
    "asset",
    "source_scanner",
    "evidence",
    "recommendation"
  ],
  "properties": {
    "id": { "type": "string", "pattern": "^NSAT-[A-Z0-9-]+$" },
    "category": {
      "type": "string",
      "enum": [
        "code_sast",
        "secret",
        "dependency",
        "network_exposure",
        "web_security",
        "authentication",
        "dos_resource",
        "host_security",
        "container_security",
        "malware_indicator",
        "blast_radius"
      ]
    },
    "severity": {
      "type": "string",
      "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    },
    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
    "title": { "type": "string" },
    "description": { "type": "string" },
    "asset": { "type": "string" },
    "source_scanner": { "type": "string" },
    "language": { "type": ["string", "null"] },
    "framework": { "type": ["string", "null"] },
    "file_path": { "type": ["string", "null"] },
    "line_start": { "type": ["integer", "null"] },
    "line_end": { "type": ["integer", "null"] },
    "column_start": { "type": ["integer", "null"] },
    "column_end": { "type": ["integer", "null"] },
    "endpoint": { "type": ["string", "null"] },
    "port": { "type": ["integer", "null"] },
    "protocol": { "type": ["string", "null"] },
    "binding_address": { "type": ["string", "null"] },
    "evidence": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "type": { "type": "string" },
          "description": { "type": "string" },
          "snippet": { "type": "string" },
          "context": { "type": "object" }
        },
        "required": ["type", "description"]
      }
    },
    "related_findings": {
      "type": "array",
      "items": { "type": "string" }
    },
    "attack_path": {
      "type": "array",
      "items": { "type": "string" }
    },
    "impact": { "type": "string" },
    "recommendation": { "type": "string" },
    "remediation": {
      "type": "object",
      "properties": {
        "patch_available": { "type": "boolean" },
        "suggested_diff": { "type": ["string", "null"] },
        "strategy": { "type": "string" }
      }
    },
    "verification_status": {
      "type": "string",
      "enum": ["UNVERIFIED", "VERIFIED_FIXED", "REGRESSION_DETECTED", "WONT_FIX"],
      "default": "UNVERIFIED"
    }
  }
}
```

---

## 6. Deduplication & Noise Suppression Engine

### 6.1 Structural Deduplication
When multiple engines run (e.g., Native AST scanner and Semgrep), duplicate findings are eliminated using a deterministic **Finding Signature Hash**:

$$\text{SignatureHash} = \text{SHA256}(\text{Category} \parallel \text{NormFilePath} \parallel \text{LineRange} \parallel \text{SinkType} \parallel \text{CWE})$$

If two findings share a Signature Hash:
1. The finding with the higher `confidence` score is retained.
2. The `source_scanner` field is appended with the secondary scanner name (e.g., `native_ast + semgrep`).
3. Evidence arrays are merged.

### 6.2 Noise Suppression Rules
Findings are filtered out if they match any of the following deterministic noise conditions:
- **Path Exclusion:** File matches `/(node_modules|vendor|\.venv|dist|build|target|\.git)/`.
- **Test File Heuristic:** File is in `test/`, `tests/`, `spec/`, or matches `*_test.py` **AND** does not contain active network listener bindings or hardcoded private keys.
- **Harmless Constant Filter:** String literals flagged by secret scanner that match common test stubs (`password`, `admin`, `123456`, `test`, `localhost`, `example.com`) without a corresponding high Shannon entropy score ($H < 3.2$).

---

## 7. Security Correlation Engine & Attack Graph

The Correlation Engine represents findings as nodes in a directed graph using **NetworkX** to synthesize cross-layer attack paths.

### 7.1 Attack Graph Structure
- **Nodes ($V$):**
  - `FindingNode(id, type, severity)`
  - `AssetNode(name, type: file|socket|secret|db|container)`
  - `NetworkNode(ip, port, exposure: LOCAL|LAN|PUBLIC)`
- **Edges ($E$):**
  - `EXPOSES(NetworkNode -> AssetNode)`
  - `AUTHENTICATES_WITH(AssetNode -> SecretNode)`
  - `CAN_ACCESS(FindingNode -> AssetNode)`
  - `LEADS_TO(FindingNode -> FindingNode)`

### 7.2 Correlation Synthesizer Implementation
```python
class CorrelationEngine:
    def __init__(self, findings: list[CanonicalFinding]):
        self.findings = findings
        self.graph = nx.DiGraph()

    def build_graph(self):
        # 1. Populate asset and network nodes
        for f in self.findings:
            self.graph.add_node(f.id, data=f, node_type="finding")
            if f.file_path:
                self.graph.add_node(f.file_path, node_type="asset_file")
                self.graph.add_edge(f.id, f.file_path, relation="LOCATED_IN")
            if f.port is not None:
                net_id = f"{f.binding_address or '0.0.0.0'}:{f.port}"
                self.graph.add_node(net_id, node_type="network_endpoint")
                self.graph.add_edge(f.id, net_id, relation="BOUND_TO")

    def synthesize_attack_paths(self) -> list[AttackPath]:
        paths = []
        # Correlation Rule: Public Network Ingress -> Code Injection -> Exposed Secret -> Lateral Database
        ingress_nodes = [n for n, d in self.graph.nodes(data=True) 
                         if d.get("node_type") == "network_endpoint" and "0.0.0.0" in n]
        
        # Traverse reachable paths to secret or database assets
        for ingress in ingress_nodes:
            # Graph search algorithms synthesize unified attack vectors
            ...
        return paths
```

---

## 8. Post-Compromise Blast Radius Engine

The Blast Radius engine evaluates what resources become reachable if an adversary gains local code execution on the host or in a container container.

### 8.1 Asset Reachability Matrix
The engine inspects:
1. **Readable Filesystem Secrets:** Scans for `.env`, `id_rsa`, `credentials.json`, `kubeconfig` accessible under current user UID/GID.
2. **Container IPC & Sockets:** Scans for `/var/run/docker.sock`, `/run/containerd/containerd.sock`, pod service account tokens (`/var/run/secrets/kubernetes.io/serviceaccount`).
3. **Internal Network Routes:** Active routes to Docker bridge (`172.17.0.0/16`), Kubernetes cluster IPs (`10.96.0.0/12`), or local loopback databases.
4. **Environment Variables:** Inspects `/proc/$PID/environ` or local parent process environment for `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, `STRIPE_KEY`.

### 8.2 Blast Radius Calculation
$$\text{BlastRadiusScore} = \sum (\text{AssetWeight} \times \text{ExposureMultiplier})$$

- Host Root Socket Mounted (`/var/run/docker.sock`): **Weight 10.0 (Tier 3 Critical)**
- Cloud Infrastructure Master Keys (`AWS_SECRET_ACCESS_KEY`): **Weight 9.0 (Tier 3 Critical)**
- Production Database Credentials: **Weight 7.5 (Tier 2 High)**
- Read-Only App Assets: **Weight 2.0 (Tier 1 Low)**

---

## 9. Contextual Risk Engine

NSAT replaces naive vulnerability counting with a **Contextual Risk Score ($0.0 - 100.0$)**:

$$\text{FinalRisk} = \min \left( 100.0, \; \sum_{i=1}^{N} \left( \text{BaseSeverity}(f_i) \times \text{Confidence}(f_i) \times \text{ReachabilityMultiplier}(f_i) \times \text{BlastRadiusMultiplier} \right) \right)$$

### Multipliers
- **Reachability Multiplier:**
  - Bound to `127.0.0.1` (Local Only): `0.6`
  - Bound to `LAN Interface` (Local Network): `1.0`
  - Bound to `0.0.0.0` or Public Interface: `1.8`
- **Blast Radius Multiplier:**
  - Tier 1 (Localized): `1.0`
  - Tier 2 (Service/Data Exposure): `1.3`
  - Tier 3 (Host/Cluster Takeover): `1.7`

---

## 10. Scanner Plugin Architecture & Capability Registry

External tools enhance NSAT but are never mandatory. The **Capability Registry** probes tool availability at runtime and seamlessly falls back to native Python/Tree-sitter analyzers.

### 10.1 Registry Table

| Tool Name | Capability Provided | Fallback Behavior if Tool Missing |
| :--- | :--- | :--- |
| **Tree-sitter** | Multi-language AST Parsing | Fallback to Python native `ast` for Python; regex/token for others |
| **Semgrep** | Advanced SAST Rule Matching | NSAT Native AST Pattern Matcher |
| **Gitleaks** | Git History Secret Scanning | NSAT Native Entropy & Token Scanner on Working Tree |
| **Trivy / OSV** | Dependency CVE Matching | NSAT Offline JSON Advisory DB Matcher |
| **Nmap** | Advanced Network Port/Service Discovery | Native Python `asyncio` Non-Blocking TCP Socket Prober |
| **osquery / Lynis** | Deep Host OS Process & Configuration Audit | Native `psutil` + `/proc` + OS Registry Inspector |
| **YARA** | Malware Binary & String Matching | Native Hex/Regex Signature Matcher |

---

## 11. Remediation Engine & Verification Loop

### 11.1 Surgical Patch Strategy
To prevent hallucinated or breaking code rewrites, the Remediation Engine generates **minimal Unified Diffs**:
1. Locates the exact AST Node corresponding to the vulnerable sink.
2. Applies pre-tested, deterministic remediation templates (e.g., parameterizing an SQL query or converting `shell=True` to `shell=False` with an argument list).
3. If LLM assistance is enabled, passes only the specific function AST slice (not the whole file) with a strict prompt requiring valid diff syntax.

### 11.2 Verification Engine Flow
```python
class VerificationEngine:
    def verify_remediation(self, finding: CanonicalFinding, original_file: Path) -> VerificationResult:
        # Step 1: Run local test suite to detect regressions
        test_result = self.run_test_suite()
        if not test_result.passed:
            self.rollback_patch(original_file)
            return VerificationResult(status="REGRESSION_DETECTED", error=test_result.error)

        # Step 2: Trigger targeted re-scan on patched file
        re_scan_findings = self.scanner_orchestrator.scan_single_file(original_file)
        
        # Step 3: Check if original finding signature is eliminated
        for f in re_scan_findings:
            if f.signature_hash == finding.signature_hash:
                self.rollback_patch(original_file)
                return VerificationResult(status="STILL_VULNERABLE")

        return VerificationResult(status="VERIFIED_FIXED")
```

---

## 12. Host, Network, Container & Malware Indicators

### 12.1 Host Security Collector (`nsat host`)
- **Process & Socket Auditor:** Uses `psutil` to iterate all active processes, resolving their command line, running user UID, active TCP/UDP listeners, and open file descriptors.
- **Persistence Checks:**
  - Linux: `/etc/cron*`, `/var/spool/cron`, `/etc/systemd/system/`.
  - Windows: Registry Run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`), Scheduled Tasks.
  - macOS: `~/Library/LaunchAgents`, `/Library/LaunchDaemons`.

### 12.2 Network Auditor (`nsat network`)
- **Strict Scope Gate:** Validates targets against user-supplied CIDR blocks. Fails immediately if an external IP is targeted without `--authorized`.
- **Non-Destructive TCP Connect Probing:** Uses non-blocking `asyncio.open_connection` with a 1.5-second timeout and 100 concurrent workers maximum to discover open ports without triggering firewall alarms or disrupting local services.

### 12.3 Container Auditor (`nsat audit` / `nsat host`)
- **Dockerfile Parser:** Inspects `USER` directive (flags default root), `HEALTHCHECK` (missing health check), `EXPOSE` (insecure ports).
- **Compose Auditor:** Inspects `docker-compose.yml` for `privileged: true`, `network_mode: host`, `pid: host`, and dangerous volume mounts (`/var/run/docker.sock:/var/run/docker.sock`).

### 12.4 Malware & Abuse Indicator Engine
- **Keylogger Indicator:** Flags processes that open `/dev/input/event*` on Linux, invoke `SetWindowsHookEx` on Windows, or import `pynput` / `keyboard` libraries in unsigned script contexts.
- **Ransomware / Tampering Indicator:** Monitors directory file modification bursts (>100 files modified per second with sudden Shannon entropy jumps $H > 7.5$) using non-blocking filesystem watchers (`watchfiles` / `inotify`).

---

## 13. AI / LLM Provider Abstraction

NSAT decouples AI logic through the `LLMProvider` abstract base class.

```python
class LLMProvider(ABC):
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider endpoint and credentials are functional."""
        pass

    @abstractmethod
    def explain_finding(self, finding: CanonicalFinding, code_context: str) -> AIExplanation:
        """Generate structured explanation separating Fact, Inference, and Recommendation."""
        pass

    @abstractmethod
    def propose_patch(self, finding: CanonicalFinding, code_context: str) -> str:
        """Generate minimal, syntactically valid unified diff."""
        pass
```

### Supported Providers
1. **Ollama (Local Default):** `http://localhost:11434` (Models: `qwen2.5-coder:7b`, `deepseek-r1:8b`, `gemma2:9b`).
2. **OpenAI-Compatible Endpoint:** Any standard v1 completions/chat endpoint (OpenAI, DeepSeek API, Groq, local vLLM).
3. **No-AI Deterministic Engine:** Generates rule-based explanations and templated fixes when no LLM is present.

---

## 14. Configuration, Scope & Storage

### 14.1 Configuration File (`nsat.toml` / `~/.nsat/config.toml`)
```toml
[scan]
max_threads = 8
file_size_limit_mb = 10
exclude_paths = ["node_modules", "vendor", ".venv", "dist", "target"]

[authorization]
authorized_networks = ["127.0.0.1/32", "192.168.1.0/24"]
require_explicit_confirmation = true

[ai]
enabled = false
provider = "ollama"
endpoint = "http://localhost:11434"
model = "qwen2.5-coder:7b"
temperature = 0.1

[thresholds]
fail_on_severity = "HIGH"
max_acceptable_risk_score = 45.0
```

### 14.2 Local Storage & Cache
- Database: Embedded SQLite (`~/.nsat/nsat_cache.db`) for caching AST hashes, OSV vulnerability entries, and previous scan diffs.
- Cache Validity: SHA-256 file hashes prevent re-parsing unchanged files during continuous runs (`nsat monitor`).

---

## 15. Concrete Data Contracts & Interfaces (Python Specification)

```python
from abc import ABC, abstractmethod
from pathlib import Path
from pydantic import BaseModel, Field
from typing import Optional, Any

class CodeLocation(BaseModel):
    file_path: Path
    line_start: int
    line_end: int
    column_start: Optional[int] = None
    column_end: Optional[int] = None

class FindingEvidence(BaseModel):
    type: str  # e.g., "AST_SINK", "RAW_SECRET", "NETWORK_BINDING"
    description: str
    snippet: Optional[str] = None
    context: dict[str, Any] = Field(default_factory=dict)

class CanonicalFinding(BaseModel):
    id: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    description: str
    asset: str
    source_scanner: str
    language: Optional[str] = None
    framework: Optional[str] = None
    location: Optional[CodeLocation] = None
    endpoint: Optional[str] = None
    port: Optional[int] = None
    binding_address: Optional[str] = None
    evidence: list[FindingEvidence] = Field(default_factory=list)
    related_findings: list[str] = Field(default_factory=list)
    attack_path: list[str] = Field(default_factory=list)
    impact: str
    recommendation: str
    suggested_diff: Optional[str] = None
    verification_status: str = "UNVERIFIED"

class LanguageAnalyzer(ABC):
    @abstractmethod
    def detect(self, repo_path: Path) -> dict[str, float]:
        """Return confidence score (0.0 - 1.0) for presence of language."""
        pass

    @abstractmethod
    def parse_structure(self, file_path: Path) -> dict[str, Any]:
        """Extract AST, endpoints, sources, and sinks without using variable names."""
        pass

    @abstractmethod
    def analyze_security(self, file_path: Path) -> list[CanonicalFinding]:
        """Apply language-specific structural security rules."""
        pass
```

---

## 16. Reproducible Deterministic Demo Environment

The implementation will bundle a reference test application in `/tests/demo-vuln-app` to guarantee 100% deterministic test execution for hackathon judges:

```
demo-vuln-app/
├── Dockerfile                  # Runs as root, exposes port 8000, mounts docker.sock
├── docker-compose.yml          # Binds postgres to 0.0.0.0:5432
├── config/
│   └── default.env             # Leaks DB_PASSWORD and AWS_SECRET_ACCESS_KEY
├── src/
│   ├── api/
│   │   ├── handlers.py         # AI-generated FastAPI handlers (a(), b(), handler2())
│   │   │                       # Contains SQL injection in handler2()
│   │   └── routes.ts           # React/TS frontend with hardcoded API token
│   ├── worker/
│   │   └── task_runner.cpp     # C++ Crow worker with unsafe popen/system call
│   └── service/
│       └── AuthService.java    # Spring Boot auth with MD5 password hashing
└── tests/
    └── test_handlers.py        # Valid unit tests for automated verification
```

---

## 17. Packaging & Cross-Platform Considerations

- **Distribution Format:** Packaged as a standard Python package via `pyproject.toml` (managed with Hatch / Poetry / pip).
- **Binary Distribution:** Can be compiled into a standalone binary using PyInstaller or PyOxidizer for zero-dependency execution.
- **Cross-Platform OS Handling:**
  - Path normalization uses `pathlib.Path` with forward slashes for finding signatures across Windows, macOS, and Linux.
  - Sockets and process inspections adapt to platform APIs (`/proc` on Linux, Win32 API on Windows, `sysctl` on macOS).

---

## 18. Step-by-Step Implementation Sequence

A coding agent or engineer must follow this precise implementation sequence:

```
PHASE 1: Core Foundation & Domain Schemas
  1.1 Define Pydantic models in normalization/models.py (CanonicalFinding, Evidence, Location).
  1.2 Implement CLI entry point with Click/Typer and Rich formatting in cli/main.py.
  1.3 Build Scope & Target Manager in core/scope.py (enforce authorization bounds).

PHASE 2: Discovery & AST Analyzers
  2.1 Implement Project & Language Discovery in core/discovery.py.
  2.2 Build Tree-sitter wrapper & language adapters for Python, JS/TS, Java, and C++.
  2.3 Implement structural taint & source-to-sink matching independent of variable names.

PHASE 3: Multi-Domain Scanners
  3.1 Build Secret & Entropy Scanner in scanners/secrets/.
  3.2 Build Dependency Lockfile Auditor in scanners/dependencies/.
  3.3 Build Network Socket & Binding Inspector in scanners/network/.
  3.4 Build Dockerfile & Container Auditor in scanners/container/.
  3.5 Build Host Process & Persistence Inspector in scanners/host/.

PHASE 4: Correlation, Blast Radius & Deduplication
  4.1 Implement Deduplication & Noise Filter in normalization/.
  4.2 Build NetworkX Attack Surface Graph in correlation/graph.py.
  4.3 Implement Cross-Domain Attack Path Synthesis in correlation/rules.py.
  4.4 Build Post-Compromise Blast Radius Calculator in correlation/blast_radius.py.
  4.5 Implement Contextual Risk Scoring Engine in correlation/risk.py.

PHASE 5: Remediation, Verification & AI
  5.1 Build Surgical Patch Generator in remediation/patcher.py.
  5.2 Build Verification & Re-scan Engine in remediation/verifier.py.
  5.3 Implement LLM Provider Interface with Ollama & OpenAI fallback in ai/.
  5.4 Build Multi-Format Exporters (Terminal, JSON, Markdown, SARIF) in reporting/.

PHASE 6: Demo Application & Verification
  6.1 Populate tests/demo-vuln-app with multi-language test cases.
  6.2 Execute end-to-end integration tests confirming 100% deterministic detection & verification.
```
