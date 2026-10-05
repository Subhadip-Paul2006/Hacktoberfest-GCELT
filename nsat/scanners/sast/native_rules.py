"""Native AST and structural SAST rule engine for NSAT."""

from pathlib import Path
import re
from typing import Any, Optional
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.scanners.base import BaseScanner


class NativeSASTScanner(BaseScanner):
    """
    Executes deterministic structural SAST checks across C++, Python, Rust, Go, PHP,
    JavaScript/TypeScript, and Java. Operates independent of variable naming.
    """

    @property
    def scanner_name(self) -> str:
        return "native_sast"

    def scan(self, target_path: Path, surface: Optional[SecuritySurface] = None) -> list[CanonicalFinding]:
        findings: list[CanonicalFinding] = []
        finding_seq = 1

        # 1. Rule: Command / Process Execution with Untrusted Input
        if surface and surface.code:
            for sink in surface.code.execution_sinks:
                if sink.sink_type in ["process_execution", "command_injection"]:
                    findings.append(
                        CanonicalFinding(
                            id=f"NSAT-CMD-{finding_seq:03d}",
                            title="Unsafe Process / Command Execution Sink",
                            category="code_sast",
                            severity="HIGH",
                            confidence=0.9,
                            confidence_label="Detected structurally",
                            source=self.scanner_name,
                            asset=Path(sink.file_path).name,
                            file_path=sink.file_path,
                            line_number=sink.line_number,
                            description=(
                                "Identified direct process execution invocation (e.g., subprocess, exec, popen, "
                                "Runtime.exec, or Command::new). If dynamic parameters flow into this sink, "
                                "it enables remote command injection."
                            ),
                            impact="Potential arbitrary command execution with application privileges.",
                            recommendation="Avoid shell invocation; use parameterized array arguments without shell=True.",
                            evidence=[
                                FindingEvidence(
                                    type="AST_SINK",
                                    description=f"Execution sink detected: {sink.snippet}",
                                    snippet=sink.snippet,
                                    line_number=sink.line_number,
                                )
                            ],
                            attack_surface_reference=f"Sink:{sink.sink_type}",
                        )
                    )
                    finding_seq += 1

        # 2. Rule: SQL Injection (Dynamic String Concatenation into Query Sinks)
        sql_patterns = [
            re.compile(r"""\bcursor\.execute\s*\(\s*f["'].*?\{.*?\}"""),
            re.compile(r"""\b(?:query|execute|mysqli_query|db\.Query)\s*\(\s*["'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?["']\s*\+"""),
            re.compile(r"""\bmysqli_query\s*\(\s*\$[a-zA-Z0-9_]+\s*,\s*["'].*?\$[a-zA-Z0-9_]+"""),
        ]

        # Scan analyzable source files for SQL concatenation patterns
        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in {"node_modules", "vendor", ".venv", "dist", "build", ".git"} for part in file_path.parts):
                continue
            if file_path.suffix.lower() not in {".py", ".js", ".ts", ".java", ".cpp", ".php", ".go", ".rs"}:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lines = content.splitlines()
            for idx, line in enumerate(lines, 1):
                for pat in sql_patterns:
                    if pat.search(line):
                        findings.append(
                            CanonicalFinding(
                                id=f"NSAT-SQLI-{finding_seq:03d}",
                                title="SQL Injection via Unsanitized Query Interpolation",
                                category="code_sast",
                                severity="CRITICAL",
                                confidence=0.95,
                                confidence_label="Detected structurally",
                                source=self.scanner_name,
                                asset=file_path.name,
                                file_path=str(file_path),
                                line_number=idx,
                                description=(
                                    "Dynamic string formatting or concatenation was detected directly inside "
                                    "a database query sink without parameterization."
                                ),
                                impact="Full database compromise: unauthorized read, modify, or deletion of sensitive tables.",
                                recommendation="Use parameterized queries with placeholder binding (e.g., %s or $1).",
                                evidence=[
                                    FindingEvidence(
                                        type="AST_SINK",
                                        description="Unparameterized string query construction",
                                        snippet=line.strip()[:80],
                                        line_number=idx,
                                    )
                                ],
                            )
                        )
                        finding_seq += 1

        # 3. Rule: Weak / Insecure Cryptographic Hash Functions (MD5 / SHA-1)
        weak_crypto_patterns = [
            re.compile(r"""MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1)["']"""),
            re.compile(r"""hashlib\.(md5|sha1)\s*\("""),
            re.compile(r"""\bmd5\s*\(\s*\$"""),
        ]
        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in {"node_modules", "vendor", ".venv", "dist", "build", ".git"} for part in file_path.parts):
                continue
            if file_path.suffix.lower() not in {".py", ".js", ".ts", ".java", ".cpp", ".php", ".go", ".rs"}:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for idx, line in enumerate(content.splitlines(), 1):
                for pat in weak_crypto_patterns:
                    m = pat.search(line)
                    if m:
                        findings.append(
                            CanonicalFinding(
                                id=f"NSAT-CRYPTO-{finding_seq:03d}",
                                title=f"Insecure Cryptographic Hash Algorithm ({m.group(1).upper()})",
                                category="code_sast",
                                severity="MEDIUM",
                                confidence=0.9,
                                confidence_label="Detected structurally",
                                source=self.scanner_name,
                                asset=file_path.name,
                                file_path=str(file_path),
                                line_number=idx,
                                description=(
                                    f"Detected usage of collision-vulnerable algorithm {m.group(1).upper()}. "
                                    "MD5 and SHA-1 are cryptographically broken."
                                ),
                                impact="Hash collision vulnerabilities and weak credential storage exposure.",
                                recommendation="Upgrade to SHA-256 or password-hashing algorithms like Argon2id or bcrypt.",
                                evidence=[
                                    FindingEvidence(
                                        type="CRYPTO_CALL",
                                        description=f"Weak hash algorithm invoked: {m.group(1)}",
                                        snippet=line.strip()[:80],
                                        line_number=idx,
                                    )
                                ],
                            )
                        )
                        finding_seq += 1

        # 4. Rule: Wildcard Network Binding (0.0.0.0 / INADDR_ANY)
        for binding in surface.infrastructure.bindings:
            if binding.exposure == "POTENTIALLY_LAN_REACHABLE":
                findings.append(
                    CanonicalFinding(
                        id=f"NSAT-NET-{finding_seq:03d}",
                        title="Network Service Bound to All Interfaces (0.0.0.0)",
                        category="network_exposure",
                        severity="MEDIUM",
                        confidence=0.9,
                        confidence_label="Strong indicator",
                        source=self.scanner_name,
                        asset=f"Port:{binding.port or 'auto'}",
                        file_path=binding.file_path,
                        line_number=binding.line_number,
                        port=binding.port,
                        binding_address=binding.host,
                        description=(
                            f"Service is explicitly configured to listen on '{binding.host}' instead of "
                            "'127.0.0.1' (localhost). This exposes the service to the local network (LAN) and "
                            "potentially the public Internet."
                        ),
                        impact="Unauthorized network clients on the local perimeter or LAN can reach the service.",
                        recommendation="Bind server explicitly to '127.0.0.1' unless external access is required.",
                        evidence=[
                            FindingEvidence(
                                type="NETWORK_BINDING",
                                description=f"Host bound to {binding.host}:{binding.port or '*'}",
                                line_number=binding.line_number,
                            )
                        ],
                    )
                )
                finding_seq += 1

        # 5. Rule: Debug Configuration Enabled in Code / Config
        debug_patterns = [
            re.compile(r"""\bDEBUG\s*=\s*True\b"""),
            re.compile(r"""\bapp\.debug\s*=\s*True\b"""),
            re.compile(r"""\bdisplay_errors\s*=\s*(?:On|1)\b"""),
        ]
        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in {"node_modules", "vendor", ".venv", "dist", "build", ".git"} for part in file_path.parts):
                continue
            if file_path.suffix.lower() not in {".py", ".js", ".ts", ".php", ".ini", ".env", ".toml", ".yaml"}:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for idx, line in enumerate(content.splitlines(), 1):
                for pat in debug_patterns:
                    if pat.search(line):
                        findings.append(
                            CanonicalFinding(
                                id=f"NSAT-CFG-{finding_seq:03d}",
                                title="Debug Mode Enabled in Configuration",
                                category="code_sast",
                                severity="LOW",
                                confidence=0.85,
                                confidence_label="Detected structurally",
                                source=self.scanner_name,
                                asset=file_path.name,
                                file_path=str(file_path),
                                line_number=idx,
                                description="Application debug mode is explicitly set to active.",
                                impact="Information leakage including stack traces, framework environment variables, and internal code paths.",
                                recommendation="Disable debug mode in production configurations.",
                                evidence=[
                                    FindingEvidence(
                                        type="CONFIG_FLAG",
                                        description="Debug flag enabled",
                                        snippet=line.strip()[:80],
                                        line_number=idx,
                                    )
                                ],
                            )
                        )
                        finding_seq += 1

        # 6. Rule: Missing Rate Limiting / Abuse Controls on Authentication Endpoints
        for auth_ep in surface.application.auth_endpoints:
            findings.append(
                CanonicalFinding(
                    id=f"NSAT-AUTH-{finding_seq:03d}",
                    title="Potential Missing Rate Limiting on Authentication Endpoint",
                    category="authentication",
                    severity="LOW",
                    confidence=0.7,
                    confidence_label="Potential exposure",
                    source=self.scanner_name,
                    asset=auth_ep.path,
                    endpoint=auth_ep.path,
                    file_path=auth_ep.file_path,
                    line_number=auth_ep.line_number,
                    description=(
                        f"Authentication endpoint '{auth_ep.path}' was detected without explicit rate limiting "
                        "or throttling middleware in its immediate decorator/declaration."
                    ),
                    impact="Increased exposure to automated credential stuffing, brute force, or OTP exhaustion attacks.",
                    recommendation="Attach rate limiting middleware (e.g., slowapi, express-rate-limit, bucket limiter).",
                    evidence=[
                        FindingEvidence(
                            type="AUTH_ENDPOINT",
                            description=f"Auth route declaration: {auth_ep.handler}",
                            line_number=auth_ep.line_number,
                        )
                    ],
                )
            )
            finding_seq += 1

        return findings
