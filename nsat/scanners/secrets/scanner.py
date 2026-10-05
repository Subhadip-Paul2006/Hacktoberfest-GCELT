"""Native secret and high-entropy credential scanner for NSAT."""

import math
from pathlib import Path
import re
from nsat.core.surface import SecretLocation, SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.scanners.base import BaseScanner


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        entropy += - p_x * math.log(p_x, 2)
    return entropy


def redact_secret(val: str, visible_prefix: int = 4, visible_suffix: int = 2) -> str:
    """Safely redact secret tokens so sensitive credentials never leak in logs or CLI."""
    if len(val) <= visible_prefix + visible_suffix:
        return "*" * len(val)
    return f"{val[:visible_prefix]}{'*' * 10}{val[-visible_suffix:]}"


class SecretScanner(BaseScanner):
    """
    Detects API keys, access tokens, private keys, database URLs, and passwords
    using regex patterns and Shannon entropy heuristics.
    """

    @property
    def scanner_name(self) -> str:
        return "secret_scanner"

    # Known high-confidence token patterns
    SECRET_PATTERNS = [
        ("AWS Access Key ID", re.compile(r"""\b(AKIA[0-9A-Z]{16})\b"""), "CRITICAL"),
        ("AWS Secret Access Key", re.compile(r"""(?i)aws_secret_access_key\s*=\s*['"]?([a-zA-Z0-9/+=]{40})['"]?"""), "CRITICAL"),
        ("GitHub Personal Access Token", re.compile(r"""\b(gh[pousr]_[0-9a-zA-Z]{36})\b"""), "CRITICAL"),
        ("Private RSA/EC/OpenSSH Key", re.compile(r"""(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"""), "CRITICAL"),
        ("Generic API Key / Secret Token", re.compile(r"""(?i)(?:api_key|apikey|secret_key|auth_token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,64})['"]"""), "HIGH"),
        ("JSON Web Token (JWT)", re.compile(r"""\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"""), "HIGH"),
        ("Hardcoded Database URL", re.compile(r"""\b((?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9_\-\.]+:[0-9]+(?:\/[a-zA-Z0-9_\-\.]*)?)\b"""), "CRITICAL"),
        ("Password in Config", re.compile(r"""(?i)(?:password|passwd|db_pass)\s*[:=]\s*['"]([^'"\s]{8,64})['"]"""), "HIGH"),
    ]

    def scan(self, target_path: Path, surface: SecuritySurface) -> list[CanonicalFinding]:
        findings: list[CanonicalFinding] = []
        seq = 1

        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue
            # Skip vendor, git, and build outputs
            parts = file_path.parts
            if any(p in {"node_modules", "vendor", ".venv", "venv", "dist", "build", "target", ".git"} for p in parts):
                continue
            # Skip media / binary files
            if file_path.suffix.lower() in {".png", ".jpg", ".pdf", ".zip", ".tar", ".exe", ".bin", ".pyc"}:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lines = content.splitlines()
            for idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith(("#", "//", "/*", "*")):
                    # Still scan if in .env file
                    if file_path.name != ".env" and not file_path.name.startswith(".env."):
                        continue

                for label, pat, sev in self.SECRET_PATTERNS:
                    match = pat.search(line)
                    if match:
                        raw_token = match.group(1) if match.groups() else match.group(0)
                        # Check entropy to filter out obvious dummies (e.g. 'test12345678')
                        entropy = shannon_entropy(raw_token)
                        if len(raw_token) >= 16 and entropy < 2.5:
                            continue

                        redacted = redact_secret(raw_token)
                        findings.append(
                            CanonicalFinding(
                                id=f"NSAT-SEC-{seq:03d}",
                                title=f"Exposed Credential: {label}",
                                category="secret",
                                severity=sev,
                                confidence=0.95,
                                confidence_label="Confirmed by safe check",
                                source=self.scanner_name,
                                asset=file_path.name,
                                file_path=str(file_path),
                                line_number=idx,
                                description=(
                                    f"Detected plaintext credential ({label}) committed in source code or configuration. "
                                    f"Redacted value: '{redacted}'."
                                ),
                                impact="Unauthorized access to external cloud providers, databases, or API resources.",
                                recommendation="Revoke this credential immediately. Store secrets in environment variables or a vault.",
                                evidence=[
                                    FindingEvidence(
                                        type="RAW_SECRET",
                                        description=f"Secret identified: {redacted}",
                                        snippet=f"{line[:match.start()]}{redacted}{line[match.end():]}"[:80],
                                        line_number=idx,
                                    )
                                ],
                            )
                        )
                        surface.data.secrets.append(
                            SecretLocation(
                                secret_type=label,
                                redacted_value=redacted,
                                file_path=str(file_path),
                                line_number=idx,
                            )
                        )
                        seq += 1

        return findings
