"""Session Security, Cookie Flags, and Token Oversight Rule for NSAT Phase 3.5."""

from pathlib import Path
import re
from typing import Any
from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence


class SessionCookieRule:
    """
    Audits cookie configurations for missing security flags (HttpOnly, Secure, SameSite)
    and evaluates session/JWT lifecycle oversights.
    """

    def audit(
        self,
        repo_path: Path,
        intel: ProjectIntelligence,
        surface: SecuritySurface,
        existing_findings: list[CanonicalFinding],
    ) -> list[CanonicalFinding]:
        findings: list[CanonicalFinding] = []
        finding_id_seq = 1

        cookie_set_regex = re.compile(
            r'(?:set_cookie|res\.cookie|response\.set_cookie)\s*\(\s*(?:key\s*=\s*|name\s*=\s*)?["\']([^"\']+)["\']',
            re.IGNORECASE,
        )

        for src_file in repo_path.rglob("*"):
            if not src_file.is_file() or src_file.suffix not in (".py", ".js", ".ts", ".tsx", ".java"):
                continue

            rel_path = str(src_file.relative_to(repo_path))
            if any(part in rel_path.lower() for part in ["test", "tests", "fixtures", "node_modules", "vendor"]):
                continue

            try:
                content = src_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()

            for line_idx, line in enumerate(lines, start=1):
                # 1. Cookie Attribute Checks
                match = cookie_set_regex.search(line)
                if match:
                    cookie_name = match.group(1)
                    line_lower = line.lower()

                    missing_flags = []
                    if "httponly" not in line_lower or "httponly=false" in line_lower:
                        missing_flags.append("HttpOnly")
                    if "secure" not in line_lower or "secure=false" in line_lower:
                        missing_flags.append("Secure")
                    if "samesite" not in line_lower:
                        missing_flags.append("SameSite")

                    if missing_flags:
                        fid = f"NSAT-COOKIE-FLAG-{finding_id_seq:03d}"
                        finding_id_seq += 1

                        desc = (
                            f"Cookie '{cookie_name}' is set without mandatory security flags: {', '.join(missing_flags)}: "
                            f"'{line.strip()[:140]}'. Missing HttpOnly permits JavaScript access (XSS token theft); "
                            "missing Secure allows cleartext transmission over unencrypted HTTP; missing SameSite enables Cross-Site Request Forgery (CSRF)."
                        )
                        impact = "Increased vulnerability to Cross-Site Scripting (XSS) session hijacking and CSRF attacks."
                        rec = f"Configure cookie '{cookie_name}' with flags: httponly=True, secure=True, samesite='lax' (or 'strict')."

                        ev = FindingEvidence(
                            type="INSECURE_COOKIE_CONFIGURATION",
                            description=f"Cookie set without security attributes: {', '.join(missing_flags)}",
                            snippet=line.strip()[:160],
                            line_number=line_idx,
                            context={"cookie_name": cookie_name, "missing_flags": missing_flags},
                        )

                        findings.append(
                            CanonicalFinding(
                                id=fid,
                                title=f"Insecure Cookie Flags ({cookie_name}: Missing {', '.join(missing_flags)})",
                                category="session_security",
                                severity="MEDIUM" if "HttpOnly" in missing_flags else "LOW",
                                confidence=0.88,
                                confidence_label="Structural API invocation inspection",
                                source="developer_oversight",
                                sources=["developer_oversight"],
                                asset=rel_path,
                                description=desc,
                                impact=impact,
                                recommendation=rec,
                                status="POTENTIAL",
                                file_path=str(src_file),
                                line_number=line_idx,
                                evidence=[ev],
                            )
                        )

                # 2. JWT without Expiration Claim
                if "jwt.encode" in line or "jwt.sign" in line:
                    # Check surrounding lines for 'exp'
                    window = "\n".join(lines[max(0, line_idx - 5):min(len(lines), line_idx + 5)]).lower()
                    if "exp" not in window and "expiresin" not in window:
                        fid = f"NSAT-JWT-EXP-{finding_id_seq:03d}"
                        finding_id_seq += 1

                        findings.append(
                            CanonicalFinding(
                                id=fid,
                                title="JWT Token Generated Without Explicit Expiration ('exp' claim)",
                                category="session_security",
                                severity="HIGH",
                                confidence=0.85,
                                confidence_label="JWT payload configuration inspection",
                                source="developer_oversight",
                                sources=["developer_oversight"],
                                asset=rel_path,
                                description=(
                                    "Cryptographic token (JWT) is signed without an expiration ('exp') claim or expiresIn parameter. "
                                    "Tokens without expiration remain valid indefinitely once issued, meaning compromised tokens "
                                    "cannot be invalidated through time-bound expiry."
                                ),
                                impact="Indefinite session replay and credential longevity upon token leakage.",
                                recommendation="Always set a short expiration lifespan (e.g. 15-60 minutes) in JWT claims using 'exp'.",
                                status="POTENTIAL",
                                file_path=str(src_file),
                                line_number=line_idx,
                                evidence=[
                                    FindingEvidence(
                                        type="JWT_MISSING_EXPIRATION",
                                        description="JWT signing call lacks 'exp' expiration claim",
                                        snippet=line.strip()[:160],
                                        line_number=line_idx,
                                    )
                                ],
                            )
                        )

        return findings
