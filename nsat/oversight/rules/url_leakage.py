"""URL / Information Leakage Audit Rule for NSAT Phase 3.5."""

from pathlib import Path
import re
from typing import Any
from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence


class URLLeakageRule:
    """
    Detects security-sensitive parameters (passwords, PINs, OTPs, tokens, API keys)
    exposed in URL paths, query parameters, or route declarations.
    Explains the operational risk (browser history, proxy logs, Referer propagation).
    """

    SENSITIVE_PARAM_PATTERNS = [
        (r"(password|passwd|pwd)", "Password / Credential", "CRITICAL"),
        (r"(otp|pin|verification_code|verify_code|auth_code)", "One-Time Password / PIN", "HIGH"),
        (r"(token|jwt|access_token|refresh_token|auth_token|session_id|sid)", "Authentication Token / Session ID", "HIGH"),
        (r"(api_key|apikey|secret|app_secret)", "API Key / Application Secret", "HIGH"),
        (r"(reset_token|reset_code|recovery_token)", "Password Reset Token", "HIGH"),
    ]

    def audit(
        self,
        repo_path: Path,
        intel: ProjectIntelligence,
        surface: SecuritySurface,
        existing_findings: list[CanonicalFinding],
    ) -> list[CanonicalFinding]:
        findings: list[CanonicalFinding] = []
        finding_id_seq = 1

        # 1. Inspect surfaced endpoints
        for ep in surface.application.endpoints:
            path_lower = ep.path.lower()

            for pattern, label, severity in self.SENSITIVE_PARAM_PATTERNS:
                # Check query parameter declarations or path templates (e.g., /verify?otp=... or /reset/{token})
                if re.search(pattern, path_lower):
                    fid = f"NSAT-URL-LEAK-{finding_id_seq:03d}"
                    finding_id_seq += 1

                    desc = (
                        f"Security-sensitive parameter '{label}' is exposed directly within the URL route: '{ep.path}'. "
                        "Values transmitted in URLs are routinely written to browser history, server access logs, "
                        "reverse proxy logs, and transmitted to third-party domains via the HTTP Referer header."
                    )
                    impact = (
                        f"Exposure of {label.lower()} through proxy caches, server access logs, browser history, "
                        "and Referer header leakage, enabling credential theft or session compromise."
                    )
                    rec = (
                        f"Migrate {label.lower()} transmission from the URL path/query string to the HTTP request body "
                        "(e.g., JSON payload over POST/PUT) or secure HTTP Authorization headers."
                    )

                    ev = FindingEvidence(
                        type="SENSITIVE_URL_PARAMETER",
                        description=f"Sensitive parameter '{label}' declared in endpoint URL route",
                        snippet=f"{ep.method} {ep.path}",
                        line_number=ep.line_number,
                        context={"endpoint": ep.path, "handler": ep.handler, "exposure_channels": ["browser_history", "server_logs", "referer_header"]},
                    )

                    findings.append(
                        CanonicalFinding(
                            id=fid,
                            title=f"Sensitive {label} Transmitted in URL Path/Query",
                            category="url_security",
                            severity=severity,
                            confidence=0.85,
                            confidence_label="Contextual AST analysis",
                            source="developer_oversight",
                            sources=["developer_oversight", "surface_extractor"],
                            asset=ep.path,
                            description=desc,
                            impact=impact,
                            recommendation=rec,
                            status="POTENTIAL",
                            file_path=ep.file_path,
                            line_number=ep.line_number,
                            endpoint=ep.path,
                            evidence=[ev],
                        )
                    )

        # 2. Inspect source code lines for client-side or backend query string builds with sensitive variables
        sensitive_query_regex = re.compile(
            r'[`\'"][^`\'"]*?[\?&](otp|pin|password|token|api_key|secret|jwt)=',
            re.IGNORECASE,
        )

        for src_file in repo_path.rglob("*"):
            if src_file.is_file() and src_file.suffix in (".py", ".js", ".ts", ".tsx", ".java", ".cpp"):
                # Skip test directories for noise suppression
                rel_path = str(src_file.relative_to(repo_path))
                if any(part in rel_path.lower() for part in ["test", "tests", "fixtures", "node_modules", "vendor"]):
                    continue

                try:
                    content = src_file.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                for line_idx, line in enumerate(content.splitlines(), start=1):
                    for match in sensitive_query_regex.finditer(line):
                        param_name = match.group(1)
                        fid = f"NSAT-URL-LEAK-{finding_id_seq:03d}"
                        finding_id_seq += 1

                        findings.append(
                            CanonicalFinding(
                                id=fid,
                                title=f"Sensitive Parameter '{param_name}' Formatted into Query String",
                                category="url_security",
                                severity="HIGH",
                                confidence=0.80,
                                confidence_label="Structural pattern matching",
                                source="developer_oversight",
                                sources=["developer_oversight"],
                                asset=rel_path,
                                description=f"URL construction includes sensitive parameter '{param_name}' in query string. Exposed to browser history and logs.",
                                impact="Sensitive parameter leakage via logs, Referer headers, and web caches.",
                                recommendation="Transmit sensitive parameter via HTTP request body or Authorization header.",
                                status="POTENTIAL",
                                file_path=str(src_file),
                                line_number=line_idx,
                                evidence=[
                                    FindingEvidence(
                                        type="QUERY_STRING_CREDENTIAL",
                                        description=f"Query string contains sensitive parameter: {param_name}",
                                        snippet=line.strip()[:160],
                                        line_number=line_idx,
                                    )
                                ],
                            )
                        )

        return findings
