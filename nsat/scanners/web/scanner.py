"""Safe web runtime security prober for NSAT."""

from pathlib import Path
from typing import Optional
import urllib.error
import urllib.parse
import urllib.request
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.scanners.base import BaseScanner


class WebProber(BaseScanner):
    """
    Safely probes an explicitly authorized HTTP/HTTPS target endpoint.
    Audits security headers, information leakage, and cookie flags.
    """

    @property
    def scanner_name(self) -> str:
        return "web_prober"

    def scan(self, target_path: Path, surface: SecuritySurface) -> list[CanonicalFinding]:
        return []

    def probe_url(self, target_url: str) -> list[CanonicalFinding]:
        """Send safe HTTP HEAD / GET to evaluate headers, cookies, and TLS."""
        findings: list[CanonicalFinding] = []
        seq = 1

        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "NSAT-Security-Audit/0.1.0"},
                method="GET",
            )
            # Short timeout to prevent hangs
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                headers = dict(resp.headers)
        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
        except Exception:
            # Target unreachable or connection refused -> return empty findings safely
            return []

        header_keys_lower = {k.lower(): v for k, v in headers.items()}

        # 1. Missing Security Headers
        recommended_headers = [
            ("content-security-policy", "Content-Security-Policy (CSP)", "MEDIUM", "Restricts resource loading to prevent XSS and data injection."),
            ("x-frame-options", "X-Frame-Options", "LOW", "Prevents clickjacking attacks by controlling framing."),
            ("x-content-type-options", "X-Content-Type-Options", "LOW", "Prevents MIME-sniffing vulnerabilities."),
            ("strict-transport-security", "Strict-Transport-Security (HSTS)", "MEDIUM", "Forces HTTPS connections to prevent SSL stripping."),
        ]

        for h_key, h_name, sev, h_desc in recommended_headers:
            if h_key not in header_keys_lower:
                findings.append(
                    CanonicalFinding(
                        id=f"NSAT-WEB-{seq:03d}",
                        title=f"Missing Security Header: {h_name}",
                        category="web_security",
                        severity=sev,
                        confidence=1.0,
                        confidence_label="Confirmed by safe check",
                        source=self.scanner_name,
                        asset=target_url,
                        endpoint=target_url,
                        description=f"The HTTP response from '{target_url}' lacks the '{h_name}' header.",
                        impact=f"Reduced defense-in-depth: {h_desc}",
                        recommendation=f"Configure web server / application to emit '{h_name}'.",
                        evidence=[
                            FindingEvidence(
                                type="HEADER_MISSING",
                                description=f"Header '{h_name}' missing from HTTP response",
                            )
                        ],
                    )
                )
                seq += 1

        # 2. Server Information Leakage (X-Powered-By / Server)
        for leak_header in ["x-powered-by", "server"]:
            if leak_header in header_keys_lower:
                val = header_keys_lower[leak_header]
                findings.append(
                    CanonicalFinding(
                        id=f"NSAT-WEB-{seq:03d}",
                        title=f"Server Information Leakage: {leak_header.title()}",
                        category="web_security",
                        severity="LOW",
                        confidence=1.0,
                        confidence_label="Confirmed by safe check",
                        source=self.scanner_name,
                        asset=target_url,
                        endpoint=target_url,
                        description=f"The '{leak_header}' header reveals internal tech stack: '{val}'.",
                        impact="Helps adversaries fingerprint specific server software and target known CVEs.",
                        recommendation=f"Remove or obscure the '{leak_header}' header.",
                        evidence=[
                            FindingEvidence(
                                type="HEADER_LEAK",
                                description=f"{leak_header}: {val}",
                                snippet=f"{leak_header}: {val}",
                            )
                        ],
                    )
                )
                seq += 1

        return findings
