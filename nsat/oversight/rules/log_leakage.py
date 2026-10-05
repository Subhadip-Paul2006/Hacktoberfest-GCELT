"""Log Leakage Audit Rule for NSAT Phase 3.5."""

from pathlib import Path
import re
from typing import Any
from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence


class LogLeakageRule:
    """
    Detects security-sensitive variables and secrets flowing into logging,
    console output, or debug print statements.
    Ensures all sensitive values in emitted evidence are strictly redacted.
    """

    LOG_CALL_PATTERNS = [
        r"(?:logging\.(?:info|debug|warning|error|critical|exception))\s*\(",
        r"(?:logger\.(?:info|debug|warn|error|trace|log))\s*\(",
        r"(?:console\.(?:log|debug|info|warn|error))\s*\(",
        r"(?:System\.out\.println|System\.err\.println)\s*\(",
        r"(?:print)\s*\(",
        r"(?:std::cout\s*<<)",
    ]

    SENSITIVE_VARIABLE_PATTERNS = [
        r"\b(?:password|passwd|pwd)\b",
        r"\b(?:otp|pin|auth_code|verify_code)\b",
        r"\b(?:jwt|access_token|refresh_token|auth_token|session_id|sid)\b",
        r"\b(?:api_key|apikey|app_secret|secret_key|db_password)\b",
        r"\b(?:authorization_header|credit_card|cvv)\b",
    ]

    def _redact_snippet(self, text: str) -> str:
        """Sanitize any explicit sensitive values in the snippet."""
        text = re.sub(r'(["\'])(?:password|secret|token|key|pwd)\1\s*[:=]\s*(["\'])[^"\']+\2', r'\1credential\1: \2***REDACTED***\2', text, flags=re.IGNORECASE)
        text = re.sub(r'([a-zA-Z0-9_\-]{24,})', '***REDACTED_SECRET***', text)
        return text.strip()[:200]

    def audit(
        self,
        repo_path: Path,
        intel: ProjectIntelligence,
        surface: SecuritySurface,
        existing_findings: list[CanonicalFinding],
    ) -> list[CanonicalFinding]:
        findings: list[CanonicalFinding] = []
        finding_id_seq = 1

        log_regex = re.compile("|".join(self.LOG_CALL_PATTERNS), re.IGNORECASE)
        var_regex = re.compile("|".join(self.SENSITIVE_VARIABLE_PATTERNS), re.IGNORECASE)

        for src_file in repo_path.rglob("*"):
            if not src_file.is_file() or src_file.suffix not in (".py", ".js", ".ts", ".tsx", ".java", ".cpp"):
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
                # Check if line contains a logging call
                if log_regex.search(line):
                    # Check if line also references a sensitive variable name
                    var_match = var_regex.search(line)
                    if var_match:
                        matched_var = var_match.group(0)
                        fid = f"NSAT-LOG-LEAK-{finding_id_seq:03d}"
                        finding_id_seq += 1

                        sanitized_snippet = self._redact_snippet(line)

                        desc = (
                            f"Sensitive variable '{matched_var}' is output to application logs or console: '{sanitized_snippet}'. "
                            "Application logs are frequently aggregated into central SIEM, third-party monitoring platforms "
                            "(e.g., Datadog, Splunk, CloudWatch), and readable by unprivileged developers or operations staff."
                        )
                        impact = (
                            f"Exposure of {matched_var} through log aggregation platforms, crash reports, "
                            "and console output, violating zero-trust logging practices."
                        )
                        rec = (
                            f"Filter or mask '{matched_var}' prior to logging. Use structured log filtering or "
                            "cryptographic hashing if identifier traceability is required."
                        )

                        ev = FindingEvidence(
                            type="SENSITIVE_LOG_DATA",
                            description=f"Logging invocation receives sensitive identifier '{matched_var}'",
                            snippet=sanitized_snippet,
                            line_number=line_idx,
                            context={"variable": matched_var, "file": rel_path},
                        )

                        findings.append(
                            CanonicalFinding(
                                id=fid,
                                title=f"Sensitive Credential / Token Output to Application Logs ({matched_var})",
                                category="log_leakage",
                                severity="HIGH" if any(k in matched_var.lower() for k in ["pass", "secret", "key", "otp"]) else "MEDIUM",
                                confidence=0.88,
                                confidence_label="Structural dataflow into logging sink",
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

        return findings
