"""Error / Stack Trace Leakage Audit Rule for NSAT Phase 3.5."""

from pathlib import Path
import re
from typing import Any
from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence


class ErrorExposureRule:
    """
    Detects detailed stack traces, internal file paths, framework debuggers,
    or raw database exceptions returned to client HTTP responses.
    """

    TRACEBACK_RETURN_PATTERNS = [
        (r"(?:traceback\.format_exc\(\))", "Python Traceback in Response", "HIGH"),
        (r"(?:traceback\.print_exc\(\))", "Unhandled Traceback Output", "MEDIUM"),
        (r"return\s+.*(?:str\(e\)|repr\(e\)|err\.message|err\.stack)", "Raw Exception String Returned to Client", "MEDIUM"),
        (r"(?:jsonify|dict|return)\s*\(.*(?:stack|traceback|exception)", "Exception Stack in API Response", "MEDIUM"),
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

        # Check existing Phase 2 finding for Debug Mode Enabled to link related findings
        debug_finding_ids = [
            f.id for f in existing_findings
            if "debug" in f.title.lower() or "debug" in f.description.lower()
        ]

        tb_regexes = [(re.compile(p, re.IGNORECASE), label, sev) for p, label, sev in self.TRACEBACK_RETURN_PATTERNS]

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
                for regex, label, severity in tb_regexes:
                    if regex.search(line):
                        fid = f"NSAT-ERR-LEAK-{finding_id_seq:03d}"
                        finding_id_seq += 1

                        desc = (
                            f"Application source code constructs response reflecting raw error or stack trace: '{line.strip()[:140]}'. "
                            "Exposing unhandled exception stack traces or framework debuggers reveals internal file structures, "
                            "database driver versions, third-party libraries, and underlying code execution paths to attackers."
                        )
                        impact = (
                            "Information disclosure aids reconnaissance and vulnerability weaponization by detailing "
                            "exact file lines, SQL query structures, and library dependencies."
                        )
                        rec = (
                            "Implement global exception handling middleware that catches all unhandled exceptions and "
                            "returns a generic error message (e.g. {'error': 'Internal Server Error', 'request_id': '...'}) "
                            "while writing the full traceback only to internal, secure logs."
                        )

                        ev = FindingEvidence(
                            type="STACK_TRACE_LEAKAGE",
                            description=f"{label} detected in application code handler",
                            snippet=line.strip()[:160],
                            line_number=line_idx,
                            context={"classification": "STATIC_INDICATOR", "file": rel_path},
                        )

                        findings.append(
                            CanonicalFinding(
                                id=fid,
                                title=f"Application Stack Trace / Error Details Exposed ({label})",
                                category="error_exposure",
                                severity=severity,
                                confidence=0.85,
                                confidence_label="Detected structurally in response handler",
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
                                related_findings=debug_finding_ids,
                            )
                        )

        return findings
