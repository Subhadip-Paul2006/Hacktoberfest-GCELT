"""Client Trust and Authorization Mismatch Audit Rule for NSAT Phase 3.5."""

from pathlib import Path
import re
from typing import Any
from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence


class ClientTrustRule:
    """
    Detects server-side trust in unauthenticated client-controlled security state,
    trusted headers (X-Role, X-User), and UI-only authorization mismatches.
    """

    TRUSTED_HEADERS = [
        "x-role",
        "x-user",
        "x-admin",
        "x-forwarded-user",
        "x-authenticated-user",
        "x-tenant-id",
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

        trusted_header_regex = re.compile(
            r'(?:headers\.get|headers\[|\.getHeader)\s*\(\s*["\'](x-(?:role|user|admin|forwarded-user|authenticated-user))["\']\s*\)',
            re.IGNORECASE,
        )

        frontend_auth_checks = []
        backend_auth_checks = []

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
                # 1. Trusted Header Audit
                match = trusted_header_regex.search(line)
                if match:
                    header_name = match.group(1)
                    # Check if line or subsequent lines perform conditional check on this header
                    window = "\n".join(lines[line_idx - 1:min(len(lines), line_idx + 4)])
                    if any(op in window for op in ["==", "===", "in", ".equals", "if"]):
                        fid = f"NSAT-TRUST-HDR-{finding_id_seq:03d}"
                        finding_id_seq += 1

                        desc = (
                            f"Application relies on client-provided header '{header_name}' for authorization/identity logic: '{line.strip()[:140]}'. "
                            "Unless stripped and strictly re-injected by a trusted upstream reverse proxy, HTTP headers can be "
                            "freely spoofed by arbitrary external clients to bypass access control."
                        )
                        impact = f"Privilege escalation and unauthorized identity assumption via spoofed '{header_name}' header."
                        rec = (
                            f"Do not trust '{header_name}' directly from incoming client requests. Validate user identity "
                            "via cryptographically signed tokens (e.g. JWT) or server-side session stores."
                        )

                        ev = FindingEvidence(
                            type="TRUSTED_HEADER_DEPENDENCY",
                            description=f"Direct authorization check on spoofable HTTP header '{header_name}'",
                            snippet=line.strip()[:160],
                            line_number=line_idx,
                            context={"header": header_name, "file": rel_path},
                        )

                        findings.append(
                            CanonicalFinding(
                                id=fid,
                                title=f"Privilege Decision Dependent on Spoofable HTTP Header ({header_name})",
                                category="client_trust",
                                severity="HIGH",
                                confidence=0.88,
                                confidence_label="Structural header check in authorization logic",
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

                # 2. Client-Side Authorization Mismatch Tracking
                if src_file.suffix in (".tsx", ".jsx", ".ts", ".js"):
                    if re.search(r'\b(?:role|isAdmin|is_admin)\s*===?\s*["\']admin["\']', line):
                        frontend_auth_checks.append((rel_path, line_idx, line.strip()))

                if src_file.suffix in (".py", ".java", ".cpp"):
                    if any(k in line.lower() for k in ["@admin_required", "@roles_required", "hasrole('admin')", "require_admin"]):
                        backend_auth_checks.append((rel_path, line_idx))

        # If frontend has UI-only admin checks but backend has 0 admin decorators/checks across endpoints
        if frontend_auth_checks and not backend_auth_checks and surface.application.admin_endpoints:
            fid = f"NSAT-CLIENT-AUTH-{finding_id_seq:03d}"
            frontend_file, f_line, f_snippet = frontend_auth_checks[0]

            findings.append(
                CanonicalFinding(
                    id=fid,
                    title="Client-Side Only Authorization Check (Frontend Guard without Backend Enforcement)",
                    category="client_trust",
                    severity="HIGH",
                    confidence=0.82,
                    confidence_label="Cross-stack frontend-to-backend authorization analysis",
                    source="developer_oversight",
                    sources=["developer_oversight"],
                    asset=frontend_file,
                    description=(
                        "Frontend contains UI-level authorization gates (e.g. role check), but no corresponding server-side "
                        "role enforcement guards were detected protecting backend admin endpoints. Attackers can bypass "
                        "the UI entirely and invoke backend endpoints directly."
                    ) ,
                    impact="Unauthorized access to administrative operations and resources.",
                    recommendation="Enforce strict authorization checks on server-side endpoint handlers regardless of frontend UI state.",
                    status="POTENTIAL",
                    file_path=frontend_file,
                    line_number=f_line,
                    evidence=[
                        FindingEvidence(
                            type="UI_ONLY_AUTHORIZATION",
                            description="Frontend conditional rendering based on role without server-side guard",
                            snippet=f_snippet[:160],
                            line_number=f_line,
                        )
                    ],
                )
            )

        return findings
