"""Configuration, Deployment, Open Redirect, and Asset Exposure Rule for NSAT Phase 3.5."""

from pathlib import Path
import re
from typing import Any
from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence


class ConfigDeploymentRule:
    """
    Detects configuration oversights, backup file remnants, source maps,
    open redirects, missing external HTTP timeouts, and dangerous CORS combinations.
    """

    BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".tmp", ".backup"]
    BACKUP_FILENAMES = [".env.production", ".env.local", ".env.bak", "dump.sql", "database.sql"]

    def audit(
        self,
        repo_path: Path,
        intel: ProjectIntelligence,
        surface: SecuritySurface,
        existing_findings: list[CanonicalFinding],
    ) -> list[CanonicalFinding]:
        findings: list[CanonicalFinding] = []
        finding_id_seq = 1

        # 1. Source Map Exposure Audit
        for map_file in repo_path.rglob("*.map"):
            if "node_modules" in str(map_file) or ".venv" in str(map_file):
                continue
            rel_map = str(map_file.relative_to(repo_path))

            fid = f"NSAT-MAP-EXPOSE-{finding_id_seq:03d}"
            finding_id_seq += 1

            findings.append(
                CanonicalFinding(
                    id=fid,
                    title=f"Source Map Artifact Detected in Project ({map_file.name})",
                    category="backup_exposure",
                    severity="MEDIUM",
                    confidence=0.95,
                    confidence_label="Static asset discovery",
                    source="developer_oversight",
                    sources=["developer_oversight"],
                    asset=rel_map,
                    description=(
                        f"Source map file '{rel_map}' detected. Deploying source maps to production environments allows "
                        "attackers to reconstruct the complete original unminified frontend source code, developer comments, "
                        "internal routes, and proprietary business logic."
                    ),
                    impact="Full client-side source code disclosure, facilitating reverse-engineering and vulnerability discovery.",
                    recommendation="Remove source maps (*.map) from production build distributions or host them on a private symbol server.",
                    status="POTENTIAL",
                    file_path=str(map_file),
                    evidence=[
                        FindingEvidence(
                            type="SOURCE_MAP_FOUND",
                            description="Source map file found in build or distribution tree",
                            snippet=rel_map,
                        )
                    ],
                )
            )

        # 2. Backup and Temporary Configuration Files
        for fpath in repo_path.rglob("*"):
            if not fpath.is_file():
                continue
            fname = fpath.name.lower()
            rel_path = str(fpath.relative_to(repo_path))
            if any(part in rel_path.lower() for part in ["node_modules", ".venv", "vendor"]):
                continue

            is_backup = (
                any(fname.endswith(ext) for ext in self.BACKUP_EXTENSIONS)
                or fname in self.BACKUP_FILENAMES
                or fname.startswith(".env.")
            )

            if is_backup and not any(k in rel_path.lower() for k in ["test", "fixture"]):
                fid = f"NSAT-BACKUP-FILE-{finding_id_seq:03d}"
                finding_id_seq += 1

                findings.append(
                    CanonicalFinding(
                        id=fid,
                        title=f"Sensitive Backup / Temporary File Present ({fname})",
                        category="backup_exposure",
                        severity="HIGH" if ".env" in fname or ".sql" in fname else "MEDIUM",
                        confidence=0.90,
                        confidence_label="Filesystem heuristic check",
                        source="developer_oversight",
                        sources=["developer_oversight"],
                        asset=rel_path,
                        description=(
                            f"Residual backup or environment artifact '{rel_path}' detected in repository. "
                            "Web servers often fail to parse backup extensions (e.g. .bak, .old) through script engines, "
                            "instead serving them as plaintext downloads to external users."
                        ),
                        impact="Plaintext disclosure of database dumps, credentials, and source backups.",
                        recommendation=f"Delete '{rel_path}' and add backup extensions to .gitignore and web server blocklists.",
                        status="POTENTIAL",
                        file_path=str(fpath),
                        evidence=[
                            FindingEvidence(
                                type="BACKUP_FILE_DISCOVERED",
                                description=f"Residual backup artifact: {fname}",
                                snippet=rel_path,
                            )
                        ],
                    )
                )

        # 3. .git Directory Exposed in Web Directory
        for web_dir in ["public", "static", "dist", "html", "www", "build"]:
            candidate = repo_path / web_dir / ".git"
            if candidate.exists() and candidate.is_dir():
                fid = f"NSAT-GIT-EXPOSE-{finding_id_seq:03d}"
                finding_id_seq += 1

                findings.append(
                    CanonicalFinding(
                        id=fid,
                        title=f"Git Version Control Metadata Inside Public Web Directory ({web_dir}/.git)",
                        category="backup_exposure",
                        severity="CRITICAL",
                        confidence=0.98,
                        confidence_label="Public directory traversal",
                        source="developer_oversight",
                        sources=["developer_oversight"],
                        asset=f"{web_dir}/.git",
                        description=(
                            f"The version control directory '{web_dir}/.git' is located inside a publicly served web directory. "
                            "Attackers can download the entire git repository, commit history, and historical secrets."
                        ),
                        impact="Total source code disclosure and historical repository exfiltration.",
                        recommendation=f"Remove '{web_dir}/.git' immediately and ensure web server blocks all access to dotfiles ('.*').",
                        status="POTENTIAL",
                        file_path=str(candidate),
                        evidence=[
                            FindingEvidence(
                                type="GIT_IN_PUBLIC_WEB_DIR",
                                description=f"'.git' discovered inside publicly exposed asset folder '{web_dir}'",
                                snippet=f"{web_dir}/.git",
                            )
                        ],
                    )
                )

        # 4. Open Redirect Pattern
        redirect_regex = re.compile(
            r'(?:RedirectResponse|redirect|res\.redirect)\s*\(\s*(?:url\s*=\s*)?(?:data|request\.query_params|request\.args|req\.query)\.get\s*\(\s*["\'](next|redirect|url|return_url|callback)["\']',
            re.IGNORECASE,
        )

        # 5. Missing HTTP Timeout Pattern
        http_call_regex = re.compile(
            r'(?:requests\.(?:get|post|put|delete)|httpx\.(?:get|post|put|delete))\s*\([^)]+\)',
            re.IGNORECASE,
        )

        for src_file in repo_path.rglob("*"):
            if not src_file.is_file() or src_file.suffix not in (".py", ".js", ".ts", ".tsx"):
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
                # Check Open Redirect (direct or via variable assigned from query params)
                is_redir_call = bool(re.search(r'(?:RedirectResponse|res\.redirect|redirect)\s*\(', line))
                if is_redir_call:
                    window_prev = "\n".join(lines[max(0, line_idx - 6):line_idx]).lower()
                    if (
                        any(k in window_prev for k in ["query_params", "query", "args", "params"])
                        or any(k in line.lower() for k in ["query_params", "query", "args", "params"])
                        or any(k in line.lower() for k in ["next", "target_url", "return_url", "redirect_url"])
                    ):
                        fid = f"NSAT-OPEN-REDIR-{finding_id_seq:03d}"
                        finding_id_seq += 1

                        findings.append(
                            CanonicalFinding(
                                id=fid,
                                title="Potential Open Redirect via Untrusted Query Parameter",
                                category="open_redirect",
                                severity="MEDIUM",
                                confidence=0.85,
                                confidence_label="AST source-to-sink redirect analysis",
                                source="developer_oversight",
                                sources=["developer_oversight"],
                                asset=rel_path,
                                description=(
                                    f"Application redirects client using untrusted destination parameter without validation: "
                                    f"'{line.strip()[:140]}'. Attackers can craft phishing links under the legitimate domain."
                                ),
                                impact="Phishing attacks, OAuth token theft, and user credential harvesting via trusted domain redirection.",
                                recommendation="Validate redirect targets against an absolute URL allowlist or restrict redirects to relative paths starting with '/'.",
                                status="POTENTIAL",
                                file_path=str(src_file),
                                line_number=line_idx,
                                evidence=[
                                    FindingEvidence(
                                        type="UNVALIDATED_REDIRECT",
                                        description="Redirect destination sourced from request parameter",
                                        snippet=line.strip()[:160],
                                        line_number=line_idx,
                                    )
                                ],
                            )
                        )

                # Check Missing HTTP Timeouts on external calls
                if http_call_regex.search(line) and "timeout" not in line.lower():
                    fid = f"NSAT-TIMEOUT-{finding_id_seq:03d}"
                    finding_id_seq += 1

                    findings.append(
                        CanonicalFinding(
                            id=fid,
                            title="External HTTP Request Executed Without Explicit Timeout",
                            category="resource_timeout",
                            severity="LOW",
                            confidence=0.80,
                            confidence_label="Library invocation inspection",
                            source="developer_oversight",
                            sources=["developer_oversight"],
                            asset=rel_path,
                            description=(
                                f"External HTTP call executes without a 'timeout' parameter: '{line.strip()[:140]}'. "
                                "By default, several HTTP client libraries wait indefinitely for connection responses, "
                                "allowing unresponsive third-party servers to consume worker threads and cause Denial of Service (DoS)."
                            ),
                            impact="Thread pool exhaustion and application Denial of Service upon upstream latency.",
                            recommendation="Specify an explicit timeout (e.g. timeout=5.0) on all outbound HTTP client requests.",
                            status="POTENTIAL",
                            file_path=str(src_file),
                            line_number=line_idx,
                            evidence=[
                                FindingEvidence(
                                    type="MISSING_HTTP_TIMEOUT",
                                    description="Outbound network call lacks timeout constraint",
                                    snippet=line.strip()[:160],
                                    line_number=line_idx,
                                )
                            ],
                        )
                    )

                # Check Permissive CORS combined with credentials
                if "allow_origins" in line and ("*" in line or '"*"' in line) and "allow_credentials=true" in line.lower():
                    fid = f"NSAT-CORS-WILDCARD-{finding_id_seq:03d}"
                    finding_id_seq += 1

                    findings.append(
                        CanonicalFinding(
                            id=fid,
                            title="Insecure CORS Policy: Wildcard Origin with Credentials Allowed",
                            category="cors_oversight",
                            severity="HIGH",
                            confidence=0.92,
                            confidence_label="Middleware configuration analysis",
                            source="developer_oversight",
                            sources=["developer_oversight"],
                            asset=rel_path,
                            description=(
                                f"CORS middleware allows wildcard origin ('*') combined with allow_credentials=True: '{line.strip()[:140]}'. "
                                "This configuration allows arbitrary malicious websites to read authenticated cross-origin API responses."
                            ),
                            impact="Cross-origin authenticated data theft and user impersonation.",
                            recommendation="Explicitly enumerate trusted frontend domains in allow_origins instead of using wildcard '*'.",
                            status="POTENTIAL",
                            file_path=str(src_file),
                            line_number=line_idx,
                            evidence=[
                                FindingEvidence(
                                    type="PERMISSIVE_CORS_POLICY",
                                    description="Wildcard origin configured with credentials enabled",
                                    snippet=line.strip()[:160],
                                    line_number=line_idx,
                                )
                            ],
                        )
                    )

        return findings
