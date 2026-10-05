"""
Assembles RemediationReportContext from existing NSAT models.

This builder READS from:
  - nsat.normalization.models.CanonicalFinding
  - nsat.remediation.models.RemediationProposal
  - nsat.remediation.models.SnapshotMetadata  (optional)
  - nsat.correlation.models.Phase4SecurityModel (optional, for blast radius / attack paths)

It does NOT mutate any NSAT state.

SECRET REDACTION:
  - All field values are validated against a blocklist of secret patterns.
  - Hashes are preserved (SHA-256 digests of files are safe — they are not secrets).
  - API keys, passwords, tokens are never forwarded.
"""

from __future__ import annotations

import re
import logging
from typing import Optional

from nsat.normalization.models import CanonicalFinding
from nsat.remediation.models import RemediationProposal, SnapshotMetadata
from nsat.remediation_report.models import (
    AffectedFileDetail,
    BeforeAfterState,
    RemediationReportContext,
    RemediationReportStatus,
)

logger = logging.getLogger("nsat.remediation_report.context_builder")

# Patterns that indicate a value contains a secret that must NOT be forwarded.
_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"(?i)(auth[_-]?token|access[_-]?token|bearer)\s*[=:]\s*\S+"),
    re.compile(r"(?i)(private[_-]?key|priv[_-]?key)"),
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),  # JWT pattern
    re.compile(r"(?i)(nvapi-|sk-|ghp_|glpat-)[a-zA-Z0-9_-]{10,}"),  # API key prefixes
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)\.env\s*content", re.DOTALL),
]


def _contains_secret(value: str) -> bool:
    """Return True if the value matches any known secret pattern."""
    for pat in _SECRET_PATTERNS:
        if pat.search(value):
            return True
    return False


def _safe_str(value: Optional[str], field_name: str = "") -> Optional[str]:
    """Return value only if it does not appear to contain a secret."""
    if value is None:
        return None
    if _contains_secret(value):
        logger.warning(
            f"Secret pattern detected in field '{field_name}'; redacting from report context."
        )
        return "[REDACTED — potential secret detected]"
    return value


def _safe_patch(patch: Optional[str]) -> Optional[str]:
    """
    Sanitise a proposed patch diff for inclusion in the report.
    - Removes lines that appear to set secrets (e.g. 'SECRET=value')
    - Preserves structural diff markers (+/-)
    - Truncates to 5 000 characters for readability
    """
    if not patch:
        return None
    lines = []
    for line in patch.splitlines():
        stripped = line.lstrip("+-").strip()
        if _contains_secret(stripped):
            lines.append(line[:1] + " [LINE REDACTED — potential secret]")
        else:
            lines.append(line)
    result = "\n".join(lines)
    if len(result) > 5000:
        result = result[:5000] + "\n... [diff truncated for report — full diff in patch.diff]"
    return result


class RemediationReportContextBuilder:
    """
    Assembles a RemediationReportContext from existing NSAT models.

    Usage::

        ctx = RemediationReportContextBuilder.build(
            finding=finding,
            proposal=proposal,
            snapshot=snapshot,       # optional
            security_model=model,    # optional
            repository_root=str(repo_root),
            project_name="MyApp",
            audit_id="audit-001",
        )
    """

    @classmethod
    def build(
        cls,
        finding: CanonicalFinding,
        proposal: RemediationProposal,
        snapshot: Optional[SnapshotMetadata] = None,
        security_model=None,  # Phase4SecurityModel — avoid circular import at type-check time
        repository_root: Optional[str] = None,
        project_name: Optional[str] = None,
        audit_id: Optional[str] = None,
        patch_status: RemediationReportStatus = RemediationReportStatus.PROPOSED,
        before_risk_score: Optional[int] = None,
    ) -> RemediationReportContext:
        """
        Build a RemediationReportContext from NSAT canonical data.

        Args:
            finding: The CanonicalFinding to report on.
            proposal: The RemediationProposal produced by RemediationPlanner.
            snapshot: Optional SnapshotMetadata from SnapshotManager (backup info).
            security_model: Optional Phase4SecurityModel for blast-radius / attack paths.
            repository_root: Absolute path to the repository root.
            project_name: Human-readable project name.
            audit_id: Audit session identifier.
            patch_status: Current lifecycle status of the proposed patch.
            before_risk_score: Risk score before remediation (from security model).
        """
        loc = finding.primary_location or {}

        # ── Source location ────────────────────────────────────────────
        file_path = (
            loc.get("file_path")
            or finding.file_path
            or finding.asset
            or "Not reliably resolved"
        )
        line_number: Optional[int] = loc.get("line_number") or finding.line_number
        function_name: Optional[str] = (
            loc.get("function_name") or finding.function_name or None
        )
        class_name: Optional[str] = (
            loc.get("class_name") or finding.class_name or None
        )
        endpoint: Optional[str] = (
            loc.get("endpoint") or finding.endpoint or None
        )

        # ── Evidence summary ──────────────────────────────────────────
        ev_parts = []
        for ev in finding.evidence[:5]:  # cap at 5 items
            snippet_safe = _safe_str(ev.snippet, "evidence.snippet") or ""
            ev_parts.append(f"[{ev.type}] {ev.description}" + (f": `{snippet_safe}`" if snippet_safe else ""))
        evidence_summary = "\n".join(ev_parts) or "No structured evidence available."

        # ── Correlated attack path ─────────────────────────────────────
        correlated_attack_path: Optional[str] = None
        blast_radius_tier: Optional[str] = None
        if security_model is not None:
            try:
                blast_radius_tier = getattr(security_model.blast_radius, "tier", None)
                for ap in getattr(security_model, "attack_paths", []):
                    involved = getattr(ap, "involved_finding_ids", [])
                    if finding.id in involved:
                        steps = " → ".join(getattr(ap, "steps", []))
                        correlated_attack_path = f"{ap.id}: {ap.title} ({steps})"
                        break
            except Exception:
                pass

        # ── Affected file details ──────────────────────────────────────
        affected_files: list[AffectedFileDetail] = []
        if proposal.affected_file:
            orig_hash = None
            post_hash = None
            if snapshot:
                orig_hash = snapshot.original_hashes.get(proposal.affected_file)
                post_hash = snapshot.post_patch_hashes.get(proposal.affected_file)
            relevant_lines: Optional[str] = None
            if proposal.affected_lines is not None and str(proposal.affected_lines) != "N/A":
                relevant_lines = str(proposal.affected_lines)
            affected_files.append(
                AffectedFileDetail(
                    file_path=proposal.affected_file,
                    original_hash=orig_hash,
                    post_patch_hash=post_hash,
                    relevant_lines=relevant_lines,
                )
            )

        # ── Backup / rollback ──────────────────────────────────────────
        backup_location: Optional[str] = None
        backup_status = "Not yet created"
        rollback_available = False
        original_file_hashes: dict[str, str] = {}
        remediation_id: Optional[str] = None

        if snapshot:
            remediation_id = snapshot.remediation_id
            backup_location = snapshot.backup_dir
            backup_status = "Created"
            rollback_available = True
            original_file_hashes = dict(snapshot.original_hashes)

        # ── Before/after ──────────────────────────────────────────────
        before_after: Optional[BeforeAfterState] = None
        if before_risk_score is not None:
            before_after = BeforeAfterState(
                before_status="OPEN",
                before_risk_score=before_risk_score,
                after_status="PENDING",
                after_risk_score=None,
                outcome="PENDING",
            )

        # ── Safe-redact free-text fields from proposal ─────────────────
        safe_patch = _safe_patch(proposal.proposed_patch)
        safe_orig = _safe_str(proposal.original_snippet, "original_snippet")
        safe_repl = _safe_str(proposal.replacement_snippet, "replacement_snippet")
        safe_side_effects = _safe_str(proposal.potential_side_effects, "side_effects") or ""
        safe_verification = _safe_str(proposal.verification_plan, "verification_plan") or ""
        safe_reason = _safe_str(proposal.reason, "reason") or ""

        return RemediationReportContext(
            finding_id=finding.id,
            finding_title=finding.title,
            severity=finding.severity,
            priority=finding.priority,
            confidence=finding.confidence,
            risk_score=finding.risk_score,
            category=finding.category,
            status=patch_status.value,
            file_path=file_path,
            line_number=line_number,
            function_name=function_name,
            class_name=class_name,
            endpoint=endpoint,
            description=finding.description,
            impact=finding.impact,
            root_cause=proposal.root_cause,
            recommendation=finding.recommendation,
            evidence_summary=evidence_summary,
            related_findings=list(finding.related_findings),
            correlated_attack_path=correlated_attack_path,
            blast_radius_tier=blast_radius_tier,
            remediation_id=remediation_id,
            affected_files=affected_files,
            proposed_change_description=proposal.recommended_change,
            proposed_patch=safe_patch,
            original_snippet=safe_orig,
            replacement_snippet=safe_repl,
            potential_side_effects=safe_side_effects or "No known side effects identified from the available evidence.",
            verification_plan=safe_verification,
            reason=safe_reason,
            backup_required=True,
            backup_location=backup_location,
            original_file_hashes=original_file_hashes,
            rollback_available=rollback_available,
            backup_status=backup_status,
            patch_status=patch_status,
            before_after=before_after,
            audit_id=audit_id,
            repository_root=repository_root,
            project_name=project_name or "Unknown Project",
        )
