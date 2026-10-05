"""
Orchestration service for generating NSAT Remediation Change Reports.

Provides high-level entry points:
- `generate_remediation_report`: Generates a single finding/proposal PDF report.
- `generate_batch_remediation_reports`: Generates reports for multiple proposals.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Sequence

from nsat.ai.provider import LLMProvider
from nsat.normalization.models import CanonicalFinding
from nsat.remediation.models import RemediationProposal, SnapshotMetadata
from nsat.remediation_report.context_builder import RemediationReportContextBuilder
from nsat.remediation_report.generator import RemediationReportGenerator
from nsat.remediation_report.models import (
    RemediationReportContext,
    RemediationReportStatus,
    ReportResult,
)
from nsat.remediation_report.pdf_renderer import ReportLabRenderer
from nsat.remediation_report.storage import ReportStorage

logger = logging.getLogger("nsat.remediation_report.service")


def generate_remediation_report(
    finding: CanonicalFinding,
    proposal: RemediationProposal,
    snapshot: Optional[SnapshotMetadata] = None,
    security_model=None,
    provider: Optional[LLMProvider] = None,
    output_path: Optional[str | Path] = None,
    repository_root: Optional[str] = None,
    project_name: Optional[str] = None,
    audit_id: Optional[str] = None,
    patch_status: RemediationReportStatus = RemediationReportStatus.PROPOSED,
    before_risk_score: Optional[int] = None,
) -> ReportResult:
    """
    Generate an AI-assisted or deterministic Remediation Change Report PDF.

    Args:
        finding: The CanonicalFinding to report on.
        proposal: The RemediationProposal produced by RemediationPlanner.
        snapshot: Optional SnapshotMetadata from SnapshotManager (backup metadata).
        security_model: Optional Phase4SecurityModel for attack paths / blast radius.
        provider: Optional LLMProvider for AI narrative generation (falls back to deterministic).
        output_path: Optional explicit PDF destination path.
        repository_root: Optional repository root path.
        project_name: Optional display name for the project.
        audit_id: Optional audit identifier.
        patch_status: Lifecycle status of the proposed patch.
        before_risk_score: Risk score before remediation.

    Returns:
        ReportResult with generated report_id, pdf_path, status, and metadata.
    """
    logger.info(f"Generating remediation change report for finding {finding.id}")

    # 1. Assemble structured context
    ctx: RemediationReportContext = RemediationReportContextBuilder.build(
        finding=finding,
        proposal=proposal,
        snapshot=snapshot,
        security_model=security_model,
        repository_root=repository_root,
        project_name=project_name,
        audit_id=audit_id,
        patch_status=patch_status,
        before_risk_score=before_risk_score,
    )

    # 2. Enrich with AI narrative (or deterministic fallback)
    ctx = RemediationReportGenerator.generate_narratives(ctx, provider=provider)

    # 3. Resolve destination path
    resolved_path = ReportStorage.resolve_output_path(
        finding_id=ctx.finding_id,
        remediation_id=ctx.remediation_id,
        output_path=output_path,
    )

    # 4. Render PDF to file
    ReportLabRenderer.render_to_file(ctx, resolved_path)
    logger.info(f"Remediation PDF report generated at {resolved_path}")

    # 5. Return structured result
    affected_files = [f.file_path for f in ctx.affected_files]
    return ReportResult(
        report_id=ctx.report_id,
        pdf_path=str(resolved_path),
        finding_id=ctx.finding_id,
        remediation_id=ctx.remediation_id,
        status=ctx.patch_status,
        model_provider=ctx.model_provider,
        affected_files=affected_files,
        audit_id=ctx.audit_id,
        repository_root=ctx.repository_root,
    )


def generate_batch_remediation_reports(
    findings: Sequence[CanonicalFinding],
    proposals: Sequence[RemediationProposal],
    snapshots: Optional[dict[str, SnapshotMetadata]] = None,
    security_model=None,
    provider: Optional[LLMProvider] = None,
    output_dir: Optional[str | Path] = None,
    repository_root: Optional[str] = None,
    project_name: Optional[str] = None,
    audit_id: Optional[str] = None,
) -> list[ReportResult]:
    """
    Generate PDF remediation reports for all matching findings and proposals.

    Matches proposals to findings by finding_id.
    """
    findings_map = {f.id: f for f in findings}
    results: list[ReportResult] = []

    for proposal in proposals:
        finding = findings_map.get(proposal.finding_id)
        if not finding:
            logger.warning(
                f"Skipping proposal for finding {proposal.finding_id}: finding not found."
            )
            continue

        snapshot = (snapshots or {}).get(proposal.finding_id)
        dest_path = None
        if output_dir:
            dest_path = ReportStorage.resolve_output_path(
                finding_id=finding.id,
                remediation_id=snapshot.remediation_id if snapshot else None,
                base_dir=output_dir,
            )

        res = generate_remediation_report(
            finding=finding,
            proposal=proposal,
            snapshot=snapshot,
            security_model=security_model,
            provider=provider,
            output_path=dest_path,
            repository_root=repository_root,
            project_name=project_name,
            audit_id=audit_id,
        )
        results.append(res)

    return results
