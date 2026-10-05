"""
Data models for the NSAT Remediation Change Report PDF subsystem.

These models are ADDITIVE — they do not replace or alias any existing
NSAT remediation or normalization models. They consume those models as inputs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class RemediationReportStatus(str, Enum):
    """Lifecycle status of the remediation change as shown in the PDF."""
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_CONFLICT = "ROLLBACK_CONFLICT"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


class AffectedFileDetail(BaseModel):
    """Details for a single file involved in the proposed remediation."""
    file_path: str
    original_hash: Optional[str] = None
    post_patch_hash: Optional[str] = None
    relevant_lines: Optional[str] = None  # e.g. "42-55"


class BeforeAfterState(BaseModel):
    """Before/After security state snapshot for the finding."""
    before_status: str = "OPEN"
    before_risk_score: Optional[int] = None
    after_status: str = "PENDING"
    after_risk_score: Optional[int] = None
    outcome: Optional[str] = None  # e.g. "RESOLVED", "PENDING"


class RemediationReportContext(BaseModel):
    """
    Structured context assembled from NSAT finding + remediation proposal.
    This is the sole input to RemediationReportGenerator.

    Privacy: no API keys, secrets, passwords, or raw env contents are included.
    All fields come from the public NSAT CanonicalFinding / RemediationProposal.
    """
    # Finding metadata
    finding_id: str
    finding_title: str
    severity: str
    priority: Optional[str] = None
    confidence: float = 0.0
    risk_score: Optional[float] = None
    category: str = "unknown"
    status: str = "PROPOSED"

    # Source location
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    endpoint: Optional[str] = None

    # Finding content
    description: str = ""
    impact: str = ""
    root_cause: str = ""
    recommendation: str = ""
    evidence_summary: str = ""

    # Related findings & attack correlation
    related_findings: list[str] = Field(default_factory=list)
    correlated_attack_path: Optional[str] = None
    blast_radius_tier: Optional[str] = None

    # Remediation proposal
    remediation_id: Optional[str] = None
    affected_files: list[AffectedFileDetail] = Field(default_factory=list)
    proposed_change_description: str = ""
    proposed_patch: Optional[str] = None
    original_snippet: Optional[str] = None
    replacement_snippet: Optional[str] = None
    potential_side_effects: str = "No known side effects identified from the available evidence."
    verification_plan: str = ""
    reason: str = ""

    # Backup / rollback
    backup_required: bool = True
    backup_location: Optional[str] = None
    original_file_hashes: dict[str, str] = Field(default_factory=dict)
    rollback_available: bool = False
    backup_status: str = "Not yet created"

    # Lifecycle
    patch_status: RemediationReportStatus = RemediationReportStatus.PROPOSED

    # Before/after
    before_after: Optional[BeforeAfterState] = None

    # Report metadata
    report_id: str = Field(
        default_factory=lambda: f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    )
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    audit_id: Optional[str] = None
    repository_root: Optional[str] = None
    project_name: Optional[str] = None
    model_provider: str = "deterministic"

    # AI-generated narrative sections (populated by generator)
    ai_executive_summary: Optional[str] = None
    ai_root_cause_narrative: Optional[str] = None
    ai_why_this_change: Optional[str] = None
    ai_final_recommendation: Optional[str] = None


class ReportResult(BaseModel):
    """Return value from generate_remediation_report()."""
    report_id: str
    pdf_path: str
    finding_id: str
    remediation_id: Optional[str] = None
    status: RemediationReportStatus = RemediationReportStatus.PROPOSED
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    model_provider: str = "deterministic"
    affected_files: list[str] = Field(default_factory=list)
    audit_id: Optional[str] = None
    repository_root: Optional[str] = None
