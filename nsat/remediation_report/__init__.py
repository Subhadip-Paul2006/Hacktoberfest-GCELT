"""
NSAT Remediation Change Report — PDF Generation Subsystem (Phase 4D additive layer).

This isolated package generates human-readable AI-assisted remediation change
reports in PDF format. It consumes outputs already produced by the deterministic
NSAT security engine and Kimi-K3 remediation planner.

It does NOT modify, replace, or alter any existing NSAT component.

Typical flow:
    CanonicalFinding
        ↓
    RemediationProposal (from RemediationPlanner)
        ↓
    RemediationReportContext (assembled here)
        ↓
    RemediationReportGenerator (AI-assisted or deterministic)
        ↓
    PDF (via ReportLabRenderer)
        ↓
    reports/<finding-id>-remediation-<remediation-id>.pdf
"""

from nsat.remediation_report.models import (
    RemediationReportContext,
    RemediationReportStatus,
    ReportResult,
    AffectedFileDetail,
    BeforeAfterState,
)
from nsat.remediation_report.context_builder import RemediationReportContextBuilder
from nsat.remediation_report.generator import RemediationReportGenerator
from nsat.remediation_report.pdf_renderer import ReportLabRenderer
from nsat.remediation_report.storage import ReportStorage
from nsat.remediation_report.service import (
    generate_remediation_report,
    generate_batch_remediation_reports,
)

__all__ = [
    "RemediationReportContext",
    "RemediationReportStatus",
    "ReportResult",
    "AffectedFileDetail",
    "BeforeAfterState",
    "RemediationReportContextBuilder",
    "RemediationReportGenerator",
    "ReportLabRenderer",
    "ReportStorage",
    "generate_remediation_report",
    "generate_batch_remediation_reports",
]

