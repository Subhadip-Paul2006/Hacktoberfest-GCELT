"""
Unit and integration tests for the NSAT Remediation Change Report PDF subsystem.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from nsat.ai.provider import LLMProvider
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.remediation.models import RemediationProposal, SnapshotMetadata
from nsat.remediation_report import (
    AffectedFileDetail,
    BeforeAfterState,
    RemediationReportContext,
    RemediationReportContextBuilder,
    RemediationReportGenerator,
    RemediationReportStatus,
    ReportLabRenderer,
    ReportResult,
    ReportStorage,
    generate_batch_remediation_reports,
    generate_remediation_report,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_finding() -> CanonicalFinding:
    return CanonicalFinding(
        id="FINDING-001",
        title="Hardcoded Database Password in Configuration",
        category="Hardcoded Secrets",
        severity="HIGH",
        priority="P1",
        confidence=0.95,
        risk_score=75.0,
        asset="backend/config.py",
        file_path="backend/config.py",
        line_number=42,
        function_name="get_db_connection",
        description="A hardcoded database password was found in backend/config.py.",
        impact="Unauthorized database access leading to potential full data breach.",
        recommendation="Store secrets in environment variables or a secrets manager.",
        evidence=[
            FindingEvidence(
                type="code",
                source="regex_scanner",
                description="Matched DB_PASSWORD assignment",
                snippet='DB_PASSWORD = "super_secret_password_123"',
            )
        ],
        primary_location={"file_path": "backend/config.py", "line_number": 42},
        related_findings=["FINDING-002"],
    )


@pytest.fixture
def sample_proposal() -> RemediationProposal:
    return RemediationProposal(
        finding_id="FINDING-001",
        recommended_change="Use os.getenv('DB_PASSWORD') with a secure fallback",
        original_snippet='DB_PASSWORD = "super_secret_password_123"',
        replacement_snippet='DB_PASSWORD = os.getenv("DB_PASSWORD")',
        proposed_patch="""--- backend/config.py
+++ backend/config.py
@@ -41,3 +41,3 @@
-DB_PASSWORD = "super_secret_password_123"
+DB_PASSWORD = os.getenv("DB_PASSWORD")
""",
        affected_file="backend/config.py",
        affected_lines="42",
        root_cause="Credentials were hardcoded during initial prototyping and never extracted.",
        reason="Reading credentials from environment variables adheres to 12-Factor principles.",
        potential_side_effects="Deployment scripts must provide DB_PASSWORD environment variable.",
        verification_plan="Run backend test suite: pytest tests/test_config.py",
    )


@pytest.fixture
def sample_snapshot() -> SnapshotMetadata:
    return SnapshotMetadata(
        remediation_id="REM-001",
        finding_id="FINDING-001",
        repository_root="/repo",
        affected_files=["backend/config.py"],
        proposed_patch="""--- backend/config.py
+++ backend/config.py
@@ -41,3 +41,3 @@
-DB_PASSWORD = "super_secret_password_123"
+DB_PASSWORD = os.getenv("DB_PASSWORD")
""",
        timestamp="2026-10-05T12:00:00Z",
        backup_dir="/tmp/nsat_backups/REM-001",
        original_hashes={"backend/config.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        post_patch_hashes={"backend/config.py": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
    )


# ── Context Builder Tests ─────────────────────────────────────────────────────

def test_context_builder_basic(sample_finding, sample_proposal, sample_snapshot):
    ctx = RemediationReportContextBuilder.build(
        finding=sample_finding,
        proposal=sample_proposal,
        snapshot=sample_snapshot,
        repository_root="/repo",
        project_name="TestProject",
        audit_id="AUD-100",
    )

    assert ctx.finding_id == "FINDING-001"
    assert ctx.finding_title == "Hardcoded Database Password in Configuration"
    assert ctx.severity == "HIGH"
    assert ctx.file_path == "backend/config.py"
    assert ctx.line_number == 42
    assert ctx.rollback_available is True
    assert ctx.backup_location == "/tmp/nsat_backups/REM-001"
    assert len(ctx.affected_files) == 1
    assert ctx.affected_files[0].file_path == "backend/config.py"
    assert ctx.affected_files[0].original_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_context_builder_secret_redaction(sample_finding, sample_proposal):
    # The snippet has `password = ...`
    ctx = RemediationReportContextBuilder.build(
        finding=sample_finding,
        proposal=sample_proposal,
    )
    # The evidence snippet contains password pattern so it should be safely redacted or handled
    assert "super_secret_password_123" not in (ctx.original_snippet or "")
    assert "[LINE REDACTED" in (ctx.proposed_patch or "") or "[REDACTED" in (ctx.original_snippet or "")


# ── Generator Tests ───────────────────────────────────────────────────────────

def test_generator_deterministic_fallback(sample_finding, sample_proposal):
    ctx = RemediationReportContextBuilder.build(
        finding=sample_finding,
        proposal=sample_proposal,
    )
    enriched = RemediationReportGenerator.generate_narratives(ctx, provider=None)

    assert enriched.model_provider == "deterministic"
    assert enriched.ai_executive_summary is not None
    assert "FINDING-001" in enriched.ai_executive_summary
    assert enriched.ai_root_cause_narrative is not None
    assert "OBSERVED:" in enriched.ai_root_cause_narrative
    assert enriched.ai_why_this_change is not None
    assert enriched.ai_final_recommendation is not None


def test_generator_with_llm_provider(sample_finding, sample_proposal):
    ctx = RemediationReportContextBuilder.build(
        finding=sample_finding,
        proposal=sample_proposal,
    )

    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.provider_name = "mock-llm"
    mock_provider.generate.return_value = "This is a detailed AI-generated analysis of the remediation change for testing."

    enriched = RemediationReportGenerator.generate_narratives(ctx, provider=mock_provider)

    assert enriched.model_provider == "mock-llm"
    assert "This is a detailed AI-generated analysis" in enriched.ai_executive_summary
    assert mock_provider.generate.call_count >= 1


def test_generator_llm_failure_falls_back(sample_finding, sample_proposal):
    ctx = RemediationReportContextBuilder.build(
        finding=sample_finding,
        proposal=sample_proposal,
    )

    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.provider_name = "failing-llm"
    mock_provider.generate.side_effect = RuntimeError("API rate limit exceeded")

    enriched = RemediationReportGenerator.generate_narratives(ctx, provider=mock_provider)

    assert enriched.ai_executive_summary is not None
    assert "FINDING-001" in enriched.ai_executive_summary


# ── Report Storage Tests ──────────────────────────────────────────────────────

def test_storage_sanitize():
    assert ReportStorage.sanitize_filename_component("FINDING:001/sub") == "FINDING_001_sub"
    assert ReportStorage.sanitize_filename_component("good-name_123") == "good-name_123"


def test_storage_resolve_output_path(tmp_path):
    target = ReportStorage.resolve_output_path(
        finding_id="F-123",
        remediation_id="R-456",
        base_dir=tmp_path,
    )
    assert target.parent == tmp_path
    assert "F-123_remediation_R-456" in target.name
    assert target.suffix == ".pdf"


# ── PDF Renderer Tests ────────────────────────────────────────────────────────

def test_renderer_to_bytes(sample_finding, sample_proposal, sample_snapshot):
    ctx = RemediationReportContextBuilder.build(
        finding=sample_finding,
        proposal=sample_proposal,
        snapshot=sample_snapshot,
        project_name="Security App",
    )
    ctx = RemediationReportGenerator.generate_narratives(ctx)

    pdf_bytes = ReportLabRenderer.render_to_bytes(ctx)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")


def test_renderer_to_file(sample_finding, sample_proposal, tmp_path):
    ctx = RemediationReportContextBuilder.build(
        finding=sample_finding,
        proposal=sample_proposal,
    )
    ctx = RemediationReportGenerator.generate_narratives(ctx)

    dest = tmp_path / "test_report.pdf"
    rendered_path = ReportLabRenderer.render_to_file(ctx, dest)

    assert rendered_path.exists()
    assert rendered_path.stat().st_size > 1000
    assert rendered_path.read_bytes().startswith(b"%PDF")


def test_renderer_xml_special_characters(sample_finding, sample_proposal, tmp_path):
    # Ensure unescaped HTML characters like <script>, &, > don't crash ReportLab
    sample_finding.title = "XSS Vulnerability with <script>alert('XSS')</script> & tokens"
    sample_proposal.recommended_change = "Sanitize with html.escape() when value > 0 & active == True"
    sample_proposal.proposed_patch = "--- a.html\n+++ b.html\n@@ -1 +1 @@\n-<div><script>evil()</script></div>\n+<div>&safe;</div>\n"

    ctx = RemediationReportContextBuilder.build(
        finding=sample_finding,
        proposal=sample_proposal,
    )
    ctx = RemediationReportGenerator.generate_narratives(ctx)

    dest = tmp_path / "special_chars_report.pdf"
    rendered_path = ReportLabRenderer.render_to_file(ctx, dest)

    assert rendered_path.exists()
    assert rendered_path.stat().st_size > 1000


# ── High-Level Service & Batch Tests ──────────────────────────────────────────

def test_generate_remediation_report_end_to_end(sample_finding, sample_proposal, sample_snapshot, tmp_path):
    out_pdf = tmp_path / "e2e_report.pdf"
    result = generate_remediation_report(
        finding=sample_finding,
        proposal=sample_proposal,
        snapshot=sample_snapshot,
        output_path=out_pdf,
        project_name="E2E Project",
    )

    assert isinstance(result, ReportResult)
    assert result.finding_id == "FINDING-001"
    assert result.remediation_id == "REM-001"
    assert Path(result.pdf_path).exists()
    assert Path(result.pdf_path).stat().st_size > 1000


def test_generate_batch_remediation_reports(sample_finding, sample_proposal, tmp_path):
    finding2 = sample_finding.model_copy(update={"id": "FINDING-002", "title": "Insecure CORS Policy"})
    proposal2 = sample_proposal.model_copy(update={"finding_id": "FINDING-002"})

    results = generate_batch_remediation_reports(
        findings=[sample_finding, finding2],
        proposals=[sample_proposal, proposal2],
        output_dir=tmp_path,
    )

    assert len(results) == 2
    for r in results:
        assert Path(r.pdf_path).exists()
        assert Path(r.pdf_path).stat().st_size > 1000


# ── CLI Tests ─────────────────────────────────────────────────────────────────

def test_cli_list(capsys):
    from nsat.remediation_report.cli import main
    exit_code = main(["--list"])
    assert exit_code == 0


def test_cli_missing_args(capsys):
    from nsat.remediation_report.cli import main
    exit_code = main([])
    assert exit_code == 1


def test_cli_generate_success(sample_finding, sample_proposal, tmp_path, capsys):
    import json
    from nsat.remediation_report.cli import main

    f_path = tmp_path / "finding.json"
    p_path = tmp_path / "proposal.json"
    pdf_path = tmp_path / "out.pdf"

    f_path.write_text(sample_finding.model_dump_json(), encoding="utf-8")
    p_path.write_text(sample_proposal.model_dump_json(), encoding="utf-8")

    exit_code = main([
        "--finding", str(f_path),
        "--proposal", str(p_path),
        "--output", str(pdf_path),
        "--project", "CLI Project",
    ])

    assert exit_code == 0
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 1000
    captured = capsys.readouterr()
    assert "generated successfully" in captured.out


