"""
Comprehensive unit and integration test suite for NSAT Phase 4C:
Kimi-K3 Remediation, Pre-Patch Snapshots, Minimal Patching,
Automatic Rollbacks, Conflict Detection, and Verification Engine.
"""

import json
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nsat.ai.config import GLMConfig, KimiConfig
from nsat.ai.kimi import KimiProvider
from nsat.cli.main import cli
from nsat.cli.main import _load_audit_context, _save_audit_context, _audit_context_path
from nsat.correlation.models import Phase4SecurityModel
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.remediation.models import (
    RemediationProposal,
    RemediationStatus,
    SnapshotMetadata,
    VerificationOutcome,
    VerificationReport,
)
from nsat.remediation.patcher import Patcher
from nsat.remediation.planner import RemediationPlanner
from nsat.remediation.rollback import RollbackManager
from nsat.remediation.snapshot import SnapshotManager
from nsat.remediation.verifier import VerificationEngine
from nsat.remediation.manager import RemediationManager

DEMO_PATH = Path("demo-vuln-app")


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def temp_project(tmp_path):
    """Create a temporary sandbox project representing a vulnerable repo."""
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True)
    vuln_file = src_dir / "vuln.py"
    vuln_file.write_text(
        'import sqlite3\n\n'
        'def get_user(x1):\n'
        '    conn = sqlite3.connect(":memory:")\n'
        '    cur = conn.cursor()\n'
        '    cur.execute(f"SELECT * FROM users WHERE name = \'{x1}\'")\n'
        '    return cur.fetchall()\n',
        encoding="utf-8",
    )
    docker_file = tmp_path / "Dockerfile"
    docker_file.write_text(
        'FROM alpine:3.18\n'
        'RUN apk add --no-cache docker-cli\n'
        'VOLUME /var/run/docker.sock\n',
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def sample_finding():
    return CanonicalFinding(
        id="NSAT-PY-SQLI",
        category="code_sast",
        severity="CRITICAL",
        confidence=0.95,
        title="SQL Injection via f-string query construction",
        description="Dynamic string formatting into sqlite3 cursor.execute sink allows arbitrary SQL injection.",
        asset="src/vuln.py",
        file_path="src/vuln.py",
        line_number=6,
        source_scanner="native_ast",
        language="python",
        primary_location={
            "file_path": "src/vuln.py",
            "line_number": 6,
            "function_name": "get_user",
        },
        evidence=[
            FindingEvidence(
                type="AST_SINK",
                description="cursor.execute sink receives formatted string",
                line_number=6,
            )
        ],
        impact="Full database readout or tampering.",
        recommendation="Use parameterized query with ? placeholder.",
    )


# =============================================================================
# 1. Kimi Configuration Loading
# =============================================================================

def test_kimi_config_loading():
    """Verify KimiConfig correctly reads KIMI_* variables and provides masked keys."""
    cfg = KimiConfig(
        api_key="sk-test-secret-key-12345",
        base_url="https://api.moonshot.ai/v1",
        model="moonshotai/kimi-k3",
    )
    assert cfg.is_configured() is True
    assert "sk-t" in cfg.masked_key()
    assert "secret" not in cfg.masked_key()


# =============================================================================
# 2. Missing Kimi API Key
# =============================================================================

def test_missing_kimi_api_key():
    """Verify unconfigured Kimi provider gracefully disables without throwing."""
    cfg = KimiConfig(api_key=None)
    assert cfg.is_configured() is False
    provider = KimiProvider(cfg)
    assert provider.health_check() is False
    with pytest.raises(ValueError, match="Kimi API key not configured"):
        provider.generate("test prompt")


# =============================================================================
# 3. Kimi API Timeout & Retries
# =============================================================================

def test_kimi_api_timeout():
    """Verify transient timeouts in Kimi provider trigger retries and raise TimeoutError."""
    import requests
    cfg = KimiConfig(api_key="mock-key", timeout_seconds=0.1, max_retries=1)
    provider = KimiProvider(cfg)

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Read timed out")):
        with pytest.raises(TimeoutError, match="timed out"):
            provider.generate("test prompt")


# =============================================================================
# 4. Remediation Context Generation
# =============================================================================

def test_remediation_context_generation(temp_project, sample_finding):
    """Verify planner extracts minimal code context without entire repository."""
    model = Phase4SecurityModel(
        findings=[sample_finding],
        surface={},
        correlation_matrix=[],
        attack_paths=[],
        blast_radius={"tier": "TIER_1_LOCALIZED"},
        risk={"overall_score": 85, "risk_level": "CRITICAL"},
        locations={},
        evidence_chains={},
        project={"name": "test-repo"},
    )

    proposal = RemediationPlanner.plan(
        finding_id="NSAT-PY-SQLI",
        repo_root=temp_project,
        model=model,
        provider=None,
    )

    assert proposal is not None
    assert proposal.finding_id == "NSAT-PY-SQLI"
    assert proposal.affected_file == "src/vuln.py"
    assert "cur.execute" in proposal.original_snippet
    assert "?" in proposal.replacement_snippet


# =============================================================================
# 5. Pre-Patch Snapshot Creation & SHA-256 Hashes
# =============================================================================

def test_snapshot_creation(temp_project):
    """Verify SnapshotManager creates isolated backup and records SHA-256 hashes."""
    snapshot = SnapshotManager.create_snapshot(
        repo_root=temp_project,
        finding_id="NSAT-PY-SQLI",
        affected_files=["src/vuln.py"],
        proposed_patch="mock-diff",
    )

    assert snapshot.remediation_id.startswith("REM-")
    assert snapshot.status == RemediationStatus.BACKED_UP
    assert "src/vuln.py" in snapshot.original_hashes
    assert len(snapshot.original_hashes["src/vuln.py"]) == 64  # valid SHA-256

    # Verify backup file on disk
    backup_file = Path(snapshot.backup_dir) / "src" / "vuln.py"
    assert backup_file.is_file()
    assert backup_file.read_text(encoding="utf-8") == (temp_project / "src" / "vuln.py").read_text(encoding="utf-8")


# =============================================================================
# 6. Minimal Patch Validation & Scope Check
# =============================================================================

def test_patch_validation_and_scope(temp_project):
    """Verify Patcher rejects non-existent files, stale hashes, or scope violations."""
    proposal = RemediationProposal(
        finding_id="NSAT-PY-SQLI",
        root_cause="SQLi",
        recommended_change="Use bind params",
        affected_file="src/nonexistent.py",
        proposed_patch="",
        original_snippet="orig",
        replacement_snippet="repl",
        reason="test",
        potential_side_effects="none",
        verification_plan="test",
    )
    ok, msg = Patcher.validate_proposal(temp_project, proposal)
    assert ok is False
    assert "does not exist" in msg

    # Mismatched context snippet
    proposal.affected_file = "src/vuln.py"
    proposal.original_snippet = "NONEXISTENT_SNIPPET_STRING"
    ok, msg = Patcher.validate_proposal(temp_project, proposal)
    assert ok is False
    assert "Original code snippet not found" in msg


# =============================================================================
# 7. Successful Minimal Patch Application
# =============================================================================

def test_successful_patch_application(temp_project, sample_finding):
    """Verify Patcher applies surgical replacement and updates post-patch hash."""
    snapshot = SnapshotManager.create_snapshot(
        repo_root=temp_project,
        finding_id=sample_finding.id,
        affected_files=["src/vuln.py"],
        proposed_patch="diff",
    )

    orig_target = 'cur.execute(f"SELECT * FROM users WHERE name = \'{x1}\'")'
    repl_target = 'cur.execute("SELECT * FROM users WHERE name = ?", (x1,))'

    proposal = RemediationProposal(
        finding_id=sample_finding.id,
        root_cause="SQLi",
        recommended_change="Bind parameters",
        affected_file="src/vuln.py",
        proposed_patch="diff",
        original_snippet=orig_target,
        replacement_snippet=repl_target,
        reason="Sanitize input",
        potential_side_effects="None",
        verification_plan="Re-scan",
    )

    res = Patcher.apply_patch(temp_project, proposal, snapshot)
    assert res.success is True
    assert res.post_patch_hash != res.pre_patch_hash

    # Verify disk content changed
    new_content = (temp_project / "src" / "vuln.py").read_text(encoding="utf-8")
    assert 'cur.execute("SELECT * FROM users WHERE name = ?", (x1,))' in new_content
    assert 'f"SELECT' not in new_content


# =============================================================================
# 8. Stale Patch Rejection (File modified after snapshot)
# =============================================================================

def test_stale_patch_rejection(temp_project, sample_finding):
    """Verify patch is rejected if the target file hash changed after snapshot."""
    snapshot = SnapshotManager.create_snapshot(
        repo_root=temp_project,
        finding_id=sample_finding.id,
        affected_files=["src/vuln.py"],
        proposed_patch="diff",
    )

    # Simulate user editing the file in the meantime
    target_file = temp_project / "src" / "vuln.py"
    target_file.write_text("# user made a modification\n" + target_file.read_text(encoding="utf-8"), encoding="utf-8")

    proposal = RemediationProposal(
        finding_id=sample_finding.id,
        root_cause="SQLi",
        recommended_change="Bind parameters",
        affected_file="src/vuln.py",
        proposed_patch="diff",
        original_snippet='cur.execute(f"SELECT * FROM users WHERE name = \'{x1}\'")',
        replacement_snippet='cur.execute("SELECT * FROM users WHERE name = ?", (x1,))',
        reason="Sanitize input",
        potential_side_effects="None",
        verification_plan="Re-scan",
    )

    ok, msg = Patcher.validate_proposal(temp_project, proposal, snapshot)
    assert ok is False
    assert "Target file hash does not match pre-remediation snapshot" in msg


# =============================================================================
# 9. Automatic Rollback on Syntax or Test Failure
# =============================================================================

def test_automatic_rollback_on_syntax_error(temp_project, sample_finding):
    """Verify invalid syntax introduced by a patch triggers automatic rollback."""
    snapshot = SnapshotManager.create_snapshot(
        repo_root=temp_project,
        finding_id=sample_finding.id,
        affected_files=["src/vuln.py"],
        proposed_patch="diff",
    )

    orig_content = (temp_project / "src" / "vuln.py").read_text(encoding="utf-8")

    # Apply malformed syntax
    bad_proposal = RemediationProposal(
        finding_id=sample_finding.id,
        root_cause="SQLi",
        recommended_change="Fix query",
        affected_file="src/vuln.py",
        proposed_patch="diff",
        original_snippet='cur.execute(f"SELECT * FROM users WHERE name = \'{x1}\'")',
        replacement_snippet='cur.execute(DEFECTIVE_SYNTAX ::: broken',
        reason="test",
        potential_side_effects="none",
        verification_plan="test",
    )

    Patcher.apply_patch(temp_project, bad_proposal, snapshot)

    # Verification must fail and trigger rollback
    report = VerificationEngine.verify(
        repo_root=temp_project,
        proposal=bad_proposal,
        snapshot=snapshot,
        original_finding=sample_finding,
        auto_rollback_on_failure=True,
    )

    assert report.resolved is False
    assert report.outcome in (VerificationOutcome.VERIFICATION_FAILED, VerificationOutcome.ROLLED_BACK)
    assert report.rollback_performed is True

    # File on disk must be restored to original exact content
    restored_content = (temp_project / "src" / "vuln.py").read_text(encoding="utf-8")
    assert restored_content == orig_content


# =============================================================================
# 10. Rollback Conflict Detection (Protects subsequent user edits)
# =============================================================================

def test_rollback_conflict_detection(temp_project, sample_finding):
    """Verify rollback aborts and raises ROLLBACK_CONFLICT if user edited post-patch."""
    snapshot = SnapshotManager.create_snapshot(
        repo_root=temp_project,
        finding_id=sample_finding.id,
        affected_files=["src/vuln.py"],
        proposed_patch="diff",
    )

    proposal = RemediationProposal(
        finding_id=sample_finding.id,
        root_cause="SQLi",
        recommended_change="Bind parameters",
        affected_file="src/vuln.py",
        proposed_patch="diff",
        original_snippet='cur.execute(f"SELECT * FROM users WHERE name = \'{x1}\'")',
        replacement_snippet='cur.execute("SELECT * FROM users WHERE name = ?", (x1,))',
        reason="test",
        potential_side_effects="none",
        verification_plan="test",
    )

    Patcher.apply_patch(temp_project, proposal, snapshot)

    # User modifies file AFTER the patch was applied
    target_file = temp_project / "src" / "vuln.py"
    target_file.write_text("# Important user work added post-patch\n" + target_file.read_text(encoding="utf-8"), encoding="utf-8")

    # Attempt rollback without force
    rb_res = RollbackManager.rollback(temp_project, snapshot, force=False)
    assert rb_res.success is False
    assert rb_res.status == RemediationStatus.ROLLBACK_CONFLICT
    assert "src/vuln.py" in rb_res.conflicted_files
    assert "# Important user work" in target_file.read_text(encoding="utf-8")


# =============================================================================
# 11. Verification Engine: Resolved Finding
# =============================================================================

def test_verification_engine_resolved(temp_project, sample_finding):
    """Verify VerificationEngine detects finding elimination and updates risk score."""
    snapshot = SnapshotManager.create_snapshot(
        repo_root=temp_project,
        finding_id=sample_finding.id,
        affected_files=["src/vuln.py"],
        proposed_patch="diff",
    )

    proposal = RemediationProposal(
        finding_id=sample_finding.id,
        root_cause="SQLi",
        recommended_change="Bind parameters",
        affected_file="src/vuln.py",
        proposed_patch="diff",
        original_snippet='cur.execute(f"SELECT * FROM users WHERE name = \'{x1}\'")',
        replacement_snippet='cur.execute("SELECT * FROM users WHERE name = ?", (x1,))',
        reason="test",
        potential_side_effects="none",
        verification_plan="test",
    )

    Patcher.apply_patch(temp_project, proposal, snapshot)

    report = VerificationEngine.verify(
        repo_root=temp_project,
        proposal=proposal,
        snapshot=snapshot,
        original_finding=sample_finding,
        previous_risk_score=85,
        previous_risk_level="CRITICAL",
        auto_rollback_on_failure=True,
    )

    assert report.resolved is True
    assert report.outcome == VerificationOutcome.RESOLVED
    assert report.current_risk_score < report.previous_risk_score
    assert report.tests_passed is True


# =============================================================================
# 12. Dry-Run Mode
# =============================================================================

def test_dry_run_mode(runner, temp_project, sample_finding):
    """Verify nsat fix --dry-run prints proposal and diff without modifying disk."""
    model = Phase4SecurityModel(
        findings=[sample_finding],
        surface={},
        correlation_matrix=[],
        attack_paths=[],
        blast_radius={"tier": "TIER_1_LOCALIZED"},
        risk={"overall_score": 85, "risk_level": "CRITICAL"},
        locations={},
        evidence_chains={},
        project={"name": "test-repo"},
    )

    orig_content = (temp_project / "src" / "vuln.py").read_text(encoding="utf-8")

    with patch("nsat.cli.main._build_security_pipeline") as mock_pipeline:
        mock_pipeline.return_value = (temp_project, None, None, [sample_finding], None, None, model)
        res = runner.invoke(cli, ["fix", "NSAT-PY-SQLI", str(temp_project), "--dry-run", "--no-ai"])

        assert res.exit_code == 0
        assert "NSAT REMEDIATION" in res.output
        assert "Proposed Patch:" in res.output
        assert "[DRY-RUN]" in res.output

    # File on disk remains untouched
    assert (temp_project / "src" / "vuln.py").read_text(encoding="utf-8") == orig_content


# =============================================================================
# 13. CLI Fix Command with Auto-Approve (--yes)
# =============================================================================

def test_cli_fix_command_auto_approve(runner, temp_project, sample_finding):
    """Verify nsat fix --yes applies fix, executes verification, and updates history."""
    model = Phase4SecurityModel(
        findings=[sample_finding],
        surface={},
        correlation_matrix=[],
        attack_paths=[],
        blast_radius={"tier": "TIER_1_LOCALIZED"},
        risk={"overall_score": 85, "risk_level": "CRITICAL"},
        locations={},
        evidence_chains={},
        project={"name": "test-repo"},
    )

    with patch("nsat.cli.main._build_security_pipeline") as mock_pipeline:
        mock_pipeline.return_value = (temp_project, None, None, [sample_finding], None, None, model)
        res = runner.invoke(cli, ["fix", "NSAT-PY-SQLI", str(temp_project), "--yes", "--no-ai"])

        assert res.exit_code == 0
        assert "Patch applied successfully" in res.output
        assert "NSAT Remediation & Verification Report" in res.output

    # Check history persisted
    history = RemediationManager.load_history(temp_project)
    assert len(history) >= 1
    assert history[-1]["finding_id"] == "NSAT-PY-SQLI"


# =============================================================================
# 14. CLI Verify Command
# =============================================================================

def test_cli_verify_command(runner, temp_project):
    """Verify nsat verify renders formatted history table."""
    # Write sample history record
    RemediationManager.record_history(
        temp_project,
        {
            "remediation_id": "REM-20261005-001",
            "finding_id": "NSAT-PY-SQLI",
            "affected_files": ["src/vuln.py"],
            "outcome": "RESOLVED",
            "tests_passed": True,
            "resolved": True,
            "previous_risk_score": 85,
            "current_risk_score": 60,
            "rollback_performed": False,
            "rollback_status": None,
        },
    )

    res = runner.invoke(cli, ["verify", str(temp_project)])
    assert res.exit_code == 0
    assert "NSAT Remediation & Verification History" in res.output
    assert "REM-20261005-001" in res.output
    assert "RESOLVED" in res.output


# =============================================================================
# 15. CLI Manual Rollback Command
# =============================================================================

def test_cli_manual_rollback_command(runner, temp_project, sample_finding):
    """Verify nsat fix --rollback <id> safely restores repository files."""
    orig_content = (temp_project / "src" / "vuln.py").read_text(encoding="utf-8")

    snapshot = SnapshotManager.create_snapshot(
        repo_root=temp_project,
        finding_id=sample_finding.id,
        affected_files=["src/vuln.py"],
        proposed_patch="diff",
    )

    # Modify file
    (temp_project / "src" / "vuln.py").write_text("# Modified by patch\n", encoding="utf-8")
    snapshot.post_patch_hashes["src/vuln.py"] = SnapshotManager.compute_sha256(temp_project / "src" / "vuln.py")
    SnapshotManager.save_metadata(temp_project, snapshot)

    # Invoke CLI rollback
    res = runner.invoke(cli, ["fix", str(temp_project), "--rollback", snapshot.remediation_id])
    assert res.exit_code == 0
    assert "Successfully rolled back" in res.output

    # File on disk restored
    assert (temp_project / "src" / "vuln.py").read_text(encoding="utf-8") == orig_content


# =============================================================================
# 16. Chatbot Explaining Remediation
# =============================================================================

def test_chatbot_explaining_remediation(runner, temp_project, sample_finding):
    """Verify SecurityChatbot answers queries about applied fixes using history."""
    RemediationManager.record_history(
        temp_project,
        {
            "remediation_id": "REM-20261005-001",
            "finding_id": "NSAT-PY-SQLI",
            "affected_files": ["src/vuln.py"],
            "outcome": "RESOLVED",
            "tests_passed": True,
            "resolved": True,
            "previous_risk_score": 85,
            "current_risk_score": 60,
            "rollback_performed": False,
            "rollback_status": None,
        },
    )

    model = Phase4SecurityModel(
        findings=[sample_finding],
        surface={},
        correlation_matrix=[],
        attack_paths=[],
        blast_radius={"tier": "TIER_1_LOCALIZED"},
        risk={"overall_score": 60, "risk_level": "HIGH"},
        locations={},
        evidence_chains={},
        project={"name": "test-repo", "path": str(temp_project)},
    )

    with patch("nsat.cli.main.GLMConfig.load", return_value=GLMConfig(enabled=False)), \
         patch("nsat.cli.main._build_security_pipeline") as mock_pipeline:
        mock_pipeline.return_value = (temp_project, None, None, [sample_finding], None, None, model)
        res = runner.invoke(
            cli,
            ["chat", str(temp_project), "--ask", "What changed after the fix?"],
        )
        assert res.exit_code == 0
        assert "NSAT:" in res.output
        assert "NSAT-PY-SQLI" in res.output
        assert "src/vuln.py" in res.output


def test_snapshot_rejects_repository_escape(temp_project):
    with pytest.raises(ValueError, match="escapes repository root"):
        SnapshotManager.create_snapshot(
            temp_project, "NSAT-ESCAPE", ["../outside.txt"], "diff"
        )


def test_snapshot_ids_are_unique(temp_project):
    first = SnapshotManager.create_snapshot(
        temp_project, "NSAT-UNIQUE", ["src/vuln.py"], "diff"
    )
    second = SnapshotManager.create_snapshot(
        temp_project, "NSAT-UNIQUE", ["src/vuln.py"], "diff"
    )
    assert first.remediation_id != second.remediation_id


def test_patch_rejects_repository_escape(temp_project):
    proposal = RemediationProposal(
        finding_id="NSAT-ESCAPE", root_cause="test", recommended_change="test",
        affected_file="../outside.txt", proposed_patch="",
        original_snippet="old", replacement_snippet="new", reason="test",
        potential_side_effects="none", verification_plan="test",
    )
    ok, message = Patcher.validate_proposal(temp_project, proposal)
    assert not ok
    assert "escapes repository root" in message


def test_rollback_rejects_corrupt_backup(temp_project, sample_finding):
    snapshot = SnapshotManager.create_snapshot(
        temp_project, sample_finding.id, ["src/vuln.py"], "diff"
    )
    backup = Path(snapshot.backup_dir) / "src" / "vuln.py"
    backup.write_text("corrupted backup", encoding="utf-8")
    result = RollbackManager.rollback(temp_project, snapshot)
    assert not result.success
    assert result.status == RemediationStatus.FAILED
    assert "src/vuln.py" in result.conflicted_files


def test_failed_rescan_does_not_mark_finding_resolved(temp_project, sample_finding):
    snapshot = SnapshotManager.create_snapshot(
        temp_project, sample_finding.id, ["src/vuln.py"], "diff"
    )
    proposal = RemediationProposal(
        finding_id=sample_finding.id, root_cause="SQLi", recommended_change="Bind parameters",
        affected_file="src/vuln.py", proposed_patch="diff",
        original_snippet='cur.execute(f"SELECT * FROM users WHERE name = \'{x1}\'")',
        replacement_snippet='cur.execute("SELECT * FROM users WHERE name = ?", (x1,))',
        reason="test", potential_side_effects="none", verification_plan="rescan",
    )
    Patcher.apply_patch(temp_project, proposal, snapshot)
    with patch.object(VerificationEngine, "_rescan_file", side_effect=RuntimeError("scanner unavailable")):
        report = VerificationEngine.verify(
            temp_project, proposal, snapshot, sample_finding,
            auto_rollback_on_failure=True,
        )
    assert report.outcome == VerificationOutcome.ROLLED_BACK
    assert not report.resolved
    assert report.rollback_performed


def test_kimi_context_redacts_secrets():
    redacted = RemediationPlanner._redact(
        'password="local-secret"\nAuthorization: Bearer abcdefghijklmnop'
    )
    assert "local-secret" not in redacted
    assert "abcdefghijklmnop" not in redacted


def test_targeted_pytest_runs_without_shell(temp_project):
    test_dir = temp_project / "tests"
    test_dir.mkdir()
    (test_dir / "test_vuln.py").write_text("def test_ok(): pass\n", encoding="utf-8")
    with patch("nsat.remediation.verifier.subprocess.run") as run:
        run.return_value.returncode = 0
        passed, message = VerificationEngine._run_targeted_tests(
            temp_project, "src/vuln.py"
        )
    assert passed
    assert "test_vuln.py" in message
    args, kwargs = run.call_args
    assert args[0][:3] == [sys.executable, "-m", "pytest"]
    assert "shell" not in kwargs
    assert kwargs["timeout"] == 120


def test_docker_socket_remediation_removes_scanner_indicator(temp_project):
    finding = CanonicalFinding(
        id="NSAT-CONT-002", title="Docker socket mounted",
        category="container", severity="CRITICAL", confidence=1.0,
        asset="Dockerfile", file_path="Dockerfile", line_number=3,
        description="Docker daemon socket is exposed.", impact="Host takeover.",
        recommendation="Remove the host Docker socket mount.",
    )
    model = Phase4SecurityModel(findings=[finding])
    proposal = RemediationPlanner.plan(
        finding.id, temp_project, model, provider=None
    )
    assert proposal is not None
    assert "/var/run/docker.sock" not in proposal.replacement_snippet
    snapshot = SnapshotManager.create_snapshot(
        temp_project, finding.id, [proposal.affected_file], proposal.proposed_patch
    )
    assert Patcher.apply_patch(temp_project, proposal, snapshot).success
    rescanned = VerificationEngine._rescan_file(
        temp_project, temp_project / "Dockerfile", finding
    )
    assert not any("docker socket" in item.title.lower() for item in rescanned)


def test_audit_context_is_reused_and_redacted(temp_project, sample_finding):
    model = Phase4SecurityModel(
        findings=[sample_finding], project={"name": "test-repo"}
    )
    model.findings[0].description = "Contains password=local-secret"
    _save_audit_context(temp_project, model)
    context_file = _audit_context_path(temp_project)
    assert context_file.is_file()
    assert "local-secret" not in context_file.read_text(encoding="utf-8")
    loaded = _load_audit_context(temp_project)
    assert loaded is not None
    assert loaded.findings[0].id == sample_finding.id
    assert loaded.project["audit_id"].startswith("AUD-")

    child = temp_project / "demo-app"
    child.mkdir()
    _save_audit_context(child, model)
    loaded_child = _load_audit_context(temp_project)
    assert loaded_child is not None
    assert Path(loaded_child.project["path"]).resolve() == child.resolve()
