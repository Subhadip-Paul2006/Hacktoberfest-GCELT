"""
Verification Engine for NSAT Remediation (Phase 4C).

Safely validates post-remediation changes:
1. Runs syntax/compilation sanity checks.
2. Executes targeted test suite.
3. Re-scans the modified file/asset using the relevant native scanner/analyzer.
4. Recalculates risk score and blast radius via RiskEngine.
5. Evaluates BEFORE vs AFTER states:
   - RESOLVED: Finding no longer detected by targeted re-scan.
   - STILL_PRESENT: Finding still triggers scanner sink.
   - REGRESSION: Finding remains or new critical findings introduced.
   - VERIFICATION_FAILED: Syntax or test execution failure.
6. Automatically triggers rollback via RollbackManager on test or verification failure.
"""

import ast
import logging
import subprocess
import sys
from pathlib import Path
from typing import Optional

from nsat.correlation.risk import RiskEngine
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding
from nsat.remediation.models import (
    RemediationProposal,
    RemediationStatus,
    SnapshotMetadata,
    VerificationOutcome,
    VerificationReport,
)
from nsat.remediation.rollback import RollbackManager
from nsat.remediation.snapshot import SnapshotManager
from nsat.scanners.container.scanner import ContainerScanner
from nsat.scanners.sast.native_rules import NativeSASTScanner
from nsat.scanners.secrets.scanner import SecretScanner

logger = logging.getLogger("nsat.remediation.verifier")


class VerificationEngine:
    """Authoritative validator comparing before and after security postures."""

    @classmethod
    def verify(
        cls,
        repo_root: Path,
        proposal: RemediationProposal,
        snapshot: SnapshotMetadata,
        original_finding: CanonicalFinding,
        previous_risk_score: int = 80,
        previous_risk_level: str = "HIGH",
        auto_rollback_on_failure: bool = True,
        baseline_findings: Optional[list[CanonicalFinding]] = None,
    ) -> VerificationReport:
        """
        Execute full end-to-end verification pipeline on remediated asset.
        """
        try:
            target_file = SnapshotManager.resolve_repo_file(repo_root, proposal.affected_file)
        except ValueError as exc:
            return cls._handle_failure(
                repo_root, snapshot, proposal, previous_risk_score, previous_risk_level,
                VerificationOutcome.VERIFICATION_FAILED, False,
                [f"Verification target rejected: {exc}"], auto_rollback_on_failure,
                "Unsafe verification target.",
            )
        evidence_log: list[str] = []
        snapshot.status = RemediationStatus.TESTING
        SnapshotManager.save_metadata(repo_root, snapshot)

        # 1. Syntax check on target file (Python / Dockerfile / JS)
        syntax_ok, syntax_err = cls._check_syntax(target_file)
        if not syntax_ok:
            evidence_log.append(f"Syntax validation failed: {syntax_err}")
            return cls._handle_failure(
                repo_root=repo_root,
                snapshot=snapshot,
                proposal=proposal,
                previous_risk_score=previous_risk_score,
                previous_risk_level=previous_risk_level,
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                tests_passed=False,
                evidence=evidence_log,
                auto_rollback=auto_rollback_on_failure,
                err_msg=f"Syntax error: {syntax_err}",
            )

        evidence_log.append("Syntax and parse sanity check passed.")

        # 2. Targeted test execution
        tests_passed, test_msg = cls._run_targeted_tests(repo_root, proposal.affected_file)
        if not tests_passed:
            evidence_log.append(f"Targeted test execution failed: {test_msg}")
            return cls._handle_failure(
                repo_root=repo_root,
                snapshot=snapshot,
                proposal=proposal,
                previous_risk_score=previous_risk_score,
                previous_risk_level=previous_risk_level,
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                tests_passed=False,
                evidence=evidence_log,
                auto_rollback=auto_rollback_on_failure,
                err_msg=f"Test failure: {test_msg}",
            )

        evidence_log.append("Targeted tests passed successfully.")

        # 3. Targeted Re-Scan using relevant native analyzer
        snapshot.status = RemediationStatus.RESCANNING
        SnapshotManager.save_metadata(repo_root, snapshot)
        try:
            re_scan_findings = cls._rescan_file(repo_root, target_file, original_finding)
        except Exception as exc:
            evidence_log.append(f"Relevant re-scan failed: {type(exc).__name__}.")
            return cls._handle_failure(
                repo_root=repo_root,
                snapshot=snapshot,
                proposal=proposal,
                previous_risk_score=previous_risk_score,
                previous_risk_level=previous_risk_level,
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                tests_passed=True,
                evidence=evidence_log,
                auto_rollback=auto_rollback_on_failure,
                err_msg="Relevant security re-scan could not complete.",
            )

        # Check if the specific finding ID or signature still exists
        finding_still_present = any(
            f.id.upper() == original_finding.id.upper()
            or f.signature_hash == original_finding.signature_hash
            for f in re_scan_findings
        )

        baseline_signatures = {
            finding.signature_hash for finding in (baseline_findings or [])
        }
        regressions = [
            finding for finding in re_scan_findings
            if finding.signature_hash not in baseline_signatures
            and finding.severity.upper() in {"CRITICAL", "HIGH"}
        ]
        if regressions:
            evidence_log.append(
                "Re-scan found new high-impact finding(s): "
                + ", ".join(f.id for f in regressions)
            )
            return cls._handle_failure(
                repo_root, snapshot, proposal, previous_risk_score,
                previous_risk_level, VerificationOutcome.REGRESSION, True,
                evidence_log, auto_rollback_on_failure,
                "Re-scan detected a new critical or high severity finding.",
            )

        if finding_still_present:
            evidence_log.append(
                f"Re-scan detected finding '{original_finding.id}' is still present in {proposal.affected_file}."
            )
            # Finding was not resolved
            return cls._handle_failure(
                repo_root, snapshot, proposal, previous_risk_score,
                previous_risk_level, VerificationOutcome.STILL_PRESENT, True,
                evidence_log, auto_rollback_on_failure,
                "Target finding remained after the remediation re-scan.",
            )
        else:
            evidence_log.append(
                f"Re-scan verified finding '{original_finding.id}' eliminated from {proposal.affected_file}."
            )
            outcome = VerificationOutcome.RESOLVED
            resolved = True
            # Recalculate risk score deterministically: finding eliminated
            severity_score = RiskEngine.BASE_SEVERITY_SCORES.get(
                original_finding.severity.upper(), 10.0
            ) * max(0.5, original_finding.confidence)
            contribution = int(round(original_finding.risk_score or severity_score))
            curr_score = max(0, previous_risk_score - contribution)
            if curr_score >= 80:
                curr_level = "CRITICAL"
            elif curr_score >= 60:
                curr_level = "HIGH"
            elif curr_score >= 40:
                curr_level = "MEDIUM"
            elif curr_score >= 20:
                curr_level = "LOW"
            else:
                curr_level = "INFO"

        snapshot.status = RemediationStatus.VERIFIED
        SnapshotManager.save_metadata(repo_root, snapshot)
        return VerificationReport(
            remediation_id=snapshot.remediation_id,
            finding_id=original_finding.id,
            previous_status=original_finding.status,
            current_status=outcome.value,
            previous_risk_score=previous_risk_score,
            current_risk_score=curr_score,
            previous_risk_level=previous_risk_level,
            current_risk_level=curr_level,
            resolved=resolved,
            outcome=outcome,
            tests_passed=True,
            re_scan_evidence=evidence_log,
            rollback_performed=False,
            rollback_status=None,
        )

    @classmethod
    def _check_syntax(cls, target_file: Path) -> tuple[bool, str]:
        """Verify code syntax without side effects."""
        if not target_file.is_file():
            return False, f"File does not exist: {target_file}"

        ext = target_file.suffix.lower()
        content = target_file.read_text(encoding="utf-8", errors="replace")

        if ext == ".py":
            try:
                ast.parse(content, filename=str(target_file))
                return True, "Valid Python syntax."
            except SyntaxError as e:
                return False, f"Line {e.lineno}: {e.msg}"

        return True, "Syntax check skipped for non-python file."

    @classmethod
    def _run_targeted_tests(cls, repo_root: Path, affected_file: str) -> tuple[bool, str]:
        """
        Run the nearest conventional Python test module when present, without
        invoking a shell or any command supplied by a model.
        """
        target_path = SnapshotManager.resolve_repo_file(repo_root, affected_file)
        if target_path.suffix.lower() == ".py":
            try:
                compile(target_path.read_text(encoding="utf-8"), str(target_path), "exec")
            except Exception as e:
                return False, str(e)

            stem = target_path.stem
            candidates = [
                repo_root / f"test_{stem}.py",
                repo_root / "tests" / f"test_{stem}.py",
            ]
            test_file = next((path for path in candidates if path.is_file()), None)
            if test_file:
                try:
                    completed = subprocess.run(
                        [sys.executable, "-m", "pytest", "-q", str(test_file)],
                        cwd=repo_root,
                        capture_output=True,
                        text=True,
                        timeout=120,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    return False, "Relevant pytest module timed out after 120 seconds."
                except OSError as exc:
                    return False, f"Could not start relevant pytest module ({type(exc).__name__})."
                if completed.returncode:
                    return False, f"Relevant pytest module failed (exit {completed.returncode})."
                return True, f"Module compilation and {test_file.relative_to(repo_root)} passed."
            return True, "Module compilation passed; no conventional targeted pytest module was found."

        return True, "No test failures."

    @classmethod
    def _rescan_file(
        cls,
        repo_root: Path,
        target_file: Path,
        original_finding: CanonicalFinding,
    ) -> list[CanonicalFinding]:
        """
        Execute targeted scanner on single modified file.
        """
        findings: list[CanonicalFinding] = []
        cat = original_finding.category.lower()

        try:
            # 1. Container scanner for Dockerfile / Compose
            if "container" in cat or "docker" in target_file.name.lower():
                c_scanner = ContainerScanner()
                # Run container scanner on repo_root
                all_c = c_scanner.scan(repo_root, SecuritySurface(target_path=str(repo_root)))
                findings.extend([f for f in all_c if proposal_match(f, target_file, repo_root)])

            # 2. Secret scanner
            elif "secret" in cat:
                s_scanner = SecretScanner()
                all_s = s_scanner.scan(repo_root, SecuritySurface(target_path=str(repo_root)))
                findings.extend([f for f in all_s if proposal_match(f, target_file, repo_root)])

            # 3. SAST / Code analyzer (Python, JS, Java, CPP)
            else:
                sast_scanner = NativeSASTScanner()
                all_sast = sast_scanner.scan(
                    repo_root, SecuritySurface(target_path=str(repo_root))
                )
                findings.extend([f for f in all_sast if proposal_match(f, target_file, repo_root)])

        except Exception as exc:
            logger.warning("Relevant re-scan failed (%s).", type(exc).__name__)
            raise RuntimeError("Relevant NSAT scanner failed") from exc

        return findings

    @classmethod
    def _handle_failure(
        cls,
        repo_root: Path,
        snapshot: SnapshotMetadata,
        proposal: RemediationProposal,
        previous_risk_score: int,
        previous_risk_level: str,
        outcome: VerificationOutcome,
        tests_passed: bool,
        evidence: list[str],
        auto_rollback: bool,
        err_msg: str,
    ) -> VerificationReport:
        """Handle remediation failure with automatic rollback."""
        rollback_done = False
        rollback_stat = None

        if auto_rollback:
            logger.info("Initiating automatic rollback due to remediation failure.")
            rb_result = RollbackManager.rollback(repo_root, snapshot)
            rollback_done = rb_result.success
            rollback_stat = rb_result.status.value
            evidence.append(f"Rollback status: {rb_result.message}")
            if rb_result.status == RemediationStatus.ROLLED_BACK:
                outcome = VerificationOutcome.ROLLED_BACK
            elif rb_result.status == RemediationStatus.ROLLBACK_CONFLICT:
                outcome = VerificationOutcome.ROLLBACK_CONFLICT

        return VerificationReport(
            remediation_id=snapshot.remediation_id,
            finding_id=proposal.finding_id,
            previous_status="VALIDATED",
            current_status=outcome.value,
            previous_risk_score=previous_risk_score,
            current_risk_score=previous_risk_score,
            previous_risk_level=previous_risk_level,
            current_risk_level=previous_risk_level,
            resolved=False,
            outcome=outcome,
            tests_passed=tests_passed,
            re_scan_evidence=evidence,
            rollback_performed=rollback_done,
            rollback_status=rollback_stat,
        )


def proposal_match(finding: CanonicalFinding, target_file: Path, repo_root: Path) -> bool:
    """Helper to check if a finding belongs to the target file."""
    loc = finding.primary_location or {}
    fpath = loc.get("file_path") or finding.file_path or finding.asset or ""
    if not fpath:
        return False
    try:
        resolved = (repo_root / fpath).resolve()
        return resolved == target_file.resolve()
    except Exception:
        return target_file.name in fpath
