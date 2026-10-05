"""
Remediation Manager for NSAT (Phase 4C).

Orchestrates the complete lifecycle of finding fixes:
1. Load latest audit/security context.
2. Formulate targeted proposal via RemediationPlanner (Kimi-K3 or deterministic rules).
3. Create pre-patch snapshot & backup via SnapshotManager (.nsat/remediation/<id>/).
4. Prompt for user confirmation (or auto-approve via --yes).
5. Apply minimal targeted diff via Patcher.
6. Run syntax checks, tests, and re-scans via VerificationEngine.
7. Automatically roll back on failure or conflict via RollbackManager.
8. Persist remediation history in .nsat/remediation/history.json.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from nsat.ai.kimi import KimiProvider
from nsat.correlation.models import Phase4SecurityModel
from nsat.normalization.models import CanonicalFinding
from nsat.remediation.models import (
    RemediationProposal,
    RemediationStatus,
    SnapshotMetadata,
    VerificationOutcome,
    VerificationReport,
)
from nsat.remediation.patcher import Patcher
from nsat.remediation.planner import RemediationPlanner
from nsat.remediation.rollback import RollbackManager, RollbackResult
from nsat.remediation.snapshot import SnapshotManager
from nsat.remediation.verifier import VerificationEngine

logger = logging.getLogger("nsat.remediation.manager")


class RemediationManager:
    """Central orchestrator for Phase 4C Remediation and Verification workflows."""

    @classmethod
    def get_history_file(cls, repo_root: Path) -> Path:
        """Get path to the local remediation history registry."""
        hist_dir = repo_root / ".nsat" / "remediation"
        hist_dir.mkdir(parents=True, exist_ok=True)
        return hist_dir / "history.json"

    @classmethod
    def load_history(cls, repo_root: Path) -> list[dict]:
        """Load persistent remediation log records."""
        hist_file = cls.get_history_file(repo_root)
        if hist_file.is_file():
            try:
                return json.loads(hist_file.read_text(encoding="utf-8"))
            except Exception:
                return []
        return []

    @classmethod
    def record_history(cls, repo_root: Path, entry: dict) -> None:
        """Append an entry to remediation history."""
        hist = cls.load_history(repo_root)
        hist.append(entry)
        hist_file = cls.get_history_file(repo_root)
        hist_file.write_text(json.dumps(hist, indent=2), encoding="utf-8")

    @classmethod
    def fix_finding(
        cls,
        finding_id: str,
        repo_root: Path,
        security_model: Phase4SecurityModel,
        provider: Optional[KimiProvider] = None,
        dry_run: bool = False,
        auto_approve: bool = False,
        console: Optional[Console] = None,
    ) -> Optional[VerificationReport]:
        """
        Execute full end-to-end remediation flow for finding_id.
        """
        con = console or Console()

        con.print(f"\n[bold cyan]NSAT REMEDIATION[/bold cyan] -- Target: [bold yellow]{finding_id}[/bold yellow]\n")

        # 1. Locate finding
        target_finding: Optional[CanonicalFinding] = None
        for f in security_model.findings:
            if f.id.upper() == finding_id.upper() or finding_id.upper() in f.id.upper():
                target_finding = f
                break

        if not target_finding:
            con.print(f"[bold red][X] Finding '{finding_id}' not found in current security model.[/bold red]")
            return None

        # 2. Plan proposal
        con.print(f"  [dim]-> Planning minimal patch via {'Kimi-K3' if (provider and provider.config.is_configured()) else 'Deterministic Rule Engine'}...[/dim]")
        proposal = RemediationPlanner.plan(
            finding_id=target_finding.id,
            repo_root=repo_root,
            model=security_model,
            provider=provider,
        )

        if not proposal:
            con.print(f"[bold red][X] Failed to generate targeted patch proposal for '{finding_id}'.[/bold red]")
            return None

        # 3. Present proposal to user
        diff_text = proposal.proposed_patch or (
            f"--- a/{proposal.affected_file}\n+++ b/{proposal.affected_file}\n"
            f"- {proposal.original_snippet}\n+ {proposal.replacement_snippet}\n"
        )
        syntax_diff = Syntax(diff_text, "diff", theme="monokai", line_numbers=True)

        info_panel = (
            f"[bold white]Finding:[/] {proposal.finding_id}\n"
            f"[bold white]Root Cause:[/] {proposal.root_cause}\n"
            f"[bold white]Recommended Fix:[/] {proposal.recommended_change}\n"
            f"[bold white]Target File:[/] {proposal.affected_file} (Lines: {proposal.affected_lines})\n"
            f"[bold white]Reason:[/] {proposal.reason}\n"
            f"[bold white]Potential Side Effects:[/] {proposal.potential_side_effects}\n"
            f"[bold white]Verification Plan:[/] {proposal.verification_plan}"
        )
        con.print(Panel(info_panel, title="Remediation Proposal", border_style="cyan"))
        con.print("\n[bold cyan]Proposed Patch:[/bold cyan]")
        con.print(syntax_diff)

        # 4. Handle --dry-run
        if dry_run:
            con.print("\n[bold yellow][DRY-RUN] Dry run mode enabled. No files modified. No backup created.[/bold yellow]\n")
            return None

        # 5. User confirmation if not auto_approve
        if not auto_approve:
            import click
            if not click.confirm("\nApply this surgical patch to your repository?", default=True):
                con.print("[yellow]Remediation cancelled by user. Working tree unchanged.[/yellow]")
                return None

        # 6. Create Mandatory Pre-Patch Snapshot & Backup
        con.print("\n  [dim]-> Creating pre-patch snapshot & backup...[/dim]")
        audit_id_val = getattr(security_model, "audit_id", None) or security_model.project.get("audit_id")
        snapshot = SnapshotManager.create_snapshot(
            repo_root=repo_root,
            finding_id=target_finding.id,
            affected_files=[proposal.affected_file],
            proposed_patch=diff_text,
            audit_id=audit_id_val,
        )
        con.print(f"  [bold green][OK] Snapshot created:[/] [dim]{snapshot.remediation_id}[/dim]")
        con.print(f"  [dim]    Backup location: {snapshot.backup_dir}[/dim]")

        # 7. Apply Patch
        con.print("  [dim]-> Applying minimal targeted patch...[/dim]")
        patch_res = Patcher.apply_patch(repo_root, proposal, snapshot)
        if not patch_res.success:
            con.print(f"[bold red][X] {patch_res.message}[/bold red]")
            # Attempt rollback if modified
            RollbackManager.rollback(repo_root, snapshot)
            return None

        con.print("  [bold green][OK] Patch applied successfully.[/bold green]")

        # 8. Run Verification Pipeline (Syntax -> Tests -> Re-scan -> Risk -> VerificationReport)
        con.print("  [dim]-> Running verification pipeline (syntax, tests, re-scan)...[/dim]")
        report = VerificationEngine.verify(
            repo_root=repo_root,
            proposal=proposal,
            snapshot=snapshot,
            original_finding=target_finding,
            previous_risk_score=security_model.risk.overall_score,
            previous_risk_level=security_model.risk.risk_level,
            auto_rollback_on_failure=True,
        )

        # 9. Print Before / After Verification Report
        cls._print_verification_report(con, report, snapshot)

        # 10. Record history
        cls.record_history(
            repo_root=repo_root,
            entry={
                "remediation_id": snapshot.remediation_id,
                "finding_id": target_finding.id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "affected_files": [proposal.affected_file],
                "outcome": report.outcome.value,
                "tests_passed": report.tests_passed,
                "resolved": report.resolved,
                "previous_risk_score": report.previous_risk_score,
                "current_risk_score": report.current_risk_score,
                "rollback_performed": report.rollback_performed,
                "rollback_status": report.rollback_status,
            },
        )

        return report

    @classmethod
    def rollback_remediation(
        cls,
        remediation_id: str,
        repo_root: Path,
        force: bool = False,
        console: Optional[Console] = None,
    ) -> RollbackResult:
        """Roll back a previous remediation action by remediation_id."""
        con = console or Console()
        con.print(f"\n[bold cyan]NSAT ROLLBACK[/bold cyan] -- Remediation ID: [bold yellow]{remediation_id}[/bold yellow]\n")

        snapshot = SnapshotManager.load_snapshot(repo_root, remediation_id)
        if not snapshot:
            con.print(f"[bold red][X] Snapshot '{remediation_id}' not found in .nsat/remediation/[/bold red]")
            return RollbackResult(
                success=False,
                status=RemediationStatus.FAILED,
                message=f"Snapshot '{remediation_id}' not found.",
                restored_files=[],
                conflicted_files=[],
            )

        res = RollbackManager.rollback(repo_root, snapshot, force=force)
        if res.success:
            con.print(f"[bold green][OK] {res.message}[/bold green]")
            for f in res.restored_files:
                con.print(f"  [dim]-> Restored:[/] {f}")
        else:
            con.print(f"[bold red][X] Rollback failed:[/] {res.message}")
            for f in res.conflicted_files:
                con.print(f"  [bold red]-> Conflict in:[/] {f} (modified after patch)")

        return res

    @classmethod
    def _print_verification_report(
        cls,
        con: Console,
        report: VerificationReport,
        snapshot: SnapshotMetadata,
    ) -> None:
        """Display authoritative Before vs After report."""
        stat_color = "bold green" if report.resolved else "bold red"
        lines = [
            f"[bold white]Finding:[/] {report.finding_id}",
            f"[bold white]Remediation ID:[/] {report.remediation_id}",
            f"[bold white]Backup Location:[/] {snapshot.backup_dir}\n",
            "[bold cyan]Before Remediation:[/bold cyan]",
            f"  Status: {report.previous_status}",
            f"  Risk Score: {report.previous_risk_score}/100 ({report.previous_risk_level})\n",
            "[bold cyan]Verification Checks:[/bold cyan]",
            f"  Tests: {'[bold green][OK] Passed[/bold green]' if report.tests_passed else '[bold red][X] Failed[/bold red]'}",
        ]

        for ev in report.re_scan_evidence:
            lines.append(f"  Re-scan: {ev}")

        lines.extend([
            "\n[bold cyan]After Remediation:[/bold cyan]",
            f"  Final Status: [{stat_color}]{report.outcome.value}[/{stat_color}]",
            f"  Risk Score: {report.current_risk_score}/100 ({report.current_risk_level})",
        ])

        if report.rollback_performed:
            lines.extend([
                "\n[bold yellow]Rollback Action:[/bold yellow]",
                f"  Status: {report.rollback_status or 'ROLLED_BACK'}",
                "  Working tree restored to original snapshot state.",
            ])

        con.print(Panel("\n".join(lines), title="NSAT Remediation & Verification Report", border_style="cyan"))
