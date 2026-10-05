"""Minimal Targeted Patch Applicator and Validator for NSAT Remediation."""

import difflib
import logging
from pathlib import Path
from typing import Optional

from nsat.remediation.models import RemediationProposal, RemediationStatus, SnapshotMetadata
from nsat.remediation.snapshot import SnapshotManager

logger = logging.getLogger("nsat.remediation.patcher")


class PatchApplicationResult:
    """Detailed result of patch application."""

    def __init__(
        self,
        success: bool,
        message: str,
        affected_file: str,
        pre_patch_hash: str = "",
        post_patch_hash: str = "",
        diff_applied: str = "",
    ):
        self.success = success
        self.message = message
        self.affected_file = affected_file
        self.pre_patch_hash = pre_patch_hash
        self.post_patch_hash = post_patch_hash
        self.diff_applied = diff_applied


class Patcher:
    """
    Applies surgical, minimal code and configuration modifications.
    Enforces strict pre-patch validation and exact context matching.
    """

    @classmethod
    def validate_proposal(
        cls,
        repo_root: Path,
        proposal: RemediationProposal,
        snapshot: Optional[SnapshotMetadata] = None,
    ) -> tuple[bool, str]:
        """
        Validate that the proposal targets an existing file, has exact matching context,
        and matches snapshot hashes.
        """
        try:
            target_file = SnapshotManager.resolve_repo_file(repo_root, proposal.affected_file)
        except ValueError as exc:
            return False, f"Patch rejected safely. {exc}"
        if not target_file.is_file():
            return False, f"Target file does not exist: {proposal.affected_file}"

        # Check snapshot pre-patch hash if snapshot provided
        if snapshot:
            expected_hash = snapshot.original_hashes.get(proposal.affected_file)
            if expected_hash:
                curr_hash = SnapshotManager.compute_sha256(target_file)
                if curr_hash != expected_hash:
                    return False, "Target file hash does not match pre-remediation snapshot (stale patch)."

        # Check that original snippet exists in the target file
        file_content = target_file.read_text(encoding="utf-8", errors="replace")
        clean_orig = proposal.original_snippet.strip()
        if clean_orig and clean_orig not in file_content:
            return False, "Original code snippet not found in target file (context mismatch)."
        if not clean_orig or not proposal.replacement_snippet.strip():
            return False, "Patch rejected: original and replacement snippets must be non-empty."
        if file_content.count(clean_orig) != 1:
            return False, "Patch rejected: original context is ambiguous; expected exactly one match."

        # The applier performs a bounded single-file replacement rather than
        # interpreting model-provided diff syntax. Reject diffs that advertise
        # modifications to another path so the reviewed proposal matches scope.
        diff_paths = [
            line[4:].strip() for line in proposal.proposed_patch.splitlines()
            if line.startswith(("--- ", "+++ "))
        ]
        if diff_paths:
            expected = {f"a/{proposal.affected_file}", f"b/{proposal.affected_file}"}
            if len(diff_paths) != 2 or set(diff_paths) != expected:
                return False, "Patch rejected: diff contains unexpected file scope."

        # Reject empty replacement or entire file replacement (> 80% of file)
        if len(file_content.splitlines()) > 5:
            replaced_lines = len(clean_orig.splitlines())
            if replaced_lines >= len(file_content.splitlines()) * 0.8:
                return False, "Patch rejected: proposed change replaces majority of file (violates minimal patching rule)."

        return True, "Patch validation passed."

    @classmethod
    def apply_patch(
        cls,
        repo_root: Path,
        proposal: RemediationProposal,
        snapshot: SnapshotMetadata,
    ) -> PatchApplicationResult:
        """
        Apply surgical modification to target file.
        Updates target file on disk and computes post-patch hash.
        """
        val_ok, val_msg = cls.validate_proposal(repo_root, proposal, snapshot)
        if not val_ok:
            return PatchApplicationResult(
                success=False,
                message=f"Patch rejected safely. {val_msg}",
                affected_file=proposal.affected_file,
            )

        target_file = SnapshotManager.resolve_repo_file(repo_root, proposal.affected_file)
        content = target_file.read_text(encoding="utf-8")
        pre_hash = SnapshotManager.compute_sha256(target_file)

        # Apply surgical replacement
        orig = proposal.original_snippet.strip()
        repl = proposal.replacement_snippet.strip()

        if orig in content:
            new_content = content.replace(orig, repl, 1)
        else:
            return PatchApplicationResult(
                success=False,
                message="Target snippet could not be matched for replacement.",
                affected_file=proposal.affected_file,
            )

        # Write safely
        target_file.write_text(new_content, encoding="utf-8")
        post_hash = SnapshotManager.compute_sha256(target_file)

        # Generate applied diff for confirmation
        orig_lines = content.splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)
        diff_lines = list(
            difflib.unified_diff(
                orig_lines,
                new_lines,
                fromfile=f"a/{proposal.affected_file}",
                tofile=f"b/{proposal.affected_file}",
                n=3,
            )
        )
        diff_str = "".join(diff_lines)

        # Record post-patch hash in snapshot metadata
        snapshot.post_patch_hashes[proposal.affected_file] = post_hash
        snapshot.status = RemediationStatus.APPLIED
        meta_file = repo_root / ".nsat" / "remediation" / snapshot.remediation_id / "metadata.json"
        if meta_file.parent.is_dir():
            meta_file.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")

        return PatchApplicationResult(
            success=True,
            message="Patch applied successfully.",
            affected_file=proposal.affected_file,
            pre_patch_hash=pre_hash,
            post_patch_hash=post_hash,
            diff_applied=diff_str or proposal.proposed_patch,
        )
