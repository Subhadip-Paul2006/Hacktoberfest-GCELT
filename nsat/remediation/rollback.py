"""Safe Rollback Engine with Conflict Detection for NSAT Remediation."""

import logging
import shutil
from pathlib import Path
from typing import Optional

from nsat.remediation.models import RemediationStatus, SnapshotMetadata
from nsat.remediation.snapshot import SnapshotManager

logger = logging.getLogger("nsat.remediation.rollback")


class RollbackResult:
    """Outcome of a rollback operation."""

    def __init__(
        self,
        success: bool,
        status: RemediationStatus,
        message: str,
        restored_files: list[str],
        conflicted_files: list[str],
    ):
        self.success = success
        self.status = status
        self.message = message
        self.restored_files = restored_files
        self.conflicted_files = conflicted_files


class RollbackManager:
    """
    Safely reverts applied remediation patches to pre-remediation snapshots.
    Guards against overwriting user modifications made after patch application.
    """

    @classmethod
    def rollback(
        cls,
        repo_root: Path,
        metadata: SnapshotMetadata,
        force: bool = False,
    ) -> RollbackResult:
        """
        Rollback modified files to the backed-up state.

        Safety Protocol:
        1. Compare current file hash on disk with post_patch_hash.
        2. If current file matches post_patch_hash (or force=True):
           - Copy backed-up version into place.
           - Verify restored file hash matches original_hash.
        3. If file was edited *after* patch application:
           - Skip automatic restoration to avoid clobbering user changes.
           - Flag ROLLBACK_CONFLICT.
        """
        backup_dir = Path(metadata.backup_dir)
        if not backup_dir.is_dir():
            return RollbackResult(
                success=False,
                status=RemediationStatus.FAILED,
                message=f"Backup directory not found: {backup_dir}",
                restored_files=[],
                conflicted_files=metadata.affected_files,
            )

        restored_files: list[str] = []
        conflicted_files: list[str] = []

        # 1. Pre-flight conflict check across all affected files
        for rel_path in metadata.affected_files:
            curr_file = repo_root / rel_path
            expected_post_hash = metadata.post_patch_hashes.get(rel_path)

            if curr_file.is_file() and expected_post_hash and not force:
                curr_hash = SnapshotManager.compute_sha256(curr_file)
                # If file changed from what the patch produced, conflict!
                if curr_hash != expected_post_hash and curr_hash != metadata.original_hashes.get(rel_path):
                    conflicted_files.append(rel_path)

        if conflicted_files and not force:
            conflict_msg = (
                f"Rollback conflict detected: {', '.join(conflicted_files)} modified after patch. "
                "Automatic rollback aborted to prevent data loss."
            )
            logger.warning(conflict_msg)
            metadata.status = RemediationStatus.ROLLBACK_CONFLICT
            cls._save_metadata(repo_root, metadata)
            return RollbackResult(
                success=False,
                status=RemediationStatus.ROLLBACK_CONFLICT,
                message=conflict_msg,
                restored_files=[],
                conflicted_files=conflicted_files,
            )

        # 2. Execute file restorations
        for rel_path in metadata.affected_files:
            source_backup = backup_dir / rel_path
            target_dest = repo_root / rel_path

            if not source_backup.is_file():
                logger.error(f"Missing backup file: {source_backup}")
                continue

            target_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_backup, target_dest)

            # Integrity verification
            restored_hash = SnapshotManager.compute_sha256(target_dest)
            expected_orig_hash = metadata.original_hashes.get(rel_path)

            if expected_orig_hash and restored_hash != expected_orig_hash:
                logger.critical(
                    f"Restored file '{rel_path}' integrity check failed! "
                    f"Expected {expected_orig_hash}, got {restored_hash}"
                )
            else:
                restored_files.append(rel_path)

        metadata.status = RemediationStatus.ROLLED_BACK
        cls._save_metadata(repo_root, metadata)

        msg = f"Successfully rolled back {len(restored_files)} file(s) to original snapshot state."
        logger.info(msg)
        return RollbackResult(
            success=True,
            status=RemediationStatus.ROLLED_BACK,
            message=msg,
            restored_files=restored_files,
            conflicted_files=[],
        )

    @staticmethod
    def _save_metadata(repo_root: Path, metadata: SnapshotMetadata) -> None:
        """Persist updated snapshot metadata."""
        meta_file = repo_root / ".nsat" / "remediation" / metadata.remediation_id / "metadata.json"
        if meta_file.parent.is_dir():
            meta_file.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")
