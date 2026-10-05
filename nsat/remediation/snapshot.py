"""Reversible Snapshot & Backup Manager for NSAT Remediation."""

import hashlib
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from nsat.remediation.models import RemediationStatus, SnapshotMetadata

logger = logging.getLogger("nsat.remediation.snapshot")


class SnapshotManager:
    """
    Manages pre-remediation filesystem snapshots, integrity digests,
    and reversible backup archives in `.nsat/remediation/`.
    """

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Compute SHA-256 digest of a file."""
        if not file_path.is_file():
            return ""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    @classmethod
    def create_snapshot(
        cls,
        repo_root: Path,
        finding_id: str,
        affected_files: list[str],
        proposed_patch: str,
        audit_id: Optional[str] = None,
    ) -> SnapshotMetadata:
        """
        Create isolated filesystem backup of affected files prior to patch application.
        Directory structure:
          .nsat/remediation/<remediation_id>/
            ├── metadata.json
            ├── patch.diff
            └── backup/
                └── <relative_path>/<file>
        """
        clean_finding = finding_id.replace(":", "_").replace("/", "_")
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        remediation_id = f"REM-{clean_finding}-{timestamp_str}"

        remediation_dir = repo_root / ".nsat" / "remediation" / remediation_id
        backup_dir = remediation_dir / "backup"
        backup_dir.mkdir(parents=True, exist_ok=True)

        original_hashes: dict[str, str] = {}
        saved_files: list[str] = []

        for rel_path in affected_files:
            target_file = (repo_root / rel_path).resolve()
            if not target_file.exists():
                logger.warning(f"File marked for backup does not exist: {target_file}")
                continue

            file_hash = cls.compute_sha256(target_file)
            original_hashes[rel_path] = file_hash

            # Copy to backup preserving directory structure
            dest_file = backup_dir / rel_path
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target_file, dest_file)
            saved_files.append(rel_path)

        # Write patch.diff
        patch_file = remediation_dir / "patch.diff"
        patch_file.write_text(proposed_patch, encoding="utf-8")

        metadata = SnapshotMetadata(
            remediation_id=remediation_id,
            finding_id=finding_id,
            audit_id=audit_id,
            repository_root=str(repo_root.resolve()),
            affected_files=saved_files,
            original_hashes=original_hashes,
            proposed_patch=proposed_patch,
            status=RemediationStatus.BACKED_UP,
            backup_dir=str(backup_dir.resolve()),
        )

        metadata_file = remediation_dir / "metadata.json"
        metadata_file.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")

        logger.info(f"Created pre-remediation snapshot '{remediation_id}' for {len(saved_files)} file(s).")
        return metadata

    @classmethod
    def verify_pre_patch_integrity(cls, repo_root: Path, metadata: SnapshotMetadata) -> tuple[bool, str]:
        """
        Verify that files on disk still match the exact hashes recorded during snapshot creation.
        Guards against overwriting newer edits made by the user.
        """
        for rel_path, expected_hash in metadata.original_hashes.items():
            curr_file = repo_root / rel_path
            if not curr_file.exists():
                return False, f"Target file '{rel_path}' does not exist on disk."

            curr_hash = cls.compute_sha256(curr_file)
            if curr_hash != expected_hash:
                return False, f"Target file '{rel_path}' was modified after analysis (hash mismatch)."

        return True, "Pre-patch integrity verified."

    @classmethod
    def save_metadata(cls, repo_root: Path, metadata: SnapshotMetadata) -> None:
        """Persist snapshot metadata to disk."""
        meta_file = repo_root / ".nsat" / "remediation" / metadata.remediation_id / "metadata.json"
        meta_file.parent.mkdir(parents=True, exist_ok=True)
        meta_file.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load_snapshot(cls, repo_root: Path, remediation_id: str) -> Optional[SnapshotMetadata]:
        """Load snapshot metadata from disk."""
        meta_file = repo_root / ".nsat" / "remediation" / remediation_id / "metadata.json"
        if not meta_file.exists():
            return None
        try:
            return SnapshotMetadata.model_validate_json(meta_file.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error(f"Failed to parse snapshot metadata '{remediation_id}': {e}")
            return None

    @classmethod
    def list_snapshots(cls, repo_root: Path) -> list[SnapshotMetadata]:
        """List all historical remediation snapshots in reverse chronological order."""
        base_dir = repo_root / ".nsat" / "remediation"
        if not base_dir.is_dir():
            return []

        snapshots: list[SnapshotMetadata] = []
        for d in sorted(base_dir.iterdir(), reverse=True):
            if d.is_dir():
                meta_file = d / "metadata.json"
                if meta_file.is_file():
                    try:
                        snap = SnapshotMetadata.model_validate_json(meta_file.read_text(encoding="utf-8"))
                        snapshots.append(snap)
                    except Exception:
                        pass
        return snapshots
