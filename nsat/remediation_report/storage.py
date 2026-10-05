"""
Storage and file-management utilities for NSAT Remediation Change Reports.

Handles default output locations, filename formatting, path resolution,
and artifact persistence for generated PDF reports.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class ReportStorage:
    """Manages output directory, path resolution, and artifact saving for reports."""

    DEFAULT_REPORTS_DIR = Path("reports/remediations")

    @classmethod
    def sanitize_filename_component(cls, val: str) -> str:
        """Sanitize a string for safe use in file paths across OSes."""
        if not val:
            return "unknown"
        # Replace path separators, colons, spaces, and non-alphanumeric chars
        sanitized = re.sub(r"[^\w\-.]", "_", val)
        return re.sub(r"_+", "_", sanitized).strip("_")

    @classmethod
    def resolve_output_path(
        cls,
        finding_id: str,
        remediation_id: Optional[str] = None,
        output_path: Optional[str | Path] = None,
        base_dir: Optional[str | Path] = None,
    ) -> Path:
        """
        Determine the absolute output Path for a remediation report PDF.

        If `output_path` is explicitly provided, it is returned resolved.
        Otherwise, a canonical file path under `base_dir` (default: reports/remediations/)
        is computed using finding ID, remediation ID, and current timestamp.
        """
        if output_path is not None:
            target = Path(output_path).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            return target

        directory = Path(base_dir).resolve() if base_dir else cls.DEFAULT_REPORTS_DIR.resolve()
        directory.mkdir(parents=True, exist_ok=True)

        clean_fid = cls.sanitize_filename_component(finding_id)
        clean_rid = (
            cls.sanitize_filename_component(remediation_id)
            if remediation_id
            else "proposal"
        )
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{clean_fid}_remediation_{clean_rid}_{ts}.pdf"
        return directory / filename

    @classmethod
    def save_bytes(cls, data: bytes, target_path: Path | str) -> Path:
        """Save raw PDF bytes to disk, creating parent directories if needed."""
        path = Path(target_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    @classmethod
    def list_reports(cls, base_dir: Optional[str | Path] = None) -> list[Path]:
        """List all PDF report files in the reports directory, sorted newest first."""
        directory = Path(base_dir).resolve() if base_dir else cls.DEFAULT_REPORTS_DIR.resolve()
        if not directory.exists():
            return []
        pdf_files = list(directory.glob("*.pdf"))
        pdf_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return pdf_files
