"""Report generation manager and artifact file saver for NSAT."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from nsat.correlation.models import Phase4SecurityModel
from nsat.reporting.json_exporter import export_json_str
from nsat.reporting.markdown_exporter import export_markdown_report
from nsat.reporting.terminal import console, print_terminal_report


class ReportManager:
    """Orchestrates report formatting, terminal display, and file persistence."""

    @classmethod
    def generate_and_save(
        cls,
        model: Phase4SecurityModel,
        format_type: str = "terminal",
        output_path: Optional[str] = None,
        save_file: bool = True,
    ) -> Path | None:
        """
        Render report and save to reports/ directory.

        Args:
            model: Populated Phase4SecurityModel
            format_type: "terminal", "json", "markdown"
            output_path: Optional explicit file path
            save_file: Whether to save report to reports/ dir (default True)

        Returns:
            Saved file Path if written, else None
        """
        # Render terminal report if requested
        if format_type == "terminal":
            print_terminal_report(model)

        # Prepare directory and filename
        saved_file: Optional[Path] = None
        if save_file or output_path:
            if output_path:
                target_file = Path(output_path).resolve()
                target_file.parent.mkdir(parents=True, exist_ok=True)
            else:
                reports_dir = Path("reports").resolve()
                reports_dir.mkdir(parents=True, exist_ok=True)
                ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                ext = "json" if format_type == "json" else "md"
                target_file = reports_dir / f"nsat-report-{ts}.{ext}"

            # Generate content according to format
            if format_type == "json":
                content = export_json_str(model)
            else:
                content = export_markdown_report(model)

            target_file.write_text(content, encoding="utf-8")
            saved_file = target_file

            if format_type == "terminal":
                console.print(f"\n[green][OK] Comprehensive security report saved to:[/] [bold]{target_file}[/bold]")

        return saved_file
