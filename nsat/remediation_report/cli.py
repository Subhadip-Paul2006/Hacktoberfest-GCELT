"""
Command-line interface for generating NSAT Remediation Change Reports.

Usage:
    python -m nsat.remediation_report --finding finding.json --proposal proposal.json --output report.pdf
    python -m nsat.remediation_report --list
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from nsat.normalization.models import CanonicalFinding
from nsat.remediation.models import RemediationProposal, SnapshotMetadata
from nsat.remediation_report.service import generate_remediation_report
from nsat.remediation_report.storage import ReportStorage


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nsat-remediation-report",
        description="Generate human-readable AI Remediation Change Reports in PDF format.",
    )
    parser.add_argument(
        "--finding",
        "-f",
        type=str,
        help="Path to JSON file containing a CanonicalFinding",
    )
    parser.add_argument(
        "--proposal",
        "-p",
        type=str,
        help="Path to JSON file containing a RemediationProposal",
    )
    parser.add_argument(
        "--snapshot",
        "-s",
        type=str,
        default=None,
        help="Optional path to JSON file containing SnapshotMetadata",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Target output PDF file path (default: reports/remediations/<finding>_remediation_<ts>.pdf)",
    )
    parser.add_argument(
        "--project",
        type=str,
        default="NSAT Audited Project",
        help="Project display name",
    )
    parser.add_argument(
        "--audit-id",
        type=str,
        default=None,
        help="Optional audit session identifier",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all generated remediation change reports",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.list:
        reports = ReportStorage.list_reports()
        if not reports:
            print("No remediation change reports found in reports/remediations/")
            return 0
        print(f"Found {len(reports)} remediation change reports:")
        for r in reports:
            print(f"  - {r.name} ({r.stat().st_size:,} bytes) -> {r}")
        return 0

    if not args.finding or not args.proposal:
        parser.print_help()
        print("\nError: Both --finding and --proposal are required unless --list is specified.")
        return 1

    finding_path = Path(args.finding).resolve()
    proposal_path = Path(args.proposal).resolve()

    if not finding_path.exists():
        print(f"Error: Finding file not found: {finding_path}", file=sys.stderr)
        return 1
    if not proposal_path.exists():
        print(f"Error: Proposal file not found: {proposal_path}", file=sys.stderr)
        return 1

    finding_data = json.loads(finding_path.read_text(encoding="utf-8"))
    proposal_data = json.loads(proposal_path.read_text(encoding="utf-8"))

    finding = CanonicalFinding.model_validate(finding_data)
    proposal = RemediationProposal.model_validate(proposal_data)

    snapshot: Optional[SnapshotMetadata] = None
    if args.snapshot:
        snap_path = Path(args.snapshot).resolve()
        if snap_path.exists():
            snap_data = json.loads(snap_path.read_text(encoding="utf-8"))
            snapshot = SnapshotMetadata.model_validate(snap_data)

    result = generate_remediation_report(
        finding=finding,
        proposal=proposal,
        snapshot=snapshot,
        output_path=args.output,
        project_name=args.project,
        audit_id=args.audit_id,
    )

    print(f"\n[OK] Remediation Change Report generated successfully!")
    print(f"     Report ID:   {result.report_id}")
    print(f"     PDF Output:  {result.pdf_path}")
    print(f"     Finding ID:  {result.finding_id}")
    print(f"     Status:      {result.status.value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
