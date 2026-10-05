"""
Phase 2 Scan Orchestrator for NSAT.

Executes all native scanners in sequence, collects CanonicalFindings,
deduplicates by signature hash, and returns a unified findings list.
"""

from pathlib import Path
from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface, SecuritySurfaceExtractor
from nsat.normalization.models import CanonicalFinding
from nsat.scanners.sast.native_rules import NativeSASTScanner
from nsat.scanners.secrets.scanner import SecretScanner
from nsat.scanners.dependencies.scanner import DependencyScanner
from nsat.scanners.container.scanner import ContainerScanner
from nsat.scanners.host.scanner import HostScanner


class Phase2Orchestrator:
    """
    Runs all Phase 2 native security scanners over a project target path.
    Each scanner receives the SecuritySurface from Phase 1 discovery.
    Findings are deduplicated by signature_hash before return.
    """

    def __init__(self):
        self.scanners = [
            NativeSASTScanner(),
            SecretScanner(),
            DependencyScanner(),
            ContainerScanner(),
            HostScanner(),
        ]

    def run(
        self,
        target_path: Path,
        intelligence: ProjectIntelligence,
    ) -> tuple[SecuritySurface, list[CanonicalFinding]]:
        """
        Execute full Phase 2 scan pipeline.

        Returns:
            (SecuritySurface, deduplicated list of CanonicalFindings)
        """
        surface = SecuritySurfaceExtractor.extract(intelligence, target_path)

        all_findings: list[CanonicalFinding] = []
        seen_hashes: set[str] = set()

        for scanner in self.scanners:
            try:
                scanner_findings = scanner.scan(target_path, surface)
                for f in scanner_findings:
                    if f.signature_hash not in seen_hashes:
                        seen_hashes.add(f.signature_hash)
                        all_findings.append(f)
            except Exception as exc:
                # Graceful degradation: log warning and continue
                import sys
                print(f"[WARN] Scanner '{scanner.scanner_name}' failed: {exc}", file=sys.stderr)

        # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFORMATIONAL
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        return surface, all_findings
