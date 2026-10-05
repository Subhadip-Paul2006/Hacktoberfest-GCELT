"""Unified Phase 4A Correlation Engine for NSAT."""

import json
from pathlib import Path
import re
from typing import Any, Optional

from nsat.correlation.blast_radius import BlastRadiusEngine
from nsat.correlation.graph import AttackSurfaceGraphBuilder
from nsat.correlation.location import SourceLocationResolver
from nsat.correlation.models import (
    CoverageReport,
    LimitationsReport,
    Phase4Input,
    Phase4SecurityModel,
)
from nsat.correlation.risk import RiskEngine
from nsat.correlation.rules import CorrelationRuleEngine
from nsat.normalization.models import CanonicalFinding, FindingEvidence


class CorrelationEngine:
    """
    Unified Intelligence Layer for Phase 4A.
    Consumes ProjectIntelligence, SecuritySurface, Phase 2 findings,
    Phase 3 validation evidence, and Phase 3.5 oversight results.
    Produces the unified Phase4SecurityModel.
    """

    @classmethod
    def run(cls, phase4_input: Phase4Input) -> Phase4SecurityModel:
        """Execute complete Phase 4A correlation, risk scoring, graph construction, and handoff generation."""
        target_path = Path(phase4_input.target_path)
        intel = phase4_input.project_intelligence
        surface = phase4_input.security_surface

        # 1. Aggregate and deduplicate findings across Phase 2, Phase 3, and Phase 3.5
        all_raw_findings: list[CanonicalFinding] = []
        all_raw_findings.extend(phase4_input.phase2_findings)

        # Merge Phase 3 swarm findings / upgrades
        if phase4_input.phase3_validation_results:
            all_raw_findings.extend(phase4_input.phase3_validation_results.findings)

        # Merge Phase 3.5 oversight findings
        if phase4_input.phase3_5_oversight_findings:
            all_raw_findings.extend(phase4_input.phase3_5_oversight_findings.findings)

        deduped_findings = cls._deduplicate_and_merge(all_raw_findings)

        # 2. Resolve precise source code locations (File, Line, Col, Function, Class, Module, Endpoint)
        for f in deduped_findings:
            loc = SourceLocationResolver.resolve_location(
                finding=f,
                target_path=target_path,
                surface=surface,
            )
            f.function_name = loc.function_name
            f.class_name = loc.class_name
            f.column_number = loc.column
            if not f.endpoint and loc.endpoint:
                f.endpoint = loc.endpoint
            f.primary_location = loc.model_dump()

        # 3. Construct In-Memory Attack Surface Graph
        graph = AttackSurfaceGraphBuilder.build(
            target_path=str(target_path),
            findings=deduped_findings,
            intelligence=intel,
            surface=surface,
        )

        # 4. Evaluate Post-Compromise Blast Radius
        blast_radius = BlastRadiusEngine.evaluate(
            findings=deduped_findings,
            surface=surface,
        )

        # 5. Deterministic Cross-Domain Correlation & Attack Paths
        correlations, attack_paths = CorrelationRuleEngine.correlate(
            findings=deduped_findings,
            surface=surface,
        )

        # 6. Deterministic Contextual Risk Scoring & Priorities
        scored_findings, risk_assessment = RiskEngine.evaluate(
            findings=deduped_findings,
            blast_radius=blast_radius,
            attack_paths=attack_paths,
            surface=surface,
        )

        # 7. Coverage Assessment
        coverage = cls._generate_coverage(target_path, intel, surface, deduped_findings)

        # 8. Limitations & Blind Spots Assessment
        limitations = cls._generate_limitations()

        # 9. Build final Phase 4 handoff object
        project_dict: dict[str, Any] = {}
        if intel:
            project_dict = {
                "name": intel.metadata.project_name,
                "target_path": intel.metadata.target_path,
                "primary_type": intel.project_type.primary_type,
                "languages": [l.language for l in intel.languages],
                "frameworks": [f.name for f in intel.frameworks],
                "files_count": intel.metadata.total_files_discovered,
                "lines_of_code": intel.metadata.total_lines_of_code,
            }

        surface_dict: dict[str, Any] = {}
        if surface:
            surface_dict = {
                "endpoints_count": len(phase4_input.endpoints),
                "secrets_count": len(surface.data.secrets),
                "bindings_count": len(surface.infrastructure.bindings),
                "docker_present": surface.infrastructure.docker_present,
            }

        return Phase4SecurityModel(
            project=project_dict,
            security_surface=surface_dict,
            findings=scored_findings,
            correlations=correlations,
            risk=risk_assessment,
            attack_paths=attack_paths,
            blast_radius=blast_radius,
            graph=graph,
            coverage=coverage,
            limitations=limitations,
        )

    @classmethod
    def _deduplicate_and_merge(cls, findings: list[CanonicalFinding]) -> list[CanonicalFinding]:
        """Merge findings representing the same issue without losing evidence or sources."""
        merged_map: dict[str, CanonicalFinding] = {}

        for f in findings:
            # Deterministic dedup key based on file, line, and category or signature hash
            norm_file = Path(f.file_path).name if f.file_path else f.asset
            key = f"{f.category}:{norm_file}:{f.line_number or ''}:{f.title.lower().strip()}"

            if key not in merged_map:
                # Sanitize evidence snippets
                sanitized_ev = [cls._sanitize_evidence(ev) for ev in f.evidence]
                f.evidence = sanitized_ev
                merged_map[key] = f
            else:
                existing = merged_map[key]

                # Merge sources
                for s in f.sources or ([f.source] if f.source else []):
                    if s and s not in existing.sources:
                        existing.sources.append(s)

                # Merge evidence
                for ev in f.evidence:
                    sanitized = cls._sanitize_evidence(ev)
                    if not any(e.description == sanitized.description and e.type == sanitized.type for e in existing.evidence):
                        existing.evidence.append(sanitized)

                # Upgrade confidence
                existing.confidence = max(existing.confidence, f.confidence)

                # Upgrade lifecycle status
                status_rank = {
                    "VALIDATED": 4,
                    "CONFIRMED_BY_SAFE_CHECK": 3,
                    "POTENTIAL": 2,
                    "UNVERIFIED": 1,
                    "RESOLVED": 0,
                    "SUPPRESSED": -1,
                }
                if status_rank.get(f.status, 0) > status_rank.get(existing.status, 0):
                    existing.status = f.status
                    existing.confidence_label = f.confidence_label

                # Upgrade severity
                sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1}
                if sev_rank.get(f.severity, 0) > sev_rank.get(existing.severity, 0):
                    existing.severity = f.severity

        # Return sorted by severity: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFORMATIONAL
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        result = list(merged_map.values())
        result.sort(key=lambda x: severity_order.get(x.severity, 5))
        return result

    @classmethod
    def _sanitize_evidence(cls, ev: FindingEvidence) -> FindingEvidence:
        """Redact sensitive passwords, keys, and tokens from snippet and description."""
        snippet = ev.snippet or ""
        # Redact common credentials
        snippet = re.sub(r'(password|passwd|secret|token|key)\s*[:=]\s*["\']?[^"\'\s]+["\']?', r'\1=***REDACTED***', snippet, flags=re.IGNORECASE)
        snippet = re.sub(r'AKIA[0-9A-Z]{16}', 'AKIA***REDACTED***', snippet)
        snippet = re.sub(r'ghp_[a-zA-Z0-9]{36}', 'ghp_***REDACTED***', snippet)

        desc = ev.description or ""
        desc = re.sub(r'AKIA[0-9A-Z]{16}', 'AKIA***REDACTED***', desc)

        return FindingEvidence(
            type=ev.type,
            description=desc,
            snippet=snippet if snippet else None,
            line_number=ev.line_number,
            context=ev.context,
        )

    @classmethod
    def _generate_coverage(
        cls,
        target_path: Path,
        intel: Optional[Any],
        surface: Optional[Any],
        findings: list[CanonicalFinding],
    ) -> CoverageReport:
        """Construct coverage report of languages and security domains evaluated."""
        langs = ["C++", "Java", "Python", "JavaScript", "TypeScript"]
        if intel and intel.languages:
            langs = list(dict.fromkeys([l.language.replace("_", "/").title() for l in intel.languages] + langs))

        domains = [
            "Source Code (SAST)",
            "Secrets & High Entropy",
            "Dependencies & CVE Advisory",
            "Network Bindings & Sockets",
            "Web Runtime Security & Headers",
            "Authentication & Rate Limiting",
            "Host Processes & Persistence",
            "Container Security & Dockerfile",
            "Developer Oversight & Information Leakage",
            "Active Non-Destructive Validation",
        ]

        scanners = [
            "NativeSASTScanner",
            "SecretScanner",
            "DependencyScanner",
            "NetworkBindingAuditor",
            "HostScanner",
            "ContainerScanner",
            "DeveloperOversightEngine",
            "ActiveValidationSwarm",
        ]

        files_count = intel.metadata.total_files_discovered if intel else len(list(target_path.rglob("*")))
        loc = intel.metadata.total_lines_of_code if intel else 0

        return CoverageReport(
            languages=langs,
            security_domains=domains,
            files_analyzed=files_count,
            lines_of_code=loc,
            scanners_executed=scanners,
        )

    @classmethod
    def _generate_limitations(cls) -> LimitationsReport:
        """Document defensive boundaries, blind spots, and deferred capabilities."""
        blind_spots = [
            "Deep OS kernel-level rootkits and driver modifications cannot be fully observed in non-root user mode.",
            "Complex dynamic microservice routing may require distributed tracing or extended live telemetry.",
            "Remote host internals outside authorized IP/socket scope cannot be inferred from static scanning alone.",
            "Novel, unpublished zero-day vulnerabilities in third-party libraries remain undetected by static CVE databases.",
            "Obfuscated binary bytecode without debug symbols requires dynamic behavioral sandboxing.",
        ]

        scope_restrictions = [
            "Non-destructive audit policy: No intrusive exploit payloads or service-disrupting traffic generated.",
            "Network scans restricted strictly to authorized IP bounds and local loopback interfaces.",
        ]

        deferred_features = [
            "GLM-5.3 Autonomous Reasoning and interactive conversational explainer: Not implemented in current phase (Scheduled for Phase 4B).",
            "Kimi-K3 Autonomous Remediation and closed-loop code patcher: Not implemented in current phase (Scheduled for Phase 4C).",
        ]

        return LimitationsReport(
            known_blind_spots=blind_spots,
            scope_restrictions=scope_restrictions,
            deferred_features=deferred_features,
        )
