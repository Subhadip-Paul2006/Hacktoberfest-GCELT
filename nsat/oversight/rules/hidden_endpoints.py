"""Hidden / Developer Endpoint and API Documentation Audit Rule for NSAT Phase 3.5."""

from pathlib import Path
import re
from typing import Any
from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence


class HiddenEndpointsRule:
    """
    Audits application routes for unauthenticated developer, debugging, staging,
    internal administration, and public API documentation endpoints.
    """

    DEVELOPER_ENDPOINT_PREFIXES = [
        ("/debug", "Developer Debug Endpoint", "HIGH"),
        ("/test", "Test / Mock Endpoint Exposed", "MEDIUM"),
        ("/dev", "Development Endpoint", "MEDIUM"),
        ("/internal", "Internal Service Route Exposed", "HIGH"),
        ("/staging", "Staging Environment Route", "MEDIUM"),
        ("/backup", "Backup / Dump Endpoint", "HIGH"),
        ("/old", "Deprecated Legacy Route", "LOW"),
        ("/actuator", "Spring Boot Actuator Monitoring", "HIGH"),
    ]

    DOCUMENTATION_PREFIXES = [
        ("/swagger", "Swagger UI API Documentation", "LOW"),
        ("/docs", "OpenAPI Interactive Documentation", "LOW"),
        ("/openapi", "OpenAPI Specification JSON Schema", "LOW"),
        ("/redoc", "ReDoc API Documentation", "LOW"),
    ]

    def audit(
        self,
        repo_path: Path,
        intel: ProjectIntelligence,
        surface: SecuritySurface,
        existing_findings: list[CanonicalFinding],
    ) -> list[CanonicalFinding]:
        findings: list[CanonicalFinding] = []
        finding_id_seq = 1

        endpoints = surface.application.endpoints

        for ep in endpoints:
            p_lower = ep.path.lower()

            # Rule 1: Developer / Internal / Debug Endpoints
            for prefix, label, severity in self.DEVELOPER_ENDPOINT_PREFIXES:
                if p_lower.startswith(prefix) or f"{prefix}/" in p_lower:
                    fid = f"NSAT-HIDDEN-EP-{finding_id_seq:03d}"
                    finding_id_seq += 1

                    desc = (
                        f"Potentially sensitive developer or internal route '{ep.path}' is registered in the application. "
                        "Developer and staging endpoints frequently bypass production authorization controls, leak internal "
                        "state, or allow administrative manipulations."
                    )
                    impact = "Unintended access to internal diagnostic facilities, testing routines, or administrative functions."
                    rec = (
                        "Remove testing/debugging routes prior to production deployment, or gate them behind strict "
                        "internal-network IP whitelisting and mutual TLS / administrator authentication."
                    )

                    ev = FindingEvidence(
                        type="DEVELOPER_ENDPOINT_SURFACED",
                        description=f"{label} registered: {ep.method} {ep.path}",
                        snippet=f"{ep.method} {ep.path} -> {ep.handler}",
                        line_number=ep.line_number,
                        context={"endpoint": ep.path, "handler": ep.handler},
                    )

                    findings.append(
                        CanonicalFinding(
                            id=fid,
                            title=f"Developer / Internal Endpoint Registered ({ep.path})",
                            category="hidden_endpoint",
                            severity=severity,
                            confidence=0.88,
                            confidence_label="Structural endpoint route discovery",
                            source="developer_oversight",
                            sources=["developer_oversight", "surface_extractor"],
                            asset=ep.path,
                            description=desc,
                            impact=impact,
                            recommendation=rec,
                            status="POTENTIAL",
                            file_path=ep.file_path,
                            line_number=ep.line_number,
                            endpoint=ep.path,
                            evidence=[ev],
                        )
                    )

            # Rule 2: API Documentation Exposure
            for prefix, label, severity in self.DOCUMENTATION_PREFIXES:
                if p_lower.startswith(prefix) or f"{prefix}/" in p_lower:
                    fid = f"NSAT-DOC-EXPOSE-{finding_id_seq:03d}"
                    finding_id_seq += 1

                    desc = (
                        f"Interactive API documentation endpoint '{ep.path}' ({label}) is enabled without authentication. "
                        "While API documentation is standard for public APIs, in internal or private architectures it gives "
                        "attackers complete schema maps, parameter types, hidden endpoints, and authentication schemas."
                    )
                    impact = "Full automated reconnaissance and API attack surface enumeration."
                    rec = "Disable interactive Swagger/OpenAPI documentation in production environments or require authentication."

                    ev = FindingEvidence(
                        type="API_DOCUMENTATION_EXPOSED",
                        description=f"{label} enabled at {ep.path}",
                        snippet=f"{ep.method} {ep.path}",
                        line_number=ep.line_number,
                    )

                    findings.append(
                        CanonicalFinding(
                            id=fid,
                            title=f"Unauthenticated API Documentation Enabled ({label})",
                            category="hidden_endpoint",
                            severity="LOW",
                            confidence=0.90,
                            confidence_label="Structural route discovery",
                            source="developer_oversight",
                            sources=["developer_oversight"],
                            asset=ep.path,
                            description=desc,
                            impact=impact,
                            recommendation=rec,
                            status="POTENTIAL",
                            file_path=ep.file_path,
                            line_number=ep.line_number,
                            endpoint=ep.path,
                            evidence=[ev],
                        )
                    )

        return findings
