"""Data Models for NSAT Phase 4A Correlation, Graph, Risk & Security Handoff."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from nsat.core.models import ProjectIntelligence
from nsat.core.surface import Endpoint, SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.oversight.models import OversightResult
from nsat.swarm.models import SwarmResult, TargetScope


class RelationshipType(str, Enum):
    """Categorized relationship types between security findings."""
    PARENT = "PARENT"
    CHILD = "CHILD"
    RELATED = "RELATED"
    CONTRIBUTES_TO = "CONTRIBUTES_TO"
    VALIDATES = "VALIDATES"
    AMPLIFIES = "AMPLIFIES"


class FindingRelationship(BaseModel):
    """Directed relationship linking two correlated findings with technical justification."""
    source_id: str
    target_id: str
    relation_type: RelationshipType
    reason: str
    context: dict[str, Any] = Field(default_factory=dict)


class PrimaryLocation(BaseModel):
    """Best-resolved source code location for developer remediation."""
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column: Optional[int] = None
    function_name: str = "Not reliably resolved"
    class_name: str = "Not reliably resolved"
    module: Optional[str] = None
    endpoint: Optional[str] = None

    def display_str(self) -> str:
        parts = []
        if self.file_path:
            parts.append(f"File: {self.file_path}")
        if self.line_number is not None:
            parts.append(f"Line: {self.line_number}")
        if self.function_name and self.function_name != "Not reliably resolved":
            parts.append(f"Function: {self.function_name}")
        if self.endpoint:
            parts.append(f"Endpoint: {self.endpoint}")
        return " | ".join(parts) if parts else "Location not specified"


class AttackNode(BaseModel):
    """Vertex representing an architectural entity in the Attack Surface Graph."""
    id: str
    type: str  # project, application, host, endpoint, process, port, database, secret, container, internal_service, finding
    name: str
    properties: dict[str, Any] = Field(default_factory=dict)


class AttackEdge(BaseModel):
    """Directed edge representing connectivity, access, or influence between entities."""
    source: str
    target: str
    relation: str  # CONTAINS, EXPOSES, CONNECTS_TO, ACCESSES, RUNS, BINDS_TO, AFFECTS, ATTACHED_TO, AUTHENTICATES
    properties: dict[str, Any] = Field(default_factory=dict)


class AttackSurfaceGraph(BaseModel):
    """Serializable directed attack-surface graph model."""
    nodes: list[AttackNode] = Field(default_factory=list)
    edges: list[AttackEdge] = Field(default_factory=list)

    def add_node(self, node_id: str, node_type: str, name: str, **properties: Any) -> AttackNode:
        for n in self.nodes:
            if n.id == node_id:
                n.properties.update(properties)
                return n
        node = AttackNode(id=node_id, type=node_type, name=name, properties=properties)
        self.nodes.append(node)
        return node

    def add_edge(self, source_id: str, target_id: str, relation: str, **properties: Any) -> AttackEdge:
        for e in self.edges:
            if e.source == source_id and e.target == target_id and e.relation == relation:
                e.properties.update(properties)
                return e
        edge = AttackEdge(source=source_id, target=target_id, relation=relation, properties=properties)
        self.edges.append(edge)
        return edge

    def find_node(self, node_id: str) -> Optional[AttackNode]:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def get_neighbors(self, node_id: str, direction: str = "outgoing") -> list[str]:
        if direction == "outgoing":
            return [e.target for e in self.edges if e.source == node_id]
        elif direction == "incoming":
            return [e.source for e in self.edges if e.target == node_id]
        else:
            return list(set(
                [e.target for e in self.edges if e.source == node_id] +
                [e.source for e in self.edges if e.target == node_id]
            ))


class AttackPath(BaseModel):
    """Synthesized multi-hop attack path derived from correlated evidence."""
    id: str
    title: str
    path_type: str = "Potential attack path"  # "Validated exposure path", "Potential attack path", "Post-compromise path"
    severity: str = "HIGH"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    steps: list[str] = Field(default_factory=list)
    involved_finding_ids: list[str] = Field(default_factory=list)
    impact: str = ""
    recommendation: str = ""
    evidence_summary: str = ""


class BlastRadiusReport(BaseModel):
    """Post-compromise exposure analysis under an Assume Breach model."""
    tier: str = "TIER 1 (LOCALIZED)"  # TIER 1 (LOCALIZED), TIER 2 (DATA/SERVICE EXPOSURE), TIER 3 (HOST/CLUSTER TAKEOVER)
    tier_level: int = 1
    summary: str = ""
    accessible_assets: list[str] = Field(default_factory=list)
    compromised_boundaries: list[str] = Field(default_factory=list)
    privilege_level: str = "Application User"
    lateral_movement_paths: list[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    """Deterministic system risk assessment and prioritizations."""
    overall_score: int = Field(default=0, ge=0, le=100)
    risk_level: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    priority_distribution: dict[str, int] = Field(default_factory=lambda: {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    critical_findings_count: int = 0
    high_findings_count: int = 0
    medium_findings_count: int = 0
    low_findings_count: int = 0
    info_findings_count: int = 0
    validated_findings_count: int = 0
    calculation_factors: dict[str, Any] = Field(default_factory=dict)


class CoverageReport(BaseModel):
    """Record of languages, domains, and files analyzed during audit."""
    languages: list[str] = Field(default_factory=list)
    security_domains: list[str] = Field(default_factory=list)
    files_analyzed: int = 0
    lines_of_code: int = 0
    scanners_executed: list[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class LimitationsReport(BaseModel):
    """Documented boundaries, blind spots, and deferred capabilities."""
    known_blind_spots: list[str] = Field(default_factory=list)
    scope_restrictions: list[str] = Field(default_factory=list)
    deferred_features: list[str] = Field(default_factory=list)


class Phase4Input(BaseModel):
    """Unified Phase 4 input model aggregating artifacts from Phase 1, 2, 3, and 3.5."""
    target_path: str
    project_intelligence: Optional[ProjectIntelligence] = None
    security_surface: Optional[SecuritySurface] = None
    endpoints: list[Endpoint] = Field(default_factory=list)
    phase2_findings: list[CanonicalFinding] = Field(default_factory=list)
    phase3_validation_results: Optional[SwarmResult] = None
    phase3_5_oversight_findings: Optional[OversightResult] = None
    evidence: list[FindingEvidence] = Field(default_factory=list)
    target_scope: Optional[TargetScope] = None
    capabilities: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_orchestration(
        cls,
        target_path: str,
        intelligence: Optional[ProjectIntelligence] = None,
        surface: Optional[SecuritySurface] = None,
        phase2_findings: Optional[list[CanonicalFinding]] = None,
        swarm_result: Optional[SwarmResult] = None,
        oversight_result: Optional[OversightResult] = None,
        scope: Optional[TargetScope] = None,
        capabilities: Optional[dict[str, Any]] = None,
    ) -> "Phase4Input":
        """Convenience constructor from multi-phase orchestration outputs."""
        p2_findings = list(phase2_findings or [])
        all_evidence: list[FindingEvidence] = []
        for f in p2_findings:
            all_evidence.extend(f.evidence)

        endpoints = []
        if surface and surface.application:
            endpoints.extend(surface.application.endpoints)
            endpoints.extend(surface.application.auth_endpoints)
            endpoints.extend(surface.application.admin_endpoints)

        return cls(
            target_path=str(target_path),
            project_intelligence=intelligence,
            security_surface=surface,
            endpoints=endpoints,
            phase2_findings=p2_findings,
            phase3_validation_results=swarm_result,
            phase3_5_oversight_findings=oversight_result,
            evidence=all_evidence,
            target_scope=scope,
            capabilities=capabilities or {},
        )


class Phase4SecurityModel(BaseModel):
    """
    Final Phase 4A unified security intelligence model.
    Serves as the structured source of truth consumed by downstream AI/Remediation layers.
    """
    project: dict[str, Any] = Field(default_factory=dict)
    security_surface: dict[str, Any] = Field(default_factory=dict)
    findings: list[CanonicalFinding] = Field(default_factory=list)
    correlations: list[FindingRelationship] = Field(default_factory=list)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    blast_radius: BlastRadiusReport = Field(default_factory=BlastRadiusReport)
    graph: AttackSurfaceGraph = Field(default_factory=AttackSurfaceGraph)
    coverage: CoverageReport = Field(default_factory=CoverageReport)
    limitations: LimitationsReport = Field(default_factory=LimitationsReport)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
