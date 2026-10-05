"""Canonical Finding Model for NSAT."""

import hashlib
from typing import Any, Optional
from pydantic import BaseModel, Field


class FindingEvidence(BaseModel):
    """Specific piece of structural or runtime evidence supporting a finding."""
    type: str  # "AST_SINK", "RAW_SECRET", "NETWORK_BINDING", "HEADER_MISSING", "CVE_ADVISORY"
    description: str
    snippet: Optional[str] = None
    line_number: Optional[int] = None
    context: dict[str, Any] = Field(default_factory=dict)


class CanonicalFinding(BaseModel):
    """
    Standardized finding emitted across all security scanners and analyzers.
    Normalizes disparate tool outputs into a uniform data model.
    """
    id: str
    title: str
    category: str  # "code_sast", "secret", "network_exposure", "web_security", "dependency", "authentication", "dos_resource", "container"
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_label: str = "Detected structurally"
    source: str = "nsat_native"
    sources: list[str] = Field(default_factory=list)
    asset: str
    description: str
    impact: str
    recommendation: str
    status: str = "UNVERIFIED"

    file_path: Optional[str] = None
    line_number: Optional[int] = None
    endpoint: Optional[str] = None
    port: Optional[int] = None
    binding_address: Optional[str] = None

    evidence: list[FindingEvidence] = Field(default_factory=list)
    related_findings: list[str] = Field(default_factory=list)
    attack_surface_reference: Optional[str] = None
    component_reference: Optional[str] = None
    signature_hash: Optional[str] = None

    # Phase 4A correlation and location enrichments
    priority: Optional[str] = None
    risk_score: Optional[float] = None
    attack_path: list[str] = Field(default_factory=list)
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    column_number: Optional[int] = None
    primary_location: Optional[dict[str, Any]] = None
    lifecycle_status: str = "UNVERIFIED"
    suggested_diff: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.sources and self.source:
            self.sources = [self.source]
        if not self.signature_hash:
            self.signature_hash = self.compute_signature_hash()

    def compute_signature_hash(self) -> str:
        """Deterministic hash for deduplicating identical findings across scanners."""
        raw = f"{self.category}:{self.asset}:{self.file_path or ''}:{self.line_number or ''}:{self.port or ''}:{self.endpoint or ''}:{self.title}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
