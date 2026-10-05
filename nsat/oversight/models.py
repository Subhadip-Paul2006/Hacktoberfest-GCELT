"""Developer Oversight and Contextual Audit Models for NSAT."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from nsat.normalization.models import CanonicalFinding, FindingEvidence


class OversightCategory(str, Enum):
    """Categories of developer oversight and hidden loophole weaknesses."""
    INFO_LEAKAGE = "info_leakage"
    URL_SECURITY = "url_security"
    LOG_LEAKAGE = "log_leakage"
    ERROR_EXPOSURE = "error_exposure"
    HIDDEN_ENDPOINT = "hidden_endpoint"
    SESSION_SECURITY = "session_security"
    SECURITY_HEADERS = "security_headers"
    CLIENT_TRUST = "client_trust"
    SERVER_VALIDATION_GAP = "server_validation_gap"
    OPEN_REDIRECT = "open_redirect"
    CORS_OVERSIGHT = "cors_oversight"
    RESOURCE_TIMEOUT = "resource_timeout"
    DEFAULT_CONFIG = "default_config"
    BACKUP_EXPOSURE = "backup_exposure"
    DEFAULT_CREDENTIALS = "default_credentials"
    RACE_CONDITION = "race_condition"
    SENSITIVE_FILE_ACCESS = "sensitive_file_access"
    DEPLOYMENT_OVERSIGHT = "deployment_oversight"


class OversightSummary(BaseModel):
    """Aggregate summary statistics for oversight audit findings."""
    total_findings: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    enriched_findings_count: int = 0
    new_findings_count: int = 0


class OversightResult(BaseModel):
    """
    Complete result returned by the Developer Oversight Engine.
    Exposes structured output consumed by Phase 4 Correlation & AI layers.
    """
    target_path: str
    rules_evaluated: list[str] = Field(default_factory=list)
    findings: list[CanonicalFinding] = Field(default_factory=list)
    enriched_findings: list[CanonicalFinding] = Field(default_factory=list)
    summary: OversightSummary = Field(default_factory=OversightSummary)

    # Clean handoff object for Phase 4
    correlation_handoff: dict[str, Any] = Field(default_factory=dict)
