"""Canonical data models and Project Intermediate Representation (IR) for NSAT."""

from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field


class LanguageDistribution(BaseModel):
    """Statistics for a detected programming language."""
    language: str
    file_count: int = 0
    line_count: int = 0
    percentage: float = 0.0
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class DiscoveredFile(BaseModel):
    """Metadata for a scanned file within the project."""
    relative_path: str
    absolute_path: str
    language: Optional[str] = None
    size_bytes: int = 0
    line_count: int = 0
    is_relevant: bool = True
    relevance_reason: str = "source_code"


class EntryPoint(BaseModel):
    """Application entry point or exposed interface."""
    file_path: str
    line_number: int
    entry_type: str  # "main", "http_route", "cli_command", "websocket_handler", "daemon_worker"
    signature: str
    details: dict[str, Any] = Field(default_factory=dict)


class NetworkComponent(BaseModel):
    """Identified network interface, listener, or client binding."""
    file_path: str
    line_number: int
    component_type: str  # "http_listener", "socket_bind", "client_connect", "cors_middleware"
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)


class DatabaseComponent(BaseModel):
    """Identified database connection, query sink, or ORM usage."""
    file_path: str
    line_number: int
    db_type: str  # "sql_query", "orm_model", "nosql_operation", "connection_pool"
    operation: str
    details: dict[str, Any] = Field(default_factory=dict)


class AuthIndicator(BaseModel):
    """Authentication or authorization pattern identified in code or config."""
    file_path: str
    line_number: int
    indicator_type: str  # "password_hashing", "token_validation", "session_management", "role_check"
    details: dict[str, Any] = Field(default_factory=dict)


class SecurityRelevantOperation(BaseModel):
    """Security-sensitive operation identified by AST structure."""
    file_path: str
    line_number: int
    operation_type: str  # "process_execution", "eval_deserialization", "raw_sql_execution", "unsafe_buffer"
    sink_category: str   # "command_injection", "sql_injection", "insecure_crypto", "memory_safety"
    snippet: str
    details: dict[str, Any] = Field(default_factory=dict)


class FrameworkEvidence(BaseModel):
    """Identified software framework or major ecosystem technology."""
    name: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    matched_files: list[str] = Field(default_factory=list)
    evidence_type: str  # "import", "decorator", "manifest", "config"
    version: Optional[str] = None


class ProjectTypeClassification(BaseModel):
    """High-level classification of the project archetype."""
    primary_type: str  # "Web Application", "REST API", "CLI Application", "Network Service", etc.
    secondary_types: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)


class DependencyInfo(BaseModel):
    """Third-party package or dependency discovered in manifests."""
    name: str
    version: Optional[str] = None
    package_manager: str  # "pip", "npm", "maven", "cmake", etc.
    source_file: str


class ProjectMetadata(BaseModel):
    """Summary metadata of the audited project."""
    target_path: str
    project_name: str
    total_files_discovered: int = 0
    analyzable_files_count: int = 0
    total_lines_of_code: int = 0
    scan_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    nsat_version: str = "0.1.0"


class ProjectIntelligence(BaseModel):
    """
    Common Project Intermediate Representation (Project IR).
    Feeds downstream security scanners, correlation engine, and reporters.
    """
    metadata: ProjectMetadata
    languages: list[LanguageDistribution] = Field(default_factory=list)
    frameworks: list[FrameworkEvidence] = Field(default_factory=list)
    project_type: ProjectTypeClassification
    files: list[DiscoveredFile] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    dependencies: list[DependencyInfo] = Field(default_factory=list)
    network_components: list[NetworkComponent] = Field(default_factory=list)
    database_components: list[DatabaseComponent] = Field(default_factory=list)
    authentication_indicators: list[AuthIndicator] = Field(default_factory=list)
    security_relevant_operations: list[SecurityRelevantOperation] = Field(default_factory=list)
    analyzer_metadata: dict[str, Any] = Field(default_factory=dict)
