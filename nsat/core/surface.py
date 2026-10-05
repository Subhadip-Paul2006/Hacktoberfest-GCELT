"""Security Surface extraction models and Future Swarm handoff contracts for NSAT."""

from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, Field
from nsat.core.models import ProjectIntelligence


class Endpoint(BaseModel):
    """Application HTTP, WebSocket, or RPC endpoint."""
    path: str
    method: str = "GET"
    handler: str
    endpoint_type: str = "api_route"  # "api_route", "websocket", "auth", "file_upload", "admin", "graphql"
    file_path: str
    line_number: int
    is_auth_required: bool = False
    parameters: list[str] = Field(default_factory=list)


class InputSource(BaseModel):
    """External untrusted input entry point."""
    source_type: str  # "http_param", "query_string", "request_body", "header", "env_var", "socket_read"
    identifier: str
    file_path: str
    line_number: int


class ExecutionSink(BaseModel):
    """Security-sensitive execution sink in source code."""
    sink_type: str  # "command_execution", "sql_query", "filesystem_write", "filesystem_read", "deserialization", "crypto_operation"
    snippet: str
    file_path: str
    line_number: int


class NetworkBinding(BaseModel):
    """Network listener interface and port binding."""
    host: str
    port: Optional[int] = None
    exposure: str = "LOCAL_ONLY"  # "LOCAL_ONLY", "POTENTIALLY_LAN_REACHABLE", "PUBLIC_WILDCARD"
    protocol: str = "tcp"
    file_path: str
    line_number: int


class ServiceIndicator(BaseModel):
    """Discovered service, container, or datastore indicator."""
    service_type: str  # "database", "redis", "docker", "reverse_proxy", "tls"
    details: dict[str, Any] = Field(default_factory=dict)


class SecretLocation(BaseModel):
    """Identified high-entropy secret or credential with redacted value."""
    secret_type: str  # "api_key", "password", "token", "private_key", "jwt", "cloud_credential"
    redacted_value: str
    file_path: str
    line_number: int


class ApplicationSurface(BaseModel):
    """Surfaced application layer interfaces."""
    endpoints: list[Endpoint] = Field(default_factory=list)
    websocket_endpoints: list[Endpoint] = Field(default_factory=list)
    auth_endpoints: list[Endpoint] = Field(default_factory=list)
    admin_endpoints: list[Endpoint] = Field(default_factory=list)
    upload_endpoints: list[Endpoint] = Field(default_factory=list)


class CodeSecuritySurface(BaseModel):
    """Surfaced code-level sources and sinks."""
    input_sources: list[InputSource] = Field(default_factory=list)
    execution_sinks: list[ExecutionSink] = Field(default_factory=list)


class InfrastructureSurface(BaseModel):
    """Surfaced host, container, and network bindings."""
    bindings: list[NetworkBinding] = Field(default_factory=list)
    services: list[ServiceIndicator] = Field(default_factory=list)
    docker_present: bool = False
    tls_configured: bool = False


class DataSecuritySurface(BaseModel):
    """Surfaced sensitive assets and secret parameters."""
    secrets: list[SecretLocation] = Field(default_factory=list)
    sensitive_files: list[str] = Field(default_factory=list)
    environment_variables: list[str] = Field(default_factory=list)


class SecuritySurface(BaseModel):
    """
    Comprehensive Security Surface Model.
    Machine-readable abstraction passed to Phase 3's Active Validation Swarm.
    """
    target_path: str
    application: ApplicationSurface = Field(default_factory=ApplicationSurface)
    code: CodeSecuritySurface = Field(default_factory=CodeSecuritySurface)
    infrastructure: InfrastructureSurface = Field(default_factory=InfrastructureSurface)
    data: DataSecuritySurface = Field(default_factory=DataSecuritySurface)


class ActiveSwarmHandoff(BaseModel):
    """
    Structured machine-readable contract specifically formatted for Phase 3's Active Validation Swarm.
    Enables Phase 3 to immediately consume validated attack surfaces without reparsing.
    """
    target: str
    endpoints: list[dict[str, Any]] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    auth_requirements: list[str] = Field(default_factory=list)
    existing_findings: list[str] = Field(default_factory=list)
    risk_priority: str = "MEDIUM"
    scope: dict[str, Any] = Field(default_factory=dict)


class SecuritySurfaceExtractor:
    """Extracts the structured SecuritySurface from Phase 1 ProjectIntelligence and target files."""

    @classmethod
    def extract(cls, intel: ProjectIntelligence, target_path: Path) -> SecuritySurface:
        app_surface = ApplicationSurface()
        code_surface = CodeSecuritySurface()
        infra_surface = InfrastructureSurface()
        data_surface = DataSecuritySurface()

        # 1. Map entry points to Endpoints
        for ep in intel.entry_points:
            ep_type = ep.entry_type
            method = ep.details.get("method") or ep.details.get("verb") or "GET"
            route = ep.details.get("route") or "/"
            endpoint_obj = Endpoint(
                path=route,
                method=method,
                handler=ep.signature,
                endpoint_type=ep_type,
                file_path=ep.file_path,
                line_number=ep.line_number,
                is_auth_required=any(k in route.lower() for k in ["admin", "secure", "private"]),
            )
            app_surface.endpoints.append(endpoint_obj)
            if "ws" in route.lower() or "socket" in route.lower():
                app_surface.websocket_endpoints.append(endpoint_obj)
            if any(k in route.lower() for k in ["login", "auth", "token", "password", "otp"]):
                app_surface.auth_endpoints.append(endpoint_obj)
            if "admin" in route.lower():
                app_surface.admin_endpoints.append(endpoint_obj)
            if "upload" in route.lower() or "file" in route.lower():
                app_surface.upload_endpoints.append(endpoint_obj)

        # 2. Map Security Relevant Operations to Sinks
        for op in intel.security_relevant_operations:
            code_surface.execution_sinks.append(
                ExecutionSink(
                    sink_type=op.operation_type,
                    snippet=op.snippet,
                    file_path=op.file_path,
                    line_number=op.line_number,
                )
            )

        # 3. Map Network Components to Bindings & Infrastructure
        for nc in intel.network_components:
            host = nc.host or "127.0.0.1"
            exposure = "LOCAL_ONLY"
            if host in ["0.0.0.0", "::", "INADDR_ANY"]:
                exposure = "POTENTIALLY_LAN_REACHABLE"
            elif host not in ["127.0.0.1", "localhost", "::1"]:
                exposure = "POTENTIALLY_LAN_REACHABLE"

            infra_surface.bindings.append(
                NetworkBinding(
                    host=host,
                    port=nc.port,
                    exposure=exposure,
                    protocol=nc.protocol or "tcp",
                    file_path=nc.file_path,
                    line_number=nc.line_number,
                )
            )

        # 4. Check for Docker and Sensitive Files in Target
        if (target_path / "Dockerfile").exists() or (target_path / "docker-compose.yml").exists() or (target_path / "docker-compose.yaml").exists():
            infra_surface.docker_present = True
            infra_surface.services.append(ServiceIndicator(service_type="docker", details={"compose": True}))

        for sf in [".env", ".env.local", ".env.production", "id_rsa", "credentials.json", "config.json"]:
            if (target_path / sf).exists():
                data_surface.sensitive_files.append(sf)

        return SecuritySurface(
            target_path=str(target_path),
            application=app_surface,
            code=code_surface,
            infrastructure=infra_surface,
            data=data_surface,
        )

    @classmethod
    def create_swarm_handoff(cls, surface: SecuritySurface, findings: list[Any]) -> ActiveSwarmHandoff:
        methods = list({ep.method for ep in surface.application.endpoints}) or ["GET"]
        endpoints_data = [
            {"path": ep.path, "method": ep.method, "auth": ep.is_auth_required}
            for ep in surface.application.endpoints
        ]
        finding_ids = [getattr(f, "id", str(f)) for f in findings]
        risk = "HIGH" if any(getattr(f, "severity", "") == "CRITICAL" for f in findings) else "MEDIUM"

        return ActiveSwarmHandoff(
            target=surface.target_path,
            endpoints=endpoints_data,
            methods=methods,
            auth_requirements=["Bearer" if surface.application.auth_endpoints else "None"],
            existing_findings=finding_ids,
            risk_priority=risk,
            scope={"local_only": not any(b.exposure == "POTENTIALLY_LAN_REACHABLE" for b in surface.infrastructure.bindings)},
        )
