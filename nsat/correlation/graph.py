"""Attack Surface Graph Builder for NSAT."""

from pathlib import Path
from typing import Optional

from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.correlation.models import AttackEdge, AttackNode, AttackSurfaceGraph
from nsat.normalization.models import CanonicalFinding


class AttackSurfaceGraphBuilder:
    """
    Constructs a lightweight, directed, serializable Attack Surface Graph
    connecting projects, applications, endpoints, processes, ports, databases,
    secrets, containers, internal services, and findings.
    """

    @classmethod
    def build(
        cls,
        target_path: str,
        findings: list[CanonicalFinding],
        intelligence: Optional[ProjectIntelligence] = None,
        surface: Optional[SecuritySurface] = None,
    ) -> AttackSurfaceGraph:
        """Build the graph from multi-layer intelligence and findings."""
        graph = AttackSurfaceGraph()
        proj_name = Path(target_path).name or "project"

        # 1. Project node
        graph.add_node(
            node_id=f"project:{proj_name}",
            node_type="project",
            name=proj_name,
            path=str(target_path),
        )

        # 2. Application node
        app_type = intelligence.project_type.primary_type if intelligence else "Application"
        graph.add_node(
            node_id=f"app:{proj_name}",
            node_type="application",
            name=f"{proj_name} ({app_type})",
            archetype=app_type,
        )
        graph.add_edge(f"project:{proj_name}", f"app:{proj_name}", "CONTAINS")

        # 3. Host node
        graph.add_node(
            node_id="host:target",
            node_type="host",
            name="Host Environment",
            exposure="Local / Containerized",
        )
        graph.add_edge(f"app:{proj_name}", "host:target", "RUNS_ON")

        # 4. Endpoints from surface
        if surface and surface.application:
            all_eps = (
                surface.application.endpoints
                + surface.application.auth_endpoints
                + surface.application.admin_endpoints
                + surface.application.upload_endpoints
                + surface.application.websocket_endpoints
            )
            for ep in all_eps:
                ep_id = f"endpoint:{ep.method}_{ep.path}"
                graph.add_node(
                    node_id=ep_id,
                    node_type="endpoint",
                    name=f"{ep.method} {ep.path}",
                    path=ep.path,
                    method=ep.method,
                    handler=ep.handler,
                    file_path=ep.file_path,
                    line_number=ep.line_number,
                    is_auth_required=ep.is_auth_required,
                )
                graph.add_edge(f"app:{proj_name}", ep_id, "EXPOSES")

        # 5. Network bindings and ports
        if surface and surface.infrastructure:
            for b in surface.infrastructure.bindings:
                port_id = f"port:{b.port or 'unknown'}"
                graph.add_node(
                    node_id=port_id,
                    node_type="port",
                    name=f"Port {b.port} ({b.host})",
                    host=b.host,
                    port=b.port,
                    exposure=b.exposure,
                )
                graph.add_edge("host:target", port_id, "BINDS_TO")

        # 6. Container node
        if (surface and surface.infrastructure.docker_present) or (intelligence and any("Dockerfile" in f.relative_path for f in intelligence.files)):
            graph.add_node(
                node_id="container:docker",
                node_type="container",
                name="Docker Container Context",
                socket_mounted=any("/var/run/docker.sock" in f.description.lower() for f in findings),
            )
            graph.add_edge("host:target", "container:docker", "RUNS_CONTAINER")

        # 7. Secrets
        if surface and surface.data:
            for i, sec in enumerate(surface.data.secrets):
                sec_id = f"secret:{sec.secret_type}_{i}"
                graph.add_node(
                    node_id=sec_id,
                    node_type="secret",
                    name=f"Secret: {sec.secret_type}",
                    redacted_value=sec.redacted_value,
                    file_path=sec.file_path,
                    line_number=sec.line_number,
                )
                graph.add_edge(f"app:{proj_name}", sec_id, "ACCESSES_SECRET")

        # 8. Databases
        if intelligence and intelligence.database_components:
            for db in intelligence.database_components:
                db_id = f"database:{db.db_type}"
                graph.add_node(
                    node_id=db_id,
                    node_type="database",
                    name=f"Database: {db.db_type}",
                    operation=db.operation,
                    file_path=db.file_path,
                )
                graph.add_edge(f"app:{proj_name}", db_id, "CONNECTS_TO_DATABASE")

        # 9. Findings nodes and links
        for f in findings:
            fid = f"finding:{f.id}"
            graph.add_node(
                node_id=fid,
                node_type="finding",
                name=f"{f.id}: {f.title}",
                severity=f.severity,
                category=f.category,
                confidence=f.confidence,
                status=f.status,
            )

            # Link finding to appropriate architectural entity
            if f.endpoint:
                for ep_node in [n for n in graph.nodes if n.type == "endpoint"]:
                    if ep_node.properties.get("path") in f.endpoint:
                        graph.add_edge(fid, ep_node.id, "AFFECTS_ENDPOINT")
            elif f.file_path:
                # Link to endpoint by file
                for ep_node in [n for n in graph.nodes if n.type == "endpoint"]:
                    if ep_node.properties.get("file_path") == f.file_path:
                        graph.add_edge(fid, ep_node.id, "AFFECTS_ENDPOINT")

            if f.category == "container" and graph.find_node("container:docker"):
                graph.add_edge(fid, "container:docker", "COMPROMISES_CONTAINER")

            if f.category == "secret":
                for sec_node in [n for n in graph.nodes if n.type == "secret"]:
                    if sec_node.properties.get("file_path") == f.file_path:
                        graph.add_edge(fid, sec_node.id, "EXPOSES_SECRET")

            if f.port:
                port_id = f"port:{f.port}"
                if graph.find_node(port_id):
                    graph.add_edge(fid, port_id, "LISTENS_ON")

            # Fallback link to application
            graph.add_edge(f"app:{proj_name}", fid, "CONTAINS_FINDING")

        return graph
