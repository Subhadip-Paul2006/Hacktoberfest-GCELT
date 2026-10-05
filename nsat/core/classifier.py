"""Evidence-based project archetype classifier for NSAT."""

from nsat.core.models import (
    DatabaseComponent,
    EntryPoint,
    FrameworkEvidence,
    NetworkComponent,
    ProjectTypeClassification,
)


class ProjectClassifier:
    """
    Classifies a project's architectural archetype based purely on structural evidence
    (frameworks, routes, network bindings, and database components), never on names alone.
    """

    @staticmethod
    def classify(
        frameworks: list[FrameworkEvidence],
        entry_points: list[EntryPoint],
        network_components: list[NetworkComponent],
        database_components: list[DatabaseComponent],
    ) -> ProjectTypeClassification:
        framework_names = {fw.name.lower() for fw in frameworks}
        evidence_notes: list[str] = []
        secondary_types: list[str] = []

        # Count route types
        http_routes_count = sum(1 for ep in entry_points if ep.entry_type == "http_route")
        has_http_listener = any(nc.component_type == "http_listener" for nc in network_components)
        has_raw_socket = any(nc.component_type == "socket_bind" for nc in network_components)

        # 1. GraphQL Service
        if any("graphql" in fw for fw in framework_names):
            evidence_notes.append("Detected GraphQL schema definition / library")
            return ProjectTypeClassification(
                primary_type="GraphQL Service",
                secondary_types=["Web Application" if has_http_listener else "API"],
                confidence=0.95,
                supporting_evidence=evidence_notes,
            )

        # 2. Frontend / Fullstack Web Application
        has_frontend = any(fw in framework_names for fw in ["react", "next.js", "vue"])
        if has_frontend:
            evidence_notes.append(f"Detected client-side framework: {[f.name for f in frameworks if f.name.lower() in ['react', 'next.js', 'vue']]}")
            if http_routes_count > 0 or has_http_listener or any(fw in framework_names for fw in ["fastapi", "express", "spring boot", "django", "flask"]):
                return ProjectTypeClassification(
                    primary_type="Web Application",
                    secondary_types=["REST API", "Fullstack Application"],
                    confidence=0.95,
                    supporting_evidence=evidence_notes,
                )
            return ProjectTypeClassification(
                primary_type="Web Application",
                secondary_types=["Frontend Client"],
                confidence=0.9,
                supporting_evidence=evidence_notes,
            )

        # 3. REST API / Microservice
        has_api_fw = any(fw in framework_names for fw in ["fastapi", "express", "spring boot", "spring mvc", "flask", "tornado", "crow c++ web daemon", "drogon c++ web framework"])
        if has_api_fw or http_routes_count > 0:
            evidence_notes.append(f"Detected {http_routes_count} HTTP route endpoints and API framework")
            if database_components:
                secondary_types.append("Database-Backed Application")
            return ProjectTypeClassification(
                primary_type="REST API / Microservice",
                secondary_types=secondary_types,
                confidence=0.95,
                supporting_evidence=evidence_notes,
            )

        # 4. CLI Application
        has_cli_fw = any("cli" in fw for fw in framework_names)
        has_main_entry = any(ep.entry_type == "main" for ep in entry_points)
        if has_cli_fw or (has_main_entry and not has_http_listener and not has_raw_socket):
            evidence_notes.append("Identified main entry point with CLI argument parsing / without listening network sockets")
            return ProjectTypeClassification(
                primary_type="CLI Application",
                secondary_types=["Utility Tool"],
                confidence=0.85,
                supporting_evidence=evidence_notes,
            )

        # 5. Network Service / Daemon
        if has_raw_socket or (has_http_listener and not has_api_fw):
            evidence_notes.append("Identified direct socket binding or raw network listener")
            return ProjectTypeClassification(
                primary_type="Network Service / Daemon",
                secondary_types=["Backend Service"],
                confidence=0.9,
                supporting_evidence=evidence_notes,
            )

        # 6. Database-backed backend service
        if database_components:
            evidence_notes.append(f"Identified {len(database_components)} database query or ORM operations")
            return ProjectTypeClassification(
                primary_type="Backend Service",
                secondary_types=["Database-Backed Application"],
                confidence=0.8,
                supporting_evidence=evidence_notes,
            )

        # Default fallback
        evidence_notes.append("Generic source structure without identifiable web or daemon frameworks")
        return ProjectTypeClassification(
            primary_type="Software Library / Backend Service",
            secondary_types=["Module"],
            confidence=0.6,
            supporting_evidence=evidence_notes,
        )
