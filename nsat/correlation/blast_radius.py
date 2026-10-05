"""Post-Compromise Blast Radius Engine for NSAT."""

from typing import Any, Optional

from nsat.core.surface import SecuritySurface
from nsat.correlation.models import BlastRadiusReport
from nsat.normalization.models import CanonicalFinding


class BlastRadiusEngine:
    """
    Evaluates Post-Compromise Blast Radius under an Assume Breach model.
    Traverses discovered secrets, container socket mounts, host privileges,
    and network bindings to quantify the impact if an application process is compromised.
    """

    @classmethod
    def evaluate(
        cls,
        findings: list[CanonicalFinding],
        surface: Optional[SecuritySurface] = None,
    ) -> BlastRadiusReport:
        """Calculate blast radius tier and accessible assets."""
        tier_level = 1
        tier_name = "TIER 1 (LOCALIZED)"
        accessible_assets: list[str] = []
        compromised_boundaries: list[str] = []
        privilege_level = "Application User (Least Privilege)"
        lateral_paths: list[str] = []

        has_docker_sock = False
        has_root_container = False
        has_command_injection = False
        has_database_creds = False
        has_cloud_keys = False
        has_sql_injection = False
        has_exposed_db_port = False

        # 1. Analyze findings
        for f in findings:
            title_lower = f.title.lower()
            desc_lower = f.description.lower()
            asset_lower = f.asset.lower()

            # Docker socket / Container escape
            if "docker.sock" in title_lower or "docker.sock" in desc_lower or "docker.sock" in asset_lower:
                has_docker_sock = True
                accessible_assets.append("Host Docker Daemon Socket (/var/run/docker.sock)")
            if "root user" in title_lower or "privileged" in title_lower or "missing user" in title_lower:
                has_root_container = True
                accessible_assets.append("Root Container Execution Context")

            # Command execution
            if "command" in title_lower and ("injection" in title_lower or "execution" in title_lower):
                has_command_injection = True
                compromised_boundaries.append("Process Execution Boundary (Shell / Exec Sink)")

            # SQL injection
            if "sql" in title_lower and "injection" in title_lower:
                has_sql_injection = True
                compromised_boundaries.append("Application Data Access Layer")

            # Credentials
            if f.category == "secret":
                if "db_" in title_lower or "password" in title_lower or "database" in title_lower:
                    has_database_creds = True
                    accessible_assets.append(f"Database Credentials in {f.asset}")
                elif "aws" in title_lower or "cloud" in title_lower or "jwt" in title_lower or "token" in title_lower:
                    has_cloud_keys = True
                    accessible_assets.append(f"Cloud/API Access Key in {f.asset}")

            # Network binding
            if f.port in (5432, 3306, 27017, 6379) and f.binding_address in ("0.0.0.0", "::"):
                has_exposed_db_port = True
                accessible_assets.append(f"Network Exposed Database Listener (Port {f.port})")

        # 2. Analyze SecuritySurface if provided
        if surface:
            if surface.infrastructure.docker_present:
                for b in surface.infrastructure.bindings:
                    if b.port in (5432, 3306, 27017, 6379) and b.exposure in ("PUBLIC_WILDCARD", "POTENTIALLY_LAN_REACHABLE"):
                        has_exposed_db_port = True
                        accessible_assets.append(f"Network Exposed Datastore on Port {b.port}")

            for sec in surface.data.secrets:
                if sec.secret_type in ("password", "cloud_credential", "api_key"):
                    accessible_assets.append(f"{sec.secret_type.replace('_', ' ').title()} in {sec.file_path}:{sec.line_number}")
                    if "password" in sec.secret_type:
                        has_database_creds = True
                    else:
                        has_cloud_keys = True

        # Deduplicate accessible assets
        accessible_assets = list(dict.fromkeys(accessible_assets))
        compromised_boundaries = list(dict.fromkeys(compromised_boundaries))

        # 3. Determine Tier
        if has_docker_sock or (has_root_container and has_command_injection):
            tier_level = 3
            tier_name = "TIER 3 (HOST/CLUSTER TAKEOVER)"
            privilege_level = "Host Root / Cluster Administrator (via Docker daemon breakout)"
            compromised_boundaries.append("Host OS Kernel & Container Isolation Boundary")
            summary = (
                "Catastrophic blast radius: Application compromise allows container breakout "
                "to host root via accessible Docker daemon socket (/var/run/docker.sock)."
            )
            lateral_paths.append(
                "Process Execution -> Mount /var/run/docker.sock -> Spawn Privileged Container -> Full Host Root"
            )

        elif has_database_creds or has_cloud_keys or (has_sql_injection and has_exposed_db_port):
            tier_level = 2
            tier_name = "TIER 2 (DATA/SERVICE EXPOSURE)"
            privilege_level = "Database Administrator / Data Layer Access"
            compromised_boundaries.append("Database / Cloud Infrastructure Boundary")
            summary = (
                "Critical data tier blast radius: Application compromise exposes database credentials, "
                "internal datastores, or third-party cloud API keys."
            )
            if has_database_creds:
                lateral_paths.append(
                    "Local Credential Harvest -> Authenticate to PostgreSQL/MySQL -> Exfiltrate Customer Records"
                )
            if has_cloud_keys:
                lateral_paths.append(
                    "Extracted Cloud Credentials -> Invoke Cloud Provider APIs -> Lateral Cloud Resource Access"
                )

        else:
            tier_level = 1
            tier_name = "TIER 1 (LOCALIZED)"
            privilege_level = "Unprivileged Application Service Worker"
            summary = (
                "Localized blast radius: Vulnerabilities are confined to individual process execution "
                "or client-side sessions with no direct access to root infrastructure or lateral credentials."
            )
            lateral_paths.append("Vulnerability impact is isolated to target process execution space.")

        return BlastRadiusReport(
            tier=tier_name,
            tier_level=tier_level,
            summary=summary,
            accessible_assets=accessible_assets,
            compromised_boundaries=compromised_boundaries,
            privilege_level=privilege_level,
            lateral_movement_paths=lateral_paths,
        )
