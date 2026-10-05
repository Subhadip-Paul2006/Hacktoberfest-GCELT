"""Post-Compromise Exposure and Blast Radius Agent for NSAT."""

import time
from typing import Optional
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class PostCompromiseExposureAgent(BaseValidationAgent):
    """Assesses potential blast radius and post-compromise asset exposure across containers, host, and secrets."""

    @property
    def name(self) -> str:
        return "Post-Compromise Exposure Agent"

    @property
    def description(self) -> str:
        return "Models blast radius (Tier 1-3) and asset exposure graph from host/container/secret findings."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        secrets = ctx.surface.data.secrets
        docker_present = ctx.surface.infrastructure.docker_present
        findings = ctx.findings

        # Identify key asset exposure indicators
        has_docker_sock = any(
            "/var/run/docker.sock" in f.description.lower() or "/var/run/docker.sock" in f.title.lower()
            for f in findings
        )
        has_root_user = any(
            "root" in f.title.lower() and f.category == "container"
            for f in findings
        )
        has_cloud_keys = any(
            s.secret_type in ("cloud_credential", "api_key") or "aws" in s.file_path.lower()
            for s in secrets
        )
        has_db_creds = any(
            s.secret_type in ("password", "token") or "password" in f.title.lower()
            for s in secrets for f in findings if f.category == "secret"
        )

        matched_finding = self.match_finding(
            findings,
            categories=["container", "secret", "host"],
            keywords=["docker.sock", "root", "secret", "password", "aws"],
        )

        # Calculate Tier and Exposure Model Chains
        chains = []
        if has_docker_sock or has_root_user:
            tier = "TIER 3 (HOST_TAKEOVER)"
            chain = "APPLICATION_PROCESS -> DOCKER_SOCKET (/var/run/docker.sock) -> HOST_ROOT_TAKEOVER"
            chains.append(chain)
        elif has_cloud_keys or has_db_creds:
            tier = "TIER 2 (DATA_EXPOSURE)"
            chain = "APPLICATION_PROCESS -> ENVIRONMENT_SECRETS (.env) -> DATABASE_CREDENTIALS / CLOUD_API"
            chains.append(chain)
        else:
            tier = "TIER 1 (LOCALIZED)"
            chain = "APPLICATION_PROCESS -> LOCAL_PROCESS_MEMORY (No broad lateral pivot)"
            chains.append(chain)

        overall_status = AgentResultStatus.VALIDATED if (has_docker_sock or has_cloud_keys or has_db_creds) else AgentResultStatus.POTENTIAL

        desc = (
            f"Assessed blast radius model: {tier}. "
            f"Chains identified: {'; '.join(chains)}. "
            f"Secrets exposed: {len(secrets)}, Docker present: {docker_present}."
        )

        evidence_list.append(
            ValidationEvidence(
                agent=self.name,
                target=ctx.target_url,
                endpoint="local_asset_environment",
                request_type="INSPECT_BLAST_RADIUS",
                safe_test_description="Evaluated post-compromise lateral expansion vectors from Phase 2 findings",
                observed_response=self.redact(desc),
                status=overall_status,
                confidence=0.92,
                related_finding_id=matched_finding.id if matched_finding else None,
                details={
                    "blast_radius_tier": tier,
                    "chains": chains,
                    "docker_sock_mounted": has_docker_sock,
                    "secrets_count": len(secrets),
                },
            )
        )

        if overall_status == AgentResultStatus.VALIDATED and matched_finding:
            upgraded_ids.append(matched_finding.id)

        return AgentExecutionResult(
            agent_name=self.name,
            status=overall_status,
            evidence=evidence_list,
            upgraded_finding_ids=upgraded_ids,
            duration_seconds=time.time() - start_time,
        )
