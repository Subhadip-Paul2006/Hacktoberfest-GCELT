"""Swarm Coordinator for NSAT Active Validation."""

import time
from typing import Any, Optional
import httpx

from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.swarm.agents.api_agent import APISecurityAgent
from nsat.swarm.agents.auth_agent import AuthenticationValidationAgent
from nsat.swarm.agents.authz_agent import AuthorizationValidationAgent
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.agents.blast_radius_agent import PostCompromiseExposureAgent
from nsat.swarm.agents.business_logic_agent import BusinessLogicAgent
from nsat.swarm.agents.file_upload_agent import FileUploadAgent
from nsat.swarm.agents.input_validation_agent import InputValidationAgent
from nsat.swarm.agents.network_agent import NetworkValidationAgent
from nsat.swarm.agents.payment_agent import PaymentFlowAgent
from nsat.swarm.agents.rate_limit_agent import RateLimitAgent
from nsat.swarm.agents.websocket_agent import WebSocketAgent
from nsat.swarm.models import (
    AgentExecutionResult,
    AgentResultStatus,
    SwarmConfig,
    SwarmResult,
    TargetScope,
    ValidationEvidence,
)
from nsat.swarm.planner import SwarmPlanner


class SwarmCoordinator:
    """
    Coordinates context-aware validation agent execution, scope enforcement,
    error isolation, and finding upgrades.
    """

    def __init__(self, config: Optional[SwarmConfig] = None):
        self.config = config or SwarmConfig()
        self.planner = SwarmPlanner()
        self.agents_registry: dict[str, BaseValidationAgent] = {
            "Authentication Agent": AuthenticationValidationAgent(),
            "Authorization Agent": AuthorizationValidationAgent(),
            "API Agent": APISecurityAgent(),
            "Input Validation Agent": InputValidationAgent(),
            "Rate Limit Agent": RateLimitAgent(),
            "Business Logic Agent": BusinessLogicAgent(),
            "Payment Agent": PaymentFlowAgent(),
            "WebSocket Agent": WebSocketAgent(),
            "File Upload Agent": FileUploadAgent(),
            "Network Validation Agent": NetworkValidationAgent(),
            "Post-Compromise Exposure Agent": PostCompromiseExposureAgent(),
        }

    def run(
        self,
        target_url: str,
        intelligence: ProjectIntelligence,
        surface: SecuritySurface,
        findings: list[CanonicalFinding],
        scope: Optional[TargetScope] = None,
        http_client: Optional[httpx.Client] = None,
    ) -> SwarmResult:
        """
        Execute active validation swarm against authorized target.
        """
        start_time = time.time()
        target_scope = scope or TargetScope(target=target_url)

        # 1. Enforce Scope
        if not target_scope.is_authorized():
            return SwarmResult(
                target=target_url,
                scope_enforced=True,
                agents_selected=[],
                agents_skipped=[("All Agents", f"Target '{target_url}' is not in authorized scope")],
                agent_results={},
                all_evidence=[],
                findings=findings,
                upgraded_count=0,
                new_findings_count=0,
                duration_seconds=time.time() - start_time,
                correlation_handoff={"scope_blocked": True},
            )

        # 2. Plan swarm agents based on surface & findings
        selected_names, skipped_info = self.planner.plan(
            intelligence=intelligence,
            surface=surface,
            findings=findings,
            scope=target_scope,
        )

        # 3. Create execution context
        context = SwarmValidationContext(
            target_url=target_url,
            surface=surface,
            intelligence=intelligence,
            findings=findings,
            config=self.config,
            scope=target_scope,
            http_client=http_client,
        )

        agent_results: dict[str, AgentExecutionResult] = {}
        all_evidence: list[ValidationEvidence] = []
        upgraded_ids_set: set[str] = set()
        new_findings: list[CanonicalFinding] = []

        try:
            # 4. Execute selected agents with isolated error handling
            for name in selected_names:
                agent = self.agents_registry.get(name)
                if not agent:
                    continue

                try:
                    res = agent.validate(context)
                except Exception as e:
                    # Isolate agent failures — never crash swarm!
                    res = AgentExecutionResult(
                        agent_name=name,
                        status=AgentResultStatus.ERROR,
                        error_message=f"Agent unhandled exception: {type(e).__name__}: {str(e)}",
                    )

                agent_results[name] = res
                all_evidence.extend(res.evidence)
                upgraded_ids_set.update(res.upgraded_finding_ids)
                new_findings.extend(res.new_findings)

            # 5. Upgrade findings based on collected validation evidence
            findings_map = {f.id: f for f in findings}
            for fid in upgraded_ids_set:
                if fid in findings_map:
                    f = findings_map[fid]
                    f.status = "VALIDATED"
                    f.confidence = min(1.0, round(f.confidence + 0.15, 2))
                    f.confidence_label = "Actively validated by NSAT Swarm"

                    # Append matching evidence
                    for ev in all_evidence:
                        if ev.related_finding_id == fid:
                            f.evidence.append(
                                FindingEvidence(
                                    type="ACTIVE_VALIDATION",
                                    description=ev.safe_test_description,
                                    snippet=ev.observed_response[:200],
                                    context={
                                        "agent": ev.agent,
                                        "status": ev.status.value,
                                        "confidence": ev.confidence,
                                    },
                                )
                            )

            # Add any newly discovered findings
            findings.extend(new_findings)

        finally:
            context.close()

        # 6. Build Phase 4 Handoff
        correlation_handoff = {
            "target": target_url,
            "validated_finding_ids": list(upgraded_ids_set),
            "evidence_count": len(all_evidence),
            "agents_executed": list(agent_results.keys()),
            "scope_enforced": True,
        }

        return SwarmResult(
            target=target_url,
            scope_enforced=True,
            agents_selected=selected_names,
            agents_skipped=skipped_info,
            agent_results=agent_results,
            all_evidence=all_evidence,
            findings=findings,
            upgraded_count=len(upgraded_ids_set),
            new_findings_count=len(new_findings),
            duration_seconds=round(time.time() - start_time, 2),
            correlation_handoff=correlation_handoff,
        )
