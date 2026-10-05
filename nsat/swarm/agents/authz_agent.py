"""Authorization Validation Agent for NSAT."""

import time
from typing import Optional
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class AuthorizationValidationAgent(BaseValidationAgent):
    """Safely validates object-level authorization (IDOR/BOLA) and admin route protection."""

    @property
    def name(self) -> str:
        return "Authorization Agent"

    @property
    def description(self) -> str:
        return "Checks administrative route authorization and horizontal/vertical IDOR access."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        all_endpoints = ctx.surface.application.endpoints
        admin_paths = [
            ep.path for ep in ctx.surface.application.admin_endpoints
        ] or [
            ep.path for ep in all_endpoints if "admin" in ep.path.lower()
        ]
        if not admin_paths:
            admin_paths = ["/admin", "/api/v1/admin/dashboard"]

        matched_finding = self.match_finding(
            ctx.findings,
            categories=["web_security", "code_sast"],
            keywords=["admin", "authz", "authorization", "idor", "privilege"],
        )

        overall_status = AgentResultStatus.NOT_APPLICABLE
        target_path = admin_paths[0]

        # Probe 1: Unauthenticated request to administrative endpoint
        resp_unauth, err = self.safe_http_request(ctx, method="GET", path=target_path)
        if err:
            if "Connection refused" in err or "Timeout" in err:
                return AgentExecutionResult(
                    agent_name=self.name,
                    status=AgentResultStatus.NOT_APPLICABLE,
                    error_message=err,
                    duration_seconds=time.time() - start_time,
                )
            return AgentExecutionResult(
                agent_name=self.name,
                status=AgentResultStatus.ERROR,
                error_message=err,
                duration_seconds=time.time() - start_time,
            )

        # Check result
        if resp_unauth.status_code == 200:
            # High risk: Unauthenticated access to sensitive route permitted
            overall_status = AgentResultStatus.VALIDATED
            desc = f"Administrative endpoint '{target_path}' returned 200 OK without authentication."
            if matched_finding:
                upgraded_ids.append(matched_finding.id)
            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=target_path,
                    request_type="HTTP_GET",
                    safe_test_description="Unauthenticated request to administrative endpoint",
                    observed_response=self.redact(f"Status: 200 OK. Body snippet: {resp_unauth.text[:120]}"),
                    status=AgentResultStatus.VALIDATED,
                    confidence=0.95,
                    related_finding_id=matched_finding.id if matched_finding else None,
                )
            )
        elif resp_unauth.status_code in (401, 403):
            overall_status = AgentResultStatus.NOT_VALIDATED  # Properly protected
            desc = f"Administrative endpoint '{target_path}' properly returned {resp_unauth.status_code} Access Denied."
            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=target_path,
                    request_type="HTTP_GET",
                    safe_test_description="Unauthenticated request to administrative endpoint",
                    observed_response=f"Status: {resp_unauth.status_code} (Properly blocked)",
                    status=AgentResultStatus.NOT_VALIDATED,
                    confidence=0.90,
                    related_finding_id=matched_finding.id if matched_finding else None,
                )
            )
        else:
            overall_status = AgentResultStatus.POTENTIAL
            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=target_path,
                    request_type="HTTP_GET",
                    safe_test_description="Unauthenticated request to administrative endpoint",
                    observed_response=f"Status: {resp_unauth.status_code}",
                    status=AgentResultStatus.POTENTIAL,
                    confidence=0.60,
                    related_finding_id=matched_finding.id if matched_finding else None,
                )
            )

        # Probe 2: IDOR / Object Level Authorization check if user routes exist
        user_id_paths = [
            ep.path for ep in all_endpoints if any(k in ep.path for k in ["{id}", "<id>", "users"])
        ]
        if user_id_paths:
            probe_path = user_id_paths[0].replace("{id}", "1").replace("<id>", "1")
            resp_idor, _ = self.safe_http_request(ctx, method="GET", path=probe_path)
            if resp_idor and resp_idor.status_code == 200:
                evidence_list.append(
                    ValidationEvidence(
                        agent=self.name,
                        target=ctx.target_url,
                        endpoint=probe_path,
                        request_type="HTTP_GET",
                        safe_test_description="Tested resource accessibility without user session ownership",
                        observed_response=self.redact(f"Returned 200 OK for ID-based route '{probe_path}'"),
                        status=AgentResultStatus.POTENTIAL,
                        confidence=0.75,
                    )
                )

        return AgentExecutionResult(
            agent_name=self.name,
            status=overall_status,
            evidence=evidence_list,
            upgraded_finding_ids=upgraded_ids,
            duration_seconds=time.time() - start_time,
        )
