"""Business Logic Validation Agent for NSAT."""

import time
from typing import Optional
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class BusinessLogicAgent(BaseValidationAgent):
    """Safely audits multi-step state transitions and workflow enforcement."""

    @property
    def name(self) -> str:
        return "Business Logic Agent"

    @property
    def description(self) -> str:
        return "Validates multi-step workflow integrity and unauthorized state-transition skipping."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        all_endpoints = ctx.surface.application.endpoints
        paths = [ep.path for ep in all_endpoints]

        # Check for multi-step order/confirmation endpoints
        order_create_path = next((p for p in paths if "order" in p and ("create" in p or "new" in p)), "/api/v1/order/create")
        order_confirm_path = next((p for p in paths if "confirm" in p or "complete" in p), "/api/v1/order/confirm")

        matched_finding = self.match_finding(
            ctx.findings,
            categories=["web_security", "code_sast"],
            keywords=["logic", "state", "order", "workflow", "transition"],
        )

        overall_status = AgentResultStatus.NOT_VALIDATED

        # Test state transition skipping: Attempt direct confirmation without intermediate payment
        resp_confirm, err = self.safe_http_request(
            ctx,
            method="POST",
            path=order_confirm_path,
            json_data={"order_id": "ORD-TEST-9999", "status": "CONFIRMED"},
        )

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

        if resp_confirm.status_code == 200 and any(k in resp_confirm.text.lower() for k in ["confirmed", "success", "completed"]):
            # Severe logic flaw: premature/unverified state transition accepted
            overall_status = AgentResultStatus.VALIDATED
            desc = f"Insecure state transition allowed: '{order_confirm_path}' directly accepted unverified order confirmation."
            if matched_finding:
                upgraded_ids.append(matched_finding.id)

            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=order_confirm_path,
                    request_type="HTTP_POST",
                    safe_test_description="Attempted to invoke final state confirmation without prior payment/validation state",
                    observed_response=self.redact(f"Direct confirmation succeeded with status 200: {resp_confirm.text[:120]}"),
                    status=AgentResultStatus.VALIDATED,
                    confidence=0.90,
                    related_finding_id=matched_finding.id if matched_finding else None,
                )
            )
        elif resp_confirm.status_code in (400, 403, 404, 422):
            overall_status = AgentResultStatus.NOT_VALIDATED
            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=order_confirm_path,
                    request_type="HTTP_POST",
                    safe_test_description="Attempted premature state transition confirmation",
                    observed_response=f"Premature transition rejected with status {resp_confirm.status_code}.",
                    status=AgentResultStatus.NOT_VALIDATED,
                    confidence=0.85,
                    related_finding_id=matched_finding.id if matched_finding else None,
                )
            )
        else:
            overall_status = AgentResultStatus.POTENTIAL

        return AgentExecutionResult(
            agent_name=self.name,
            status=overall_status,
            evidence=evidence_list,
            upgraded_finding_ids=upgraded_ids,
            duration_seconds=time.time() - start_time,
        )
