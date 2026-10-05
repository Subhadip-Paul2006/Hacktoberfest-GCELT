"""Payment Flow Validation Agent for NSAT."""

import time
from typing import Optional
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class PaymentFlowAgent(BaseValidationAgent):
    """Safely assesses client-side price tampering and client-trusted payment status indicators."""

    @property
    def name(self) -> str:
        return "Payment Agent"

    @property
    def description(self) -> str:
        return "Safely audits payment endpoints for client-side price manipulation and unverified status flags."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        all_endpoints = ctx.surface.application.endpoints
        paths = [ep.path for ep in all_endpoints]

        payment_endpoints = [
            p for p in paths if any(k in p.lower() for k in ["pay", "checkout", "charge", "billing"])
        ] or ["/api/v1/checkout", "/checkout"]

        target_path = payment_endpoints[0]

        matched_finding = self.match_finding(
            ctx.findings,
            categories=["web_security", "code_sast"],
            keywords=["pay", "price", "checkout", "amount", "transaction"],
        )

        overall_status = AgentResultStatus.NOT_VALIDATED

        # Probe 1: Client-trusted price parameter tampering probe ($0.01)
        resp_tamper, err = self.safe_http_request(
            ctx,
            method="POST",
            path=target_path,
            json_data={
                "item_id": 101,
                "quantity": 1,
                "price": 0.01,
                "amount": 0.01,
                "payment_status": "PAID",
            },
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

        body_lower = resp_tamper.text.lower()

        # If server blindly accepts arbitrary client price/status
        if resp_tamper.status_code == 200 and any(k in body_lower for k in ["success", "approved", "processed", "charge"]):
            overall_status = AgentResultStatus.VALIDATED
            if matched_finding:
                upgraded_ids.append(matched_finding.id)

            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=target_path,
                    request_type="HTTP_POST",
                    safe_test_description="Submitted client-tampered price ($0.01) and payment_status flag to checkout endpoint",
                    observed_response=self.redact(f"Server accepted client-specified price/status: {resp_tamper.text[:120]}"),
                    status=AgentResultStatus.VALIDATED,
                    confidence=0.92,
                    related_finding_id=matched_finding.id if matched_finding else None,
                    details={"tampered_amount": 0.01, "status_code": resp_tamper.status_code},
                )
            )
        elif resp_tamper.status_code in (400, 422, 403):
            overall_status = AgentResultStatus.NOT_VALIDATED
            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=target_path,
                    request_type="HTTP_POST",
                    safe_test_description="Submitted client-tampered price parameters",
                    observed_response=f"Server rejected client-supplied price parameters with status {resp_tamper.status_code}.",
                    status=AgentResultStatus.NOT_VALIDATED,
                    confidence=0.88,
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
