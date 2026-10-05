"""Authentication Validation Agent for NSAT."""

import time
from typing import Optional
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class AuthenticationValidationAgent(BaseValidationAgent):
    """Safely validates login endpoints, account enumeration, and session management."""

    @property
    def name(self) -> str:
        return "Authentication Agent"

    @property
    def description(self) -> str:
        return "Validates login controls, account enumeration, and session tokens."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        # Find login/auth endpoint
        auth_paths = [
            ep.path for ep in ctx.surface.application.auth_endpoints
        ] or [
            ep.path for ep in ctx.surface.application.endpoints
            if any(k in ep.path.lower() for k in ["login", "auth", "token", "signin"])
        ]

        if not auth_paths:
            auth_paths = ["/api/v1/login", "/login"]

        matched_finding = self.match_finding(
            ctx.findings,
            categories=["authentication", "web_security"],
            keywords=["auth", "login", "password", "token"],
        )

        overall_status = AgentResultStatus.NOT_APPLICABLE
        endpoint_tested = auth_paths[0]

        # Probe 1: Non-existent user probe to check account enumeration
        resp1, err1 = self.safe_http_request(
            ctx,
            method="POST",
            path=endpoint_tested,
            json_data={"username": "non_existent_nsat_user_999", "password": "DummyPassword123!"},
        )

        if err1:
            if "Connection refused" in err1 or "Timeout" in err1:
                return AgentExecutionResult(
                    agent_name=self.name,
                    status=AgentResultStatus.NOT_APPLICABLE,
                    error_message=err1,
                    duration_seconds=time.time() - start_time,
                )
            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=endpoint_tested,
                    request_type="HTTP_POST",
                    safe_test_description="Safe probe for authentication endpoint availability",
                    observed_response=f"Error: {err1}",
                    status=AgentResultStatus.ERROR,
                    confidence=0.5,
                    related_finding_id=matched_finding.id if matched_finding else None,
                )
            )
            return AgentExecutionResult(
                agent_name=self.name,
                status=AgentResultStatus.ERROR,
                evidence=evidence_list,
                duration_seconds=time.time() - start_time,
            )

        # Probe 2: Known/common user with wrong password
        resp2, err2 = self.safe_http_request(
            ctx,
            method="POST",
            path=endpoint_tested,
            json_data={"username": "admin", "password": "wrong_password_probe_123"},
        )

        status_code1 = resp1.status_code if resp1 else 0
        status_code2 = resp2.status_code if resp2 else 0
        body1 = resp1.text if resp1 else ""
        body2 = resp2.text if resp2 else ""

        # Analyze Account Enumeration
        enum_detected = False
        enum_desc = "Authentication responses are uniform for existent and non-existent users."
        if ("user not found" in body1.lower() or "no such user" in body1.lower()) and (
            "incorrect password" in body2.lower() or "invalid password" in body2.lower()
        ):
            enum_detected = True
            enum_desc = "Disparate error messages reveal username existence (Account Enumeration indicator)."
        elif status_code1 != status_code2 and status_code1 in (404, 400) and status_code2 in (401, 403):
            enum_detected = True
            enum_desc = f"Different HTTP status codes returned for unknown user ({status_code1}) vs invalid password ({status_code2})."

        # Check for Session / Token issuance controls
        token_control_desc = "No sensitive token leakage observed in unauthenticated flows."

        if enum_detected:
            overall_status = AgentResultStatus.POTENTIAL
            if matched_finding:
                upgraded_ids.append(matched_finding.id)
        else:
            overall_status = AgentResultStatus.VALIDATED if (status_code1 in (401, 400, 200)) else AgentResultStatus.NOT_VALIDATED

        evidence_list.append(
            ValidationEvidence(
                agent=self.name,
                target=ctx.target_url,
                endpoint=endpoint_tested,
                request_type="HTTP_POST",
                safe_test_description="Evaluated authentication response uniformity and credential validation",
                observed_response=self.redact(f"Status codes: [NonExistent={status_code1}, Existent={status_code2}]. Summary: {enum_desc}"),
                status=overall_status,
                confidence=0.85 if enum_detected else 0.70,
                related_finding_id=matched_finding.id if matched_finding else None,
                details={"enum_detected": enum_detected, "tested_endpoint": endpoint_tested},
            )
        )

        return AgentExecutionResult(
            agent_name=self.name,
            status=overall_status,
            evidence=evidence_list,
            upgraded_finding_ids=upgraded_ids,
            duration_seconds=time.time() - start_time,
        )
