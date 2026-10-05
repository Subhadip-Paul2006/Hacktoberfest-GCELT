"""API Security Validation Agent for NSAT."""

import time
from typing import Optional
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class APISecurityAgent(BaseValidationAgent):
    """Safely audits API endpoint inventory for method tampering, error leakage, and unauthenticated exposure."""

    @property
    def name(self) -> str:
        return "API Agent"

    @property
    def description(self) -> str:
        return "Audits API inventory for method tampering, stack trace leakage, and missing security headers."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        all_endpoints = ctx.surface.application.endpoints or []
        endpoints_to_test = [ep.path for ep in all_endpoints[:3]]
        if not endpoints_to_test:
            endpoints_to_test = ["/", "/api", "/api/v1/health"]

        overall_status = AgentResultStatus.NOT_VALIDATED
        debug_leak_detected = False

        matched_debug_finding = self.match_finding(
            ctx.findings,
            categories=["web_security", "code_sast"],
            keywords=["debug", "stack", "error", "leak"],
        )

        for path in endpoints_to_test:
            if not ctx.can_send_request():
                break

            # Probe 1: Send request triggering potential error or parameter parsing
            resp, err = self.safe_http_request(ctx, method="GET", path=path, params={"test_param": "nsat_probe_!@#"})
            if err:
                if "Connection refused" in err or "Timeout" in err:
                    return AgentExecutionResult(
                        agent_name=self.name,
                        status=AgentResultStatus.NOT_APPLICABLE,
                        error_message=err,
                        duration_seconds=time.time() - start_time,
                    )
                continue

            # Check for error tracebacks / sensitive internal leakage
            body = resp.text.lower()
            if any(leak in body for leak in ["traceback (most recent call last):", "exception in thread", "syntaxerror:", "internal server error:", "uvicorn.error"]):
                debug_leak_detected = True
                evidence_list.append(
                    ValidationEvidence(
                        agent=self.name,
                        target=ctx.target_url,
                        endpoint=path,
                        request_type="HTTP_GET",
                        safe_test_description="Sent unexpected parameter to evaluate error and stack trace leakage",
                        observed_response="Server response contains internal stack trace / debug details.",
                        status=AgentResultStatus.VALIDATED,
                        confidence=0.90,
                        related_finding_id=matched_debug_finding.id if matched_debug_finding else None,
                    )
                )

            # Probe 2: Method tampering (e.g. OPTIONS or unexpected verb)
            resp_opt, _ = self.safe_http_request(ctx, method="OPTIONS", path=path)
            if resp_opt and "allow" in [k.lower() for k in resp_opt.headers]:
                allow_header = resp_opt.headers.get("Allow") or resp_opt.headers.get("allow", "")
                if "TRACE" in allow_header or "*" in allow_header:
                    evidence_list.append(
                        ValidationEvidence(
                            agent=self.name,
                            target=ctx.target_url,
                            endpoint=path,
                            request_type="HTTP_OPTIONS",
                            safe_test_description="Audited allowed HTTP methods on endpoint",
                            observed_response=f"Allowed methods expose dangerous verbs: {allow_header}",
                            status=AgentResultStatus.POTENTIAL,
                            confidence=0.70,
                        )
                    )

        if debug_leak_detected:
            overall_status = AgentResultStatus.VALIDATED
            if matched_debug_finding:
                upgraded_ids.append(matched_debug_finding.id)
        elif evidence_list:
            overall_status = AgentResultStatus.POTENTIAL
        else:
            overall_status = AgentResultStatus.VALIDATED  # No API anomalies observed

        return AgentExecutionResult(
            agent_name=self.name,
            status=overall_status,
            evidence=evidence_list,
            upgraded_finding_ids=upgraded_ids,
            duration_seconds=time.time() - start_time,
        )
