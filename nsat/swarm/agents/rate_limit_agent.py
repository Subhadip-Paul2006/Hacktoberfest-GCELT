"""Rate Limit and Abuse Prevention Agent for NSAT."""

import time
from typing import Optional
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class RateLimitAgent(BaseValidationAgent):
    """Safely audits login and sensitive endpoints for rate limiting using bounded low-volume probes."""

    @property
    def name(self) -> str:
        return "Rate Limit Agent"

    @property
    def description(self) -> str:
        return "Evaluates brute-force resistance and HTTP 429 throttling via bounded probes."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        all_endpoints = ctx.surface.application.endpoints
        login_endpoints = [
            ep.path for ep in ctx.surface.application.auth_endpoints
        ] or [
            ep.path for ep in all_endpoints if "login" in ep.path.lower()
        ]
        target_path = login_endpoints[0] if login_endpoints else "/api/v1/login"

        matched_finding = self.match_finding(
            ctx.findings,
            categories=["authentication", "dos_resource", "web_security"],
            keywords=["rate limit", "throttle", "brute", "lockout"],
        )

        # Bounded probe: exactly 5 rapid requests (safe, zero DDoS risk)
        PROBE_COUNT = 5
        statuses = []
        has_rate_limit_header = False

        for i in range(PROBE_COUNT):
            if not ctx.can_send_request():
                break
            resp, err = self.safe_http_request(
                ctx,
                method="POST",
                path=target_path,
                json_data={"username": f"nsat_test_{i}", "password": "wrong_password_test"},
            )
            if err:
                if "Connection refused" in err or "Timeout" in err:
                    return AgentExecutionResult(
                        agent_name=self.name,
                        status=AgentResultStatus.NOT_APPLICABLE,
                        error_message=err,
                        duration_seconds=time.time() - start_time,
                    )
                continue

            statuses.append(resp.status_code)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            if any(h in headers_lower for h in ["retry-after", "x-ratelimit-remaining", "ratelimit-limit"]):
                has_rate_limit_header = True

        if not statuses:
            return AgentExecutionResult(
                agent_name=self.name,
                status=AgentResultStatus.NOT_APPLICABLE,
                duration_seconds=time.time() - start_time,
            )

        # Classification
        # If any status is 429 -> PASS (rate limiting is active) -> NOT_VALIDATED vulnerability
        # If all requests were accepted with no 429 and no throttling headers -> FAIL -> VALIDATED vulnerability
        if 429 in statuses:
            classification = "PASS"
            agent_status = AgentResultStatus.NOT_VALIDATED
            desc = f"Rate limiting active on '{target_path}': HTTP 429 Too Many Requests observed after {statuses.index(429) + 1} requests."
            confidence = 0.95
        elif len(statuses) >= 4 and all(s in (200, 400, 401) for s in statuses) and not has_rate_limit_header:
            classification = "FAIL"
            agent_status = AgentResultStatus.VALIDATED  # Missing rate limiting confirmed
            desc = f"Missing rate limiting on sensitive endpoint '{target_path}': {len(statuses)} sequential login requests permitted without throttling or 429."
            confidence = 0.90
            if matched_finding:
                upgraded_ids.append(matched_finding.id)
        else:
            classification = "POTENTIAL EXPOSURE"
            agent_status = AgentResultStatus.POTENTIAL
            desc = f"Inconclusive throttling on '{target_path}'. Statuses: {statuses}"
            confidence = 0.60

        evidence_list.append(
            ValidationEvidence(
                agent=self.name,
                target=ctx.target_url,
                endpoint=target_path,
                request_type="HTTP_POST",
                safe_test_description=f"Sent {len(statuses)} bounded sequential probes to evaluate rate limiting and lockout enforcement",
                observed_response=f"Classification: {classification}. {desc} Response status sequence: {statuses}. Rate limit headers present: {has_rate_limit_header}",
                status=agent_status,
                confidence=confidence,
                related_finding_id=matched_finding.id if matched_finding else None,
                details={"classification": classification, "statuses": statuses},
            )
        )

        return AgentExecutionResult(
            agent_name=self.name,
            status=agent_status,
            evidence=evidence_list,
            upgraded_finding_ids=upgraded_ids,
            duration_seconds=time.time() - start_time,
        )
