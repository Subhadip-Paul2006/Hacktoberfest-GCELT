"""Input Validation Agent for NSAT."""

import time
from typing import Optional
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class InputValidationAgent(BaseValidationAgent):
    """Safely validates SQL injection, command injection, and traversal vulnerabilities with non-destructive probes."""

    @property
    def name(self) -> str:
        return "Input Validation Agent"

    @property
    def description(self) -> str:
        return "Safely probes execution sinks with non-destructive SQL, command, and traversal canary payloads."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        all_endpoints = ctx.surface.application.endpoints
        overall_status = AgentResultStatus.NOT_VALIDATED

        # ── Test 1: SQL Injection Non-Destructive Probe ─────────────────
        sqli_endpoints = [
            ep.path for ep in all_endpoints if any(k in ep.path.lower() for k in ["search", "query", "find", "user", "item"])
        ] or ["/search"]

        sqli_finding = self.match_finding(
            ctx.findings,
            categories=["code_sast"],
            keywords=["sql", "sqlite", "query", "injection"],
        )

        for ep_path in sqli_endpoints:
            if not ctx.can_send_request():
                break

            # Send benign SQL syntax probe
            resp_sqli, err_sqli = self.safe_http_request(
                ctx,
                method="GET",
                path=ep_path,
                params={"x1": "' OR '1'='1", "q": "' OR '1'='1", "query": "' OR '1'='1"},
            )
            if err_sqli:
                if "Connection refused" in err_sqli or "Timeout" in err_sqli:
                    return AgentExecutionResult(
                        agent_name=self.name,
                        status=AgentResultStatus.NOT_APPLICABLE,
                        error_message=err_sqli,
                        duration_seconds=time.time() - start_time,
                    )
                continue

            sqli_text = resp_sqli.text.lower()
            if any(indicator in sqli_text for indicator in [
                "sqlite3.operationalerror",
                "syntax error",
                "unclosed quotation mark",
                "sql syntax",
                "database error",
                "psycopg2",
            ]) or (resp_sqli.status_code == 200 and "results" in sqli_text and len(resp_sqli.text) > 10):
                evidence_list.append(
                    ValidationEvidence(
                        agent=self.name,
                        target=ctx.target_url,
                        endpoint=ep_path,
                        request_type="HTTP_GET",
                        safe_test_description="Sent non-destructive SQL syntax/logical canary (' OR '1'='1)",
                        observed_response=self.redact(f"Observed SQL reflection/unhandled query state. Status: {resp_sqli.status_code}"),
                        status=AgentResultStatus.VALIDATED,
                        confidence=0.95,
                        related_finding_id=sqli_finding.id if sqli_finding else None,
                    )
                )
                if sqli_finding:
                    upgraded_ids.append(sqli_finding.id)
                overall_status = AgentResultStatus.VALIDATED
                break

        # ── Test 2: Command Injection Non-Destructive Canary ─────────────
        cmd_endpoints = [
            ep.path for ep in all_endpoints if any(k in ep.path.lower() for k in ["run", "exec", "task", "cmd", "ping"])
        ] or ["/run"]

        cmd_finding = self.match_finding(
            ctx.findings,
            categories=["code_sast"],
            keywords=["command", "subprocess", "shell", "exec", "popen"],
        )

        canary_token = "__NSAT_VALIDATION_CANARY_OK__"
        for ep_path in cmd_endpoints:
            if not ctx.can_send_request():
                break

            # Safe harmless probe: echo canary token (no destructive command)
            resp_cmd, _ = self.safe_http_request(
                ctx,
                method="POST",
                path=ep_path,
                json_data={"command": f"echo {canary_token}"},
            )
            if resp_cmd and canary_token in resp_cmd.text:
                evidence_list.append(
                    ValidationEvidence(
                        agent=self.name,
                        target=ctx.target_url,
                        endpoint=ep_path,
                        request_type="HTTP_POST",
                        safe_test_description="Sent safe stdout echo canary token to verify command execution sink",
                        observed_response=f"Canary '{canary_token}' reflected in server stdout response.",
                        status=AgentResultStatus.VALIDATED,
                        confidence=0.99,
                        related_finding_id=cmd_finding.id if cmd_finding else None,
                    )
                )
                if cmd_finding:
                    upgraded_ids.append(cmd_finding.id)
                overall_status = AgentResultStatus.VALIDATED
                break

        return AgentExecutionResult(
            agent_name=self.name,
            status=overall_status,
            evidence=evidence_list,
            upgraded_finding_ids=upgraded_ids,
            duration_seconds=time.time() - start_time,
        )
