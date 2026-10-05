"""WebSocket Validation Agent for NSAT."""

import time
from typing import Optional
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class WebSocketAgent(BaseValidationAgent):
    """Safely audits WebSocket endpoints for origin validation, handshake auth, and CSWSH indicators."""

    @property
    def name(self) -> str:
        return "WebSocket Agent"

    @property
    def description(self) -> str:
        return "Evaluates WebSocket handshake authentication and cross-site origin validation."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        ws_endpoints = [
            ep.path for ep in ctx.surface.application.websocket_endpoints
        ] or [
            ep.path for ep in ctx.surface.application.endpoints
            if any(k in ep.path.lower() for k in ["ws", "socket", "stream"])
        ] or ["/ws"]

        target_path = ws_endpoints[0]

        matched_finding = self.match_finding(
            ctx.findings,
            categories=["web_security", "network_exposure"],
            keywords=["websocket", "ws", "socket", "origin"],
        )

        overall_status = AgentResultStatus.NOT_APPLICABLE

        # 1. Try WebSocket connection with untrusted origin if client supports websocket_connect
        if hasattr(ctx.client, "websocket_connect"):
            try:
                with ctx.client.websocket_connect(
                    target_path,
                    headers={"Origin": "https://unauthorized-external-origin.com"},
                ) as ws:
                    try:
                        msg = ws.receive_text()
                    except Exception:
                        msg = "Connected"
                    overall_status = AgentResultStatus.VALIDATED
                    if matched_finding:
                        upgraded_ids.append(matched_finding.id)

                    evidence_list.append(
                        ValidationEvidence(
                            agent=self.name,
                            target=ctx.target_url,
                            endpoint=target_path,
                            request_type="WS_CONNECT",
                            safe_test_description="Connected to WebSocket with unauthorized third-party Origin header",
                            observed_response="Handshake accepted without origin rejection. CSWSH vulnerability indicator.",
                            status=AgentResultStatus.VALIDATED,
                            confidence=0.90,
                            related_finding_id=matched_finding.id if matched_finding else None,
                        )
                    )
                    return AgentExecutionResult(
                        agent_name=self.name,
                        status=overall_status,
                        evidence=evidence_list,
                        upgraded_finding_ids=upgraded_ids,
                        duration_seconds=time.time() - start_time,
                    )
            except Exception as ws_err:
                err_str = str(ws_err).lower()
                if "403" in err_str or "rejected" in err_str:
                    overall_status = AgentResultStatus.NOT_VALIDATED
                    evidence_list.append(
                        ValidationEvidence(
                            agent=self.name,
                            target=ctx.target_url,
                            endpoint=target_path,
                            request_type="WS_CONNECT",
                            safe_test_description="Connected to WebSocket with unauthorized Origin header",
                            observed_response="Handshake properly rejected by server.",
                            status=AgentResultStatus.NOT_VALIDATED,
                            confidence=0.85,
                            related_finding_id=matched_finding.id if matched_finding else None,
                        )
                    )
                    return AgentExecutionResult(
                        agent_name=self.name,
                        status=overall_status,
                        evidence=evidence_list,
                        duration_seconds=time.time() - start_time,
                    )

        # 2. Fallback HTTP handshake probe with unauthorized untrusted Origin
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "Origin": "https://unauthorized-external-origin.com",
        }

        resp, err = self.safe_http_request(ctx, method="GET", path=target_path, headers=headers)

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
                status=AgentResultStatus.NOT_APPLICABLE,
                duration_seconds=time.time() - start_time,
            )

        if resp.status_code == 101 or (resp.status_code == 200 and "upgrade" in resp.headers.get("Connection", "").lower()):
            overall_status = AgentResultStatus.VALIDATED
            if matched_finding:
                upgraded_ids.append(matched_finding.id)

            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=target_path,
                    request_type="WS_HANDSHAKE",
                    safe_test_description="Sent WebSocket handshake upgrade with unauthorized third-party Origin header",
                    observed_response="Handshake accepted (Status 101 / Upgrade allowed) without origin rejection. CSWSH vulnerability indicator.",
                    status=AgentResultStatus.VALIDATED,
                    confidence=0.88,
                    related_finding_id=matched_finding.id if matched_finding else None,
                )
            )
        elif resp.status_code in (400, 403):
            overall_status = AgentResultStatus.NOT_VALIDATED
            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=target_path,
                    request_type="WS_HANDSHAKE",
                    safe_test_description="Sent WebSocket handshake upgrade with external Origin header",
                    observed_response=f"Handshake properly rejected with HTTP {resp.status_code}.",
                    status=AgentResultStatus.NOT_VALIDATED,
                    confidence=0.85,
                    related_finding_id=matched_finding.id if matched_finding else None,
                )
            )
        else:
            overall_status = AgentResultStatus.NOT_APPLICABLE

        return AgentExecutionResult(
            agent_name=self.name,
            status=overall_status,
            evidence=evidence_list,
            upgraded_finding_ids=upgraded_ids,
            duration_seconds=time.time() - start_time,
        )
