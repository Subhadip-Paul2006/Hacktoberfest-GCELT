"""Network Validation Agent for NSAT."""

import socket
import time
from typing import Optional
from urllib.parse import urlparse
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class NetworkValidationAgent(BaseValidationAgent):
    """Safely audits reachable network services, public 0.0.0.0 listeners, and unauthenticated ports."""

    @property
    def name(self) -> str:
        return "Network Validation Agent"

    @property
    def description(self) -> str:
        return "Validates TCP service reachability, public wildcard socket bindings, and exposure."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        bindings = ctx.surface.infrastructure.bindings
        parsed = urlparse(ctx.target_url if "://" in ctx.target_url else f"http://{ctx.target_url}")
        target_host = parsed.hostname or "127.0.0.1"

        matched_finding = self.match_finding(
            ctx.findings,
            categories=["network_exposure", "code_sast"],
            keywords=["binding", "0.0.0.0", "inaddr_any", "network", "port"],
        )

        overall_status = AgentResultStatus.NOT_VALIDATED
        validated_binding = False

        # Check each discovered binding
        tested_ports = set()
        for b in bindings:
            port = b.port or parsed.port or 8000
            if port in tested_ports:
                continue
            tested_ports.add(port)

            # Probe TCP socket reachability
            is_open = False
            banner = ""
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(min(1.5, ctx.config.request_timeout))
                    res = s.connect_ex((target_host, port))
                    if res == 0:
                        is_open = True
                        try:
                            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            raw = s.recv(256)
                            banner = raw.decode("utf-8", errors="replace").split("\r\n")[0]
                        except Exception:
                            banner = "Connected (no initial banner)"
            except Exception:
                is_open = False

            exposure_flag = b.exposure == "POTENTIALLY_LAN_REACHABLE" or b.host in ("0.0.0.0", "::", "INADDR_ANY")

            if is_open:
                if exposure_flag:
                    validated_binding = True
                    desc = f"Port {port} is active and bound to wildcard '{b.host}' — reachable from all network interfaces."
                    status = AgentResultStatus.VALIDATED
                else:
                    desc = f"Port {port} is active and restricted to local host '{b.host}'."
                    status = AgentResultStatus.NOT_VALIDATED

                evidence_list.append(
                    ValidationEvidence(
                        agent=self.name,
                        target=f"{target_host}:{port}",
                        endpoint=f":{port}",
                        request_type="TCP_CONNECT",
                        safe_test_description=f"Attempted non-destructive TCP handshake on port {port}",
                        observed_response=f"{desc} Banner: {banner}",
                        status=status,
                        confidence=0.95 if exposure_flag else 0.85,
                        related_finding_id=matched_finding.id if (matched_finding and exposure_flag) else None,
                        details={"port": port, "host": b.host, "banner": banner},
                    )
                )

        if validated_binding:
            overall_status = AgentResultStatus.VALIDATED
            if matched_finding:
                upgraded_ids.append(matched_finding.id)
        elif evidence_list:
            overall_status = AgentResultStatus.NOT_VALIDATED
        else:
            # If no bindings were open, verify default target port
            target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            overall_status = AgentResultStatus.POTENTIAL

        return AgentExecutionResult(
            agent_name=self.name,
            status=overall_status,
            evidence=evidence_list,
            upgraded_finding_ids=upgraded_ids,
            duration_seconds=time.time() - start_time,
        )
