"""Swarm Planner for NSAT Active Validation.

Determines relevant validation agents based on ProjectIntelligence,
SecuritySurface, existing CanonicalFindings, and TargetScope.
Avoids running irrelevant agents blindly.
"""

from typing import Any
from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding
from nsat.swarm.models import TargetScope


class SwarmPlanner:
    """
    Evaluates project context and security surface to produce an optimized,
    context-aware validation agent execution plan.
    """

    ALL_AGENTS = [
        "Authentication Agent",
        "Authorization Agent",
        "API Agent",
        "Input Validation Agent",
        "Rate Limit Agent",
        "Business Logic Agent",
        "Payment Agent",
        "WebSocket Agent",
        "File Upload Agent",
        "Network Validation Agent",
        "Post-Compromise Exposure Agent",
    ]

    def plan(
        self,
        intelligence: ProjectIntelligence,
        surface: SecuritySurface,
        findings: list[CanonicalFinding],
        scope: TargetScope,
    ) -> tuple[list[str], list[tuple[str, str]]]:
        """
        Produce a list of selected agent names and skipped agent names with reasons.
        """
        selected: list[str] = []
        skipped: list[tuple[str, str]] = []

        all_endpoints = surface.application.endpoints
        paths = [ep.path.lower() for ep in all_endpoints]
        finding_categories = {f.category for f in findings}
        finding_titles = " ".join(f.title.lower() for f in findings)
        sink_types = {sink.sink_type for sink in surface.code.execution_sinks}

        # 1. Authentication Agent
        has_auth_endpoints = bool(surface.application.auth_endpoints) or any(
            any(k in p for k in ["login", "auth", "token", "password", "otp", "session"])
            for p in paths
        )
        has_auth_findings = (
            "authentication" in finding_categories
            or "jwt" in finding_titles
            or "auth" in finding_titles
            or any(s.secret_type in ("jwt", "token") for s in surface.data.secrets)
        )
        if has_auth_endpoints or has_auth_findings:
            selected.append("Authentication Agent")
        else:
            skipped.append(("Authentication Agent", "No login/auth endpoints or authentication findings detected"))

        # 2. Authorization Agent
        has_admin_endpoints = bool(surface.application.admin_endpoints) or any("admin" in p for p in paths)
        has_id_endpoints = any(any(k in p for k in ["{id}", "<id>", "/users/", "/account/", "/items/"]) for p in paths)
        if has_admin_endpoints or has_id_endpoints or len(all_endpoints) > 1:
            selected.append("Authorization Agent")
        else:
            skipped.append(("Authorization Agent", "No multi-user, object-id, or admin endpoints discovered"))

        # 3. API Agent
        if all_endpoints or any(lang in intelligence.languages for lang in ["python", "javascript", "typescript"]):
            selected.append("API Agent")
        else:
            skipped.append(("API Agent", "No HTTP/REST API endpoints present"))

        # 4. Input Validation Agent
        has_sinks = bool(surface.code.execution_sinks) or bool(surface.code.input_sources)
        has_injection_findings = any(k in finding_titles for k in ["injection", "sql", "command", "traversal", "xss"])
        if has_sinks or has_injection_findings or all_endpoints:
            selected.append("Input Validation Agent")
        else:
            skipped.append(("Input Validation Agent", "No dynamic execution sinks or injection vectors discovered"))

        # 5. Rate Limit Agent
        if has_auth_endpoints or all_endpoints or "rate limit" in finding_titles:
            selected.append("Rate Limit Agent")
        else:
            skipped.append(("Rate Limit Agent", "No sensitive transactional or authentication endpoints to rate limit"))

        # 6. Business Logic Agent
        has_logic_endpoints = any(
            any(k in p for k in ["order", "cart", "checkout", "refund", "confirm", "coupon", "discount", "status"])
            for p in paths
        )
        if has_logic_endpoints or "logic" in finding_titles or "order" in finding_titles:
            selected.append("Business Logic Agent")
        else:
            skipped.append(("Business Logic Agent", "No stateful multi-step business workflow endpoints discovered"))

        # 7. Payment Agent
        has_payment = any(
            any(k in p for k in ["pay", "billing", "checkout", "charge", "invoice", "stripe", "paypal"])
            for p in paths
        )
        if has_payment or "payment" in finding_titles or "price" in finding_titles:
            selected.append("Payment Agent")
        else:
            skipped.append(("Payment Agent", "No payment, billing, or transaction endpoints found"))

        # 8. WebSocket Agent
        if surface.application.websocket_endpoints or any("ws" in p or "socket" in p for p in paths):
            selected.append("WebSocket Agent")
        else:
            skipped.append(("WebSocket Agent", "No WebSocket endpoints or listeners identified in surface"))

        # 9. File Upload Agent
        if (
            surface.application.upload_endpoints
            or any("upload" in p or "file" in p for p in paths)
            or "filesystem_write" in sink_types
        ):
            selected.append("File Upload Agent")
        else:
            skipped.append(("File Upload Agent", "No file upload or multipart forms surfaced"))

        # 10. Network Validation Agent
        if surface.infrastructure.bindings or "network_exposure" in finding_categories or "network" in finding_categories:
            selected.append("Network Validation Agent")
        else:
            skipped.append(("Network Validation Agent", "No local or external network listeners configured"))

        # 11. Post-Compromise Exposure Agent
        if (
            surface.infrastructure.docker_present
            or surface.data.secrets
            or surface.data.sensitive_files
            or "container" in finding_categories
            or "secret" in finding_categories
            or "host" in finding_categories
        ):
            selected.append("Post-Compromise Exposure Agent")
        else:
            skipped.append(("Post-Compromise Exposure Agent", "No container, host, or credential assets detected for blast radius"))

        return selected, skipped
