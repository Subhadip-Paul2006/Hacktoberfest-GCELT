"""Base class and context for NSAT Validation Agents."""

from abc import ABC, abstractmethod
from typing import Any, Optional
import re
import time
import httpx
from pydantic import BaseModel, Field

from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.swarm.models import (
    AgentExecutionResult,
    AgentResultStatus,
    SwarmConfig,
    TargetScope,
    ValidationEvidence,
)


class SwarmValidationContext:
    """Shared execution context provided to validation agents during execution."""

    def __init__(
        self,
        target_url: str,
        surface: SecuritySurface,
        intelligence: ProjectIntelligence,
        findings: list[CanonicalFinding],
        config: SwarmConfig,
        scope: TargetScope,
        http_client: Optional[httpx.Client] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.surface = surface
        self.intelligence = intelligence
        self.findings = findings
        self.config = config
        self.scope = scope
        self.requests_sent = 0
        self._client = http_client or httpx.Client(
            timeout=config.request_timeout,
            verify=False,
            follow_redirects=True,
        )

    @property
    def client(self) -> httpx.Client:
        return self._client

    def can_send_request(self) -> bool:
        return self.requests_sent < self.config.global_target_budget

    def increment_request_counter(self) -> None:
        self.requests_sent += 1

    def close(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass


class BaseValidationAgent(ABC):
    """Abstract base class for all NSAT active validation agents."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the validation agent."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description of the validation capability."""
        pass

    @abstractmethod
    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        """Execute safe, non-destructive bounded validation."""
        pass

    def redact(self, text: str) -> str:
        """Sanitize sensitive secrets, keys, or passwords from logs and evidence."""
        if not text:
            return ""
        # Redact JWTs
        text = re.sub(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", "eyJ...[REDACTED_JWT]", text)
        # Redact AWS keys
        text = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA...[REDACTED_AWS_KEY]", text)
        # Redact generic passwords / tokens
        text = re.sub(r"(password|token|secret|key)[\"':= ]+([^\"' ,;}\n]+)", r"\1=***REDACTED***", text, flags=re.IGNORECASE)
        # Truncate if response body is too long
        if len(text) > 400:
            text = text[:400] + "... [TRUNCATED]"
        return text

    def safe_http_request(
        self,
        ctx: SwarmValidationContext,
        method: str,
        path: str,
        params: Optional[dict[str, Any]] = None,
        json_data: Optional[dict[str, Any]] = None,
        data: Optional[Any] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> tuple[Optional[httpx.Response], Optional[str]]:
        """
        Safely execute a bounded HTTP request respecting scope, payload size, and budgets.
        Returns (response, error_string).
        """
        if not ctx.scope.is_authorized():
            return None, "Target out of authorized scope"

        if not ctx.can_send_request():
            return None, "Global target request budget exhausted"

        full_url = f"{ctx.target_url}{path}" if path.startswith("/") else f"{ctx.target_url}/{path}"
        ctx.increment_request_counter()

        req_headers = headers or {}
        req_headers.setdefault("User-Agent", "NSAT-Security-Validation-Agent/1.0 (Defensive)")

        try:
            resp = ctx.client.request(
                method=method.upper(),
                url=full_url,
                params=params,
                json=json_data,
                data=data,
                headers=req_headers,
            )
            return resp, None
        except httpx.ConnectError:
            return None, f"Connection refused to {full_url}"
        except httpx.TimeoutException:
            return None, f"Timeout after {ctx.config.request_timeout}s at {full_url}"
        except Exception as e:
            return None, f"Request failed: {type(e).__name__} ({str(e)})"

    def match_finding(
        self,
        findings: list[CanonicalFinding],
        categories: list[str],
        keywords: list[str],
        file_path_hint: Optional[str] = None,
    ) -> Optional[CanonicalFinding]:
        """Find an existing CanonicalFinding to upgrade with active validation evidence."""
        for f in findings:
            if f.category in categories or not categories:
                title_lower = f.title.lower()
                desc_lower = f.description.lower()
                if any(kw.lower() in title_lower or kw.lower() in desc_lower for kw in keywords):
                    if file_path_hint and f.file_path:
                        if file_path_hint.lower() in f.file_path.lower():
                            return f
                    else:
                        return f
        return None
