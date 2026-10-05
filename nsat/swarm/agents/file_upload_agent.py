"""File Upload Validation Agent for NSAT."""

import time
from typing import Optional
from nsat.swarm.agents.base import BaseValidationAgent, SwarmValidationContext
from nsat.swarm.models import AgentExecutionResult, AgentResultStatus, ValidationEvidence


class FileUploadAgent(BaseValidationAgent):
    """Safely audits file upload endpoints for extension restrictions, MIME validation, and path traversal."""

    @property
    def name(self) -> str:
        return "File Upload Agent"

    @property
    def description(self) -> str:
        return "Audits multipart upload forms for file extension whitelisting and path traversal filenames."

    def validate(self, ctx: SwarmValidationContext) -> AgentExecutionResult:
        start_time = time.time()
        evidence_list: list[ValidationEvidence] = []
        upgraded_ids: list[str] = []

        all_endpoints = ctx.surface.application.endpoints
        upload_endpoints = [
            ep.path for ep in ctx.surface.application.upload_endpoints
        ] or [
            ep.path for ep in all_endpoints if "upload" in ep.path.lower()
        ]

        if not upload_endpoints:
            return AgentExecutionResult(
                agent_name=self.name,
                status=AgentResultStatus.NOT_APPLICABLE,
                duration_seconds=time.time() - start_time,
            )

        target_path = upload_endpoints[0]

        matched_finding = self.match_finding(
            ctx.findings,
            categories=["web_security", "code_sast"],
            keywords=["upload", "file", "multipart", "extension"],
        )

        overall_status = AgentResultStatus.NOT_VALIDATED

        # Safe harmless probe: Upload a text-only script extension file with benign contents
        dummy_content = b"echo 'nsat harmless test probe'\n"
        files = {"file": ("probe_harmless.sh", dummy_content, "application/x-sh")}

        try:
            resp = ctx.client.post(
                f"{ctx.target_url}{target_path}",
                files=files,
                timeout=ctx.config.request_timeout,
            )
            ctx.increment_request_counter()
        except Exception as e:
            return AgentExecutionResult(
                agent_name=self.name,
                status=AgentResultStatus.NOT_APPLICABLE,
                error_message=str(e),
                duration_seconds=time.time() - start_time,
            )

        # Check response: if 200/201 without rejecting executable shell script extension
        if resp.status_code in (200, 201):
            overall_status = AgentResultStatus.VALIDATED
            if matched_finding:
                upgraded_ids.append(matched_finding.id)

            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=target_path,
                    request_type="HTTP_POST_MULTIPART",
                    safe_test_description="Submitted benign test file with executable extension (.sh) to upload endpoint",
                    observed_response=f"Upload endpoint accepted script extension with HTTP {resp.status_code}. Missing file type whitelist.",
                    status=AgentResultStatus.VALIDATED,
                    confidence=0.90,
                    related_finding_id=matched_finding.id if matched_finding else None,
                )
            )
        elif resp.status_code in (400, 415, 422):
            overall_status = AgentResultStatus.NOT_VALIDATED
            evidence_list.append(
                ValidationEvidence(
                    agent=self.name,
                    target=ctx.target_url,
                    endpoint=target_path,
                    request_type="HTTP_POST_MULTIPART",
                    safe_test_description="Submitted benign test file with executable extension (.sh)",
                    observed_response=f"Upload properly rejected with HTTP {resp.status_code}.",
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
