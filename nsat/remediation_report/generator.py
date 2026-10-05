"""
AI-assisted and deterministic narrative generator for NSAT Remediation Reports.

This generator is provider-neutral: it uses the existing LLMProvider interface
if a provider is supplied, otherwise produces a fully deterministic narrative.

It populates the free-text narrative fields of RemediationReportContext:
  - ai_executive_summary
  - ai_root_cause_narrative
  - ai_why_this_change
  - ai_final_recommendation

These fields are written ONLY into the report context — they do NOT alter
any NSAT security finding, remediation proposal, or security model.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from nsat.ai.provider import LLMProvider
from nsat.remediation_report.models import RemediationReportContext, ReportResult

logger = logging.getLogger("nsat.remediation_report.generator")

# ── Prompts ────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a professional application security engineer writing a human-review remediation report. "
    "Be precise, technical but accessible. Do not hallucinate code details not present in the context. "
    "Use ONLY the data provided. Clearly distinguish: OBSERVED, INFERRED, RECOMMENDED."
)

_EXECUTIVE_SUMMARY_PROMPT = """
Write a concise executive summary (3-5 sentences) for a remediation change report.

Finding ID: {finding_id}
Title: {title}
Severity: {severity}
Priority: {priority}
Description: {description}
Impact: {impact}
Proposed Change: {proposed_change}

Explain:
1. What security issue was detected.
2. Why it matters (business and technical risk).
3. What change is proposed to fix it.
Keep it suitable for a non-technical reviewer.
""".strip()

_ROOT_CAUSE_PROMPT = """
Explain the technical root cause of this security finding.

Finding: {title}
Category: {category}
Root Cause (from NSAT): {root_cause}
Evidence: {evidence}
Affected File: {file_path}
Line: {line_number}

Clearly label:
- OBSERVED: what NSAT actually detected
- INFERRED: what technical mechanism likely caused it
- RECOMMENDED: what change addresses the root cause

Do not invent implementation details not present in the evidence.
""".strip()

_WHY_THIS_CHANGE_PROMPT = """
Explain why the proposed remediation change is the correct security fix.

Finding: {title}
Severity: {severity}
Original Code Area: {original_snippet}
Proposed Change: {proposed_change}
Reason: {reason}
Attack Path / Blast Radius: {attack_path}

Explain:
1. Why the original implementation is unsafe.
2. Why the proposed change mitigates the vulnerability.
3. What security property is improved (e.g. least privilege, input validation, parameterisation).
4. What attack vector or exposure is reduced.
""".strip()

_FINAL_RECOMMENDATION_PROMPT = """
Write a final recommendation paragraph for this remediation report.

Finding: {title}
Severity: {severity}
Verification Plan: {verification_plan}
Patch Status: {patch_status}

Provide:
1. A clear recommended action for the reviewer.
2. What verification steps are most important.
3. A risk note if the patch is not applied.
Keep it to 3-5 sentences.
""".strip()


class RemediationReportGenerator:
    """
    Generates AI-assisted or deterministic narrative sections for remediation reports.

    This is a SEPARATE AI responsibility from the existing deterministic security engine.
    It uses the same LLMProvider abstraction but does NOT use Kimi (remediation-specific)
    or GLM (security-report-specific) directly — it accepts any configured provider.

    If no provider is given (offline / not configured), it falls back to
    clean deterministic prose generation.
    """

    @classmethod
    def generate_narratives(
        cls,
        ctx: RemediationReportContext,
        provider: Optional[LLMProvider] = None,
    ) -> RemediationReportContext:
        """
        Populate the ai_* narrative fields on the context.

        Returns the mutated context (in-place update for convenience).
        The caller must pass the returned context to the PDF renderer.
        """
        if provider:
            ctx = cls._generate_with_provider(ctx, provider)
        else:
            ctx = cls._generate_deterministic(ctx)
        return ctx

    @classmethod
    def _generate_with_provider(
        cls,
        ctx: RemediationReportContext,
        provider: LLMProvider,
    ) -> RemediationReportContext:
        """Attempt AI generation; fall back to deterministic on any failure."""

        def _safe_generate(prompt: str, field: str) -> Optional[str]:
            try:
                result = provider.generate(
                    prompt=prompt,
                    system_prompt=_SYSTEM_PROMPT,
                    temperature=0.2,
                    max_tokens=512,
                )
                if result and len(result.strip()) > 50:
                    return result.strip()
            except Exception as exc:
                logger.warning(
                    f"AI generation failed for '{field}' ({type(exc).__name__}): {exc}. "
                    "Using deterministic fallback."
                )
            return None

        attack_path_str = ctx.correlated_attack_path or ctx.blast_radius_tier or "Not identified"

        ctx.ai_executive_summary = _safe_generate(
            _EXECUTIVE_SUMMARY_PROMPT.format(
                finding_id=ctx.finding_id,
                title=ctx.finding_title,
                severity=ctx.severity,
                priority=ctx.priority or "N/A",
                description=ctx.description[:800],
                impact=ctx.impact[:400],
                proposed_change=ctx.proposed_change_description[:400],
            ),
            "executive_summary",
        )

        ctx.ai_root_cause_narrative = _safe_generate(
            _ROOT_CAUSE_PROMPT.format(
                title=ctx.finding_title,
                category=ctx.category,
                root_cause=ctx.root_cause[:600],
                evidence=ctx.evidence_summary[:400],
                file_path=ctx.file_path or "Not reliably resolved",
                line_number=str(ctx.line_number) if ctx.line_number else "N/A",
            ),
            "root_cause_narrative",
        )

        ctx.ai_why_this_change = _safe_generate(
            _WHY_THIS_CHANGE_PROMPT.format(
                title=ctx.finding_title,
                severity=ctx.severity,
                original_snippet=(ctx.original_snippet or "Not available")[:300],
                proposed_change=ctx.proposed_change_description[:400],
                reason=ctx.reason[:400],
                attack_path=attack_path_str[:300],
            ),
            "why_this_change",
        )

        ctx.ai_final_recommendation = _safe_generate(
            _FINAL_RECOMMENDATION_PROMPT.format(
                title=ctx.finding_title,
                severity=ctx.severity,
                verification_plan=ctx.verification_plan[:400],
                patch_status=ctx.patch_status.value,
            ),
            "final_recommendation",
        )

        if provider:
            ctx.model_provider = provider.provider_name

        # Fill any missing fields with deterministic prose
        ctx = cls._fill_missing_deterministic(ctx)
        return ctx

    @classmethod
    def _generate_deterministic(cls, ctx: RemediationReportContext) -> RemediationReportContext:
        """Produce clean, accurate deterministic prose from structured NSAT data."""
        ctx.model_provider = "deterministic"
        return cls._fill_missing_deterministic(ctx)

    @staticmethod
    def _fill_missing_deterministic(ctx: RemediationReportContext) -> RemediationReportContext:
        """Fill any unset narrative fields with high-quality deterministic prose."""
        sev = ctx.severity
        title = ctx.finding_title
        fid = ctx.finding_id
        file_str = ctx.file_path or "Not reliably resolved"
        change_desc = ctx.proposed_change_description or ctx.recommendation or "Apply recommended security fix."

        if not ctx.ai_executive_summary:
            ctx.ai_executive_summary = (
                f"NSAT identified a {sev} severity security issue ({fid}): {title}. "
                f"This vulnerability was detected in {file_str} and represents a concrete security exposure. "
                f"{ctx.impact} "
                f"The proposed remediation is: {change_desc}"
            )

        if not ctx.ai_root_cause_narrative:
            lines = [
                f"OBSERVED: NSAT detected '{title}' (category: {ctx.category}) in {file_str}.",
            ]
            if ctx.evidence_summary and ctx.evidence_summary != "No structured evidence available.":
                lines.append(f"Evidence: {ctx.evidence_summary}")
            if ctx.root_cause:
                lines.append(f"INFERRED: {ctx.root_cause}")
            lines.append(f"RECOMMENDED: {change_desc}")
            ctx.ai_root_cause_narrative = "\n".join(lines)

        if not ctx.ai_why_this_change:
            parts = [
                f"The original implementation is considered unsafe because: {ctx.root_cause or ctx.description}",
                f"The proposed change mitigates this by: {change_desc}",
            ]
            if ctx.reason:
                parts.append(f"Security rationale: {ctx.reason}")
            if ctx.correlated_attack_path:
                parts.append(f"This change reduces exposure along the attack path: {ctx.correlated_attack_path}")
            ctx.ai_why_this_change = "\n".join(parts)

        if not ctx.ai_final_recommendation:
            ctx.ai_final_recommendation = (
                f"Recommended Action: Review the proposed patch for {fid} before applying it. "
                f"Verification: {ctx.verification_plan or 'Run the specified tests and perform an NSAT re-scan after remediation.'} "
                f"If the patch is not applied, the {sev} severity exposure remains open."
            )

        return ctx
