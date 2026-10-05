"""Finding-Level AI and Deterministic Explainer for NSAT."""

import json
import logging
from typing import Optional

from nsat.ai.context_builder import AIContextBuilder
from nsat.ai.prompts import FINDING_EXPLANATION_PROMPT, SYSTEM_PROMPT_ANALYST
from nsat.ai.provider import LLMProvider
from nsat.correlation.models import Phase4SecurityModel
from nsat.normalization.models import CanonicalFinding

logger = logging.getLogger("nsat.ai.explainer")


class FindingExplainer:
    """Explains a specific security finding with root cause analysis and contextual impact."""

    @classmethod
    def explain(
        cls,
        finding_id: str,
        model: Phase4SecurityModel,
        provider: Optional[LLMProvider] = None,
    ) -> str:
        """
        Produce a structured, evidence-grounded explanation for finding_id.
        Gracefully falls back to deterministic rule explanation if AI provider is unavailable.
        """
        # 1. Locate finding
        target: Optional[CanonicalFinding] = None
        for f in model.findings:
            if f.id.upper() == finding_id.upper() or finding_id.upper() in f.id.upper():
                target = f
                break

        if not target:
            return f"[ERROR] Finding ID '{finding_id}' not found in current audit results."

        # 2. Extract targeted context
        finding_dict, related_ctx = AIContextBuilder.build_finding_context(target.id, model)
        if not finding_dict:
            return f"[ERROR] Could not build context for finding '{finding_id}'."

        # 3. If provider is available, attempt AI reasoning
        if provider:
            try:
                loc = finding_dict.get("location", {})
                prompt = FINDING_EXPLANATION_PROMPT.format(
                    finding_json=json.dumps(finding_dict, indent=2),
                    context_json=json.dumps(related_ctx, indent=2),
                    finding_id=target.id,
                    title=target.title,
                    severity=target.severity,
                    confidence=f"{target.confidence:.2f}",
                    status=target.status,
                    priority=target.priority or "P2",
                    file_path=loc.get("file") or "Not reliably resolved",
                    line_number=loc.get("line") or "Not reliably resolved",
                    function_name=loc.get("function") or "Not reliably resolved",
                    class_name=loc.get("class_name") or "Not reliably resolved",
                    endpoint=loc.get("endpoint") or "Not reliably resolved",
                )
                ai_output = provider.generate(
                    prompt=prompt,
                    system_prompt=SYSTEM_PROMPT_ANALYST,
                    temperature=0.1,
                    max_tokens=1024,
                )
                if ai_output and len(ai_output.strip()) > 50:
                    return ai_output.strip()
            except Exception as e:
                # Controlled warning and seamless fallback
                sys_msg = "[WARN] GLM provider unavailable\n[INFO] Falling back to deterministic report\n\n"
                return sys_msg + cls._build_deterministic_explanation(target, finding_dict, related_ctx)

        # 4. Deterministic fallback explanation (100% offline & reliable)
        return cls._build_deterministic_explanation(target, finding_dict, related_ctx)

    @classmethod
    def _build_deterministic_explanation(
        cls,
        target: CanonicalFinding,
        finding_dict: dict,
        related_ctx: dict,
    ) -> str:
        """Construct deterministic explanation adhering strictly to required format."""
        loc = finding_dict.get("location", {})
        file_p = loc.get("file") or "Not reliably resolved"
        line_p = loc.get("line") or "Not reliably resolved"
        func_p = loc.get("function") or "Not reliably resolved"
        cls_p = loc.get("class_name") or "Not reliably resolved"
        ep_p = loc.get("endpoint") or "Not reliably resolved"

        # Evidence lines
        ev_lines = []
        for ev in finding_dict.get("evidence", []):
            line = f"  [{ev.get('type')}] {ev.get('description')}"
            if ev.get("snippet"):
                line += f"\n    Snippet: {ev.get('snippet')}"
            ev_lines.append(line)
        evidence_text = "\n".join(ev_lines) if ev_lines else "  Structural AST pattern match identified in source code."

        # Related findings
        rel_lines = []
        for rf in target.related_findings:
            rel_lines.append(f"  - {rf}")
        related_text = "\n".join(rel_lines) if rel_lines else "  None identified in current scan domain."

        # Attack path
        paths = related_ctx.get("relevant_attack_paths", [])
        if paths:
            path_steps = []
            for p in paths:
                path_steps.append(f"  Attack Path [{p.get('id')}]: {p.get('title')}")
                for s in p.get("steps", []):
                    path_steps.append(f"    -> {s}")
            attack_path_text = "\n".join(path_steps)
        elif target.attack_path:
            attack_path_text = "  -> " + "\n  -> ".join(target.attack_path)
        else:
            attack_path_text = "  Isolated execution sink with no multi-hop chain identified."

        # Verification direction
        if target.status == "VALIDATED":
            verify_text = (
                "Vulnerability was dynamically confirmed by Phase 3 Active Validation Swarm. "
                "Applying patch and re-running targeted scanner must eliminate the AST sink node."
            )
        else:
            verify_text = (
                "Re-scanning the target file with targeted language AST analyzer to confirm "
                "that the vulnerable sink signature is no longer present."
            )

        return (
            f"Finding: {target.id} -- {target.title}\n"
            f"Severity: {target.severity}\n"
            f"Confidence: {target.confidence:.2f}\n"
            f"Status: {target.status}\n"
            f"Priority: {target.priority or 'P2'}\n\n"
            f"Where:\n"
            f"  File: {file_p}\n"
            f"  Line: {line_p}\n"
            f"  Function: {func_p}\n"
            f"  Class: {cls_p}\n"
            f"  Endpoint: {ep_p}\n\n"
            f"What happened:\n"
            f"  {target.description}\n\n"
            f"Why it matters:\n"
            f"  {target.impact}\n\n"
            f"Evidence:\n"
            f"{evidence_text}\n\n"
            f"Related findings:\n"
            f"{related_text}\n\n"
            f"Potential attack path:\n"
            f"{attack_path_text}\n\n"
            f"Recommended direction:\n"
            f"  {target.recommendation}\n\n"
            f"What would verify the fix:\n"
            f"  {verify_text}"
        )
