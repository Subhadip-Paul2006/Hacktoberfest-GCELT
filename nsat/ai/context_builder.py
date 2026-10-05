"""Context Builder for NSAT AI Reasoning Layer with Redaction and Context Limiting."""

import json
from pathlib import Path
import re
from typing import Any, Optional

from nsat.correlation.models import Phase4SecurityModel
from nsat.normalization.models import CanonicalFinding, FindingEvidence


class AIContextBuilder:
    """
    Builds compact, redacted, token-efficient prompt contexts from Phase4SecurityModel.
    Implements intelligent context selection to avoid overflowing model limits.
    """

    @classmethod
    def redact_secrets(cls, text: str) -> str:
        """Redact API keys, tokens, passwords, and connection strings from prompt text."""
        if not text:
            return ""

        # AWS Access Key ID
        text = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA***REDACTED***", text)
        # GitHub Personal Access Token
        text = re.sub(r"ghp_[a-zA-Z0-9]{36}", "ghp_***REDACTED***", text)
        # Passwords / Tokens in assignments
        text = re.sub(
            r'(password|passwd|secret|token|api_key|auth_token|db_password)\s*[:=]\s*["\']?[^"\'\s,;}]+["\']?',
            r"\1=***REDACTED***",
            text,
            flags=re.IGNORECASE,
        )
        # Private Keys
        text = re.sub(
            r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----",
            "***REDACTED PRIVATE KEY***",
            text,
            flags=re.DOTALL,
        )
        return text

    @classmethod
    def build_report_context(cls, model: Phase4SecurityModel) -> dict[str, Any]:
        """Generate comprehensive yet compact context for full AI security report generation."""
        # Top findings (prioritize P0, P1, and high/critical)
        top_findings = []
        for f in model.findings[:15]:
            top_findings.append(cls._format_finding_summary(f))

        risk_summary = {
            "score": model.risk.overall_score,
            "level": model.risk.risk_level,
            "critical_count": model.risk.critical_findings_count,
            "high_count": model.risk.high_findings_count,
            "medium_count": model.risk.medium_findings_count,
            "low_count": model.risk.low_findings_count,
            "validated_count": model.risk.validated_findings_count,
            "priorities": model.risk.priority_distribution,
        }

        return {
            "project": model.project,
            "risk": risk_summary,
            "overall_risk": risk_summary,
            "blast_radius": {
                "tier": model.blast_radius.tier,
                "summary": model.blast_radius.summary,
                "accessible_assets": model.blast_radius.accessible_assets,
                "lateral_paths": model.blast_radius.lateral_movement_paths,
            },
            "attack_paths": [
                {
                    "id": ap.id,
                    "title": ap.title,
                    "type": ap.path_type,
                    "severity": ap.severity,
                    "confidence": ap.confidence,
                    "steps": ap.steps,
                    "impact": ap.impact,
                    "recommendation": ap.recommendation,
                }
                for ap in model.attack_paths
            ],
            "top_findings": top_findings,
            "security_surface": model.security_surface,
            "coverage_summary": {
                "languages": model.coverage.languages,
                "domains": model.coverage.security_domains,
                "files_analyzed": model.coverage.files_analyzed,
            },
            "known_limitations": model.limitations.known_blind_spots,
        }

    @classmethod
    def build_finding_context(cls, finding_id: str, model: Phase4SecurityModel) -> tuple[Optional[dict[str, Any]], dict[str, Any]]:
        """
        Build targeted context limited strictly to a single finding and its immediate neighborhood.
        Returns:
            (finding_dict, related_context_dict)
        """
        target: Optional[CanonicalFinding] = None
        for f in model.findings:
            if f.id.upper() == finding_id.upper() or finding_id.upper() in f.id.upper():
                target = f
                break

        if not target:
            return None, {}

        finding_dict = cls._format_finding_summary(target, full_evidence=True)

        # Related findings
        related_ids = set()
        for rf_str in target.related_findings:
            # Extract finding ID from e.g. "NSAT-AUTH-008 (AMPLIFIES)"
            token = rf_str.split()[0]
            related_ids.add(token)

        related_summaries = []
        for f in model.findings:
            if f.id in related_ids:
                related_summaries.append(cls._format_finding_summary(f))

        # Relevant attack paths
        relevant_paths = []
        for ap in model.attack_paths:
            if target.id in ap.involved_finding_ids:
                relevant_paths.append({
                    "id": ap.id,
                    "title": ap.title,
                    "path_type": ap.path_type,
                    "steps": ap.steps,
                    "impact": ap.impact,
                })

        context_dict = {
            "project_name": model.project.get("name", "Project"),
            "related_findings": related_summaries,
            "relevant_attack_paths": relevant_paths,
            "blast_radius_tier": model.blast_radius.tier,
        }

        return finding_dict, context_dict

    @classmethod
    def build_chat_context(cls, query: str, model: Phase4SecurityModel) -> dict[str, Any]:
        """
        Dynamically limits context based on whether query is finding-specific or project-wide.
        """
        query_upper = query.upper()

        # Check if query references a specific finding ID
        for f in model.findings:
            if f.id.upper() in query_upper:
                f_data, ctx = cls.build_finding_context(f.id, model)
                return {
                    "mode": "finding_focused",
                    "context_type": "finding_focused",
                    "target_finding": f_data,
                    "focused_finding": f_data,
                    "context": ctx,
                }

        # Check if query asks specifically about Docker / Container
        if "DOCKER" in query_upper or "CONTAINER" in query_upper or "SOCKET" in query_upper:
            docker_findings = [cls._format_finding_summary(f) for f in model.findings if "docker" in f.title.lower() or f.category == "container"]
            docker_paths = [ap.model_dump() for ap in model.attack_paths if any("docker" in step.lower() for step in ap.steps)]
            return {
                "mode": "docker_focused",
                "context_type": "docker_focused",
                "blast_radius_tier": model.blast_radius.tier,
                "docker_findings": docker_findings,
                "docker_attack_paths": docker_paths,
            }

        # Check if query asks about remediation, fixes, rollback, or changes
        if any(term in query_upper for term in ("FIX", "REMEDIAT", "PATCH", "ROLLBACK", "WHAT CHANGED", "VERIF")):
            from nsat.remediation.manager import RemediationManager
            repo_path_str = model.project.get("path") or "."
            # Also check finding asset paths if available
            if repo_path_str == "." and model.findings:
                top_asset = model.findings[0].asset or model.findings[0].file_path or ""
                if Path(top_asset).is_absolute():
                    repo_path_str = str(Path(top_asset).parents[1])

            hist = RemediationManager.load_history(Path(repo_path_str))
            if not hist and repo_path_str != ".":
                hist = RemediationManager.load_history(Path("."))

            return {
                "mode": "remediation_focused",
                "context_type": "remediation_focused",
                "remediation_history": hist,
                "project": model.project,
                "overall_score": model.risk.overall_score,
                "risk_level": model.risk.risk_level,
                "total_findings": len(model.findings),
            }

        # Default: Project-wide context summary (compact)
        top_priorities = [cls._format_finding_summary(f) for f in model.findings if f.priority in ("P0", "P1")][:6]
        return {
            "mode": "project_wide",
            "context_type": "project_wide",
            "project": model.project,
            "overall_score": model.risk.overall_score,
            "risk_level": model.risk.risk_level,
            "priorities": model.risk.priority_distribution,
            "blast_radius_tier": model.blast_radius.tier,
            "top_findings": top_priorities,
            "attack_paths": [ap.title for ap in model.attack_paths],
            "total_findings": len(model.findings),
            "validated_findings_count": model.risk.validated_findings_count,
        }

    @classmethod
    def _format_finding_summary(cls, f: CanonicalFinding, full_evidence: bool = False) -> dict[str, Any]:
        """Format a finding into a compact, redacted dictionary."""
        loc = f.primary_location or {}

        evidence_list = []
        for ev in f.evidence:
            ev_entry = {
                "type": ev.type,
                "description": cls.redact_secrets(ev.description),
            }
            if ev.snippet:
                ev_entry["snippet"] = cls.redact_secrets(ev.snippet[:200])
            evidence_list.append(ev_entry)

        return {
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "confidence": f.confidence,
            "status": f.status,
            "priority": f.priority or "P2",
            "risk_score": f.risk_score,
            "location": {
                "file": loc.get("file_path") or f.file_path or f.asset,
                "line": loc.get("line_number") or f.line_number,
                "function": loc.get("function_name") or f.function_name or "Not reliably resolved",
                "class_name": loc.get("class_name") or f.class_name or "Not reliably resolved",
                "endpoint": loc.get("endpoint") or f.endpoint,
            },
            "description": cls.redact_secrets(f.description),
            "impact": cls.redact_secrets(f.impact),
            "recommendation": f.recommendation,
            "related_findings": f.related_findings,
            "evidence": evidence_list if full_evidence else evidence_list[:2],
        }
