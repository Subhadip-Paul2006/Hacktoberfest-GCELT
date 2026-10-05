"""Developer Oversight Engine for NSAT Phase 3.5."""

from pathlib import Path
from typing import Any, Optional

from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.oversight.models import OversightResult, OversightSummary
from nsat.oversight.rules.client_trust import ClientTrustRule
from nsat.oversight.rules.config_deployment import ConfigDeploymentRule
from nsat.oversight.rules.error_exposure import ErrorExposureRule
from nsat.oversight.rules.hidden_endpoints import HiddenEndpointsRule
from nsat.oversight.rules.log_leakage import LogLeakageRule
from nsat.oversight.rules.race_condition import RaceConditionRule
from nsat.oversight.rules.session_cookie import SessionCookieRule
from nsat.oversight.rules.url_leakage import URLLeakageRule


class DeveloperOversightEngine:
    """
    Contextual audit engine targeting developer oversights, information leakage,
    insecure URL designs, trusted headers, and hidden loopholes.
    """

    def __init__(self):
        self.rules = [
            ("URL / Information Leakage", URLLeakageRule()),
            ("Log Leakage", LogLeakageRule()),
            ("Error / Stack Trace Exposure", ErrorExposureRule()),
            ("Hidden / Developer Endpoints", HiddenEndpointsRule()),
            ("Client Trust & Authorization", ClientTrustRule()),
            ("Session & Cookie Security", SessionCookieRule()),
            ("Configuration & Deployment", ConfigDeploymentRule()),
            ("Race Condition / TOCTOU", RaceConditionRule()),
        ]

    def run(
        self,
        repo_path: Path,
        intel: ProjectIntelligence,
        surface: SecuritySurface,
        existing_findings: list[CanonicalFinding],
    ) -> OversightResult:
        """
        Execute all developer oversight rules, deduplicating and enriching existing findings.
        """
        raw_findings: list[CanonicalFinding] = []
        rules_evaluated: list[str] = []

        # 1. Run all rules
        for rule_name, rule_instance in self.rules:
            rules_evaluated.append(rule_name)
            try:
                found = rule_instance.audit(
                    repo_path=repo_path,
                    intel=intel,
                    surface=surface,
                    existing_findings=existing_findings,
                )
                raw_findings.extend(found)
            except Exception as e:
                # Isolate rule errors — never crash audit!
                pass

        # 2. Deduplicate across rules by signature hash
        unique_findings: list[CanonicalFinding] = []
        seen_hashes = set()
        for f in raw_findings:
            h = f.signature_hash or f.compute_signature_hash()
            if h not in seen_hashes:
                seen_hashes.add(h)
                unique_findings.append(f)

        # 3. Deduplicate / Enrich with Phase 2 & Phase 3 findings
        enriched_list: list[CanonicalFinding] = []
        final_oversight_findings: list[CanonicalFinding] = []

        existing_by_asset_and_line = {
            (f.file_path, f.line_number): f for f in existing_findings if f.file_path and f.line_number
        }
        existing_by_endpoint = {
            f.endpoint: f for f in existing_findings if f.endpoint
        }

        for of in unique_findings:
            key = (of.file_path, of.line_number)
            if key in existing_by_asset_and_line:
                # Enrich existing finding with oversight context
                parent = existing_by_asset_and_line[key]
                parent.related_findings.append(of.id)
                parent.evidence.extend(of.evidence)
                of.related_findings.append(parent.id)
                enriched_list.append(parent)
                final_oversight_findings.append(of)
            elif of.endpoint and of.endpoint in existing_by_endpoint:
                parent = existing_by_endpoint[of.endpoint]
                parent.related_findings.append(of.id)
                of.related_findings.append(parent.id)
                enriched_list.append(parent)
                final_oversight_findings.append(of)
            else:
                final_oversight_findings.append(of)

        # 4. Compute Summary
        summary = OversightSummary(
            total_findings=len(final_oversight_findings),
            by_category={},
            by_severity={},
            enriched_findings_count=len(enriched_list),
            new_findings_count=len(final_oversight_findings),
        )

        for f in final_oversight_findings:
            summary.by_category[f.category] = summary.by_category.get(f.category, 0) + 1
            summary.by_severity[f.severity] = summary.by_severity.get(f.severity, 0) + 1

        # 5. Build Phase 4 handoff object
        correlation_handoff = {
            "target_path": str(repo_path),
            "oversight_findings_count": len(final_oversight_findings),
            "categories": summary.by_category,
            "severities": summary.by_severity,
            "rules_evaluated": rules_evaluated,
            "enriched_finding_ids": [f.id for f in enriched_list],
            "finding_ids": [f.id for f in final_oversight_findings],
        }

        return OversightResult(
            target_path=str(repo_path),
            rules_evaluated=rules_evaluated,
            findings=final_oversight_findings,
            enriched_findings=enriched_list,
            summary=summary,
            correlation_handoff=correlation_handoff,
        )
