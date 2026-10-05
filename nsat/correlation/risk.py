"""Deterministic Contextual Risk Engine and Remediation Priority Classifier for NSAT."""

from typing import Optional

from nsat.core.surface import SecuritySurface
from nsat.correlation.models import AttackPath, BlastRadiusReport, RiskAssessment
from nsat.normalization.models import CanonicalFinding


class RiskEngine:
    """
    Deterministic risk-scoring and priority classification system.
    Evaluates findings based on structural severity, confidence, active validation status,
    blast-radius tier, exposure, and cross-domain correlation without LLM dependency.
    """

    BASE_SEVERITY_SCORES = {
        "CRITICAL": 50.0,
        "HIGH": 35.0,
        "MEDIUM": 20.0,
        "LOW": 10.0,
        "INFORMATIONAL": 3.0,
    }

    @classmethod
    def evaluate(
        cls,
        findings: list[CanonicalFinding],
        blast_radius: BlastRadiusReport,
        attack_paths: list[AttackPath],
        surface: Optional[SecuritySurface] = None,
    ) -> tuple[list[CanonicalFinding], RiskAssessment]:
        """
        Compute per-finding risk score and priority, then synthesize system-wide risk.
        Returns:
            (scored_findings, overall_risk_assessment)
        """
        priority_dist = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        validated_count = 0

        # Set of finding IDs in multi-hop attack paths
        path_finding_ids = set()
        for ap in attack_paths:
            path_finding_ids.update(ap.involved_finding_ids)

        has_wildcard_binding = False
        if surface and surface.infrastructure:
            has_wildcard_binding = any(
                b.exposure in ("PUBLIC_WILDCARD", "POTENTIALLY_LAN_REACHABLE")
                for b in surface.infrastructure.bindings
            )

        scored_findings: list[CanonicalFinding] = []

        for f in findings:
            # 1. Base Severity Score
            base_score = cls.BASE_SEVERITY_SCORES.get(f.severity.upper(), 10.0)

            # 2. Confidence scaling
            conf_factor = max(0.5, f.confidence)
            item_score = base_score * conf_factor

            # 3. Active Validation Bonus
            if f.status in ("VALIDATED", "CONFIRMED_BY_SAFE_CHECK"):
                item_score += 15.0
                validated_count += 1
            elif f.status == "POTENTIAL":
                item_score += 5.0

            # 4. Correlation / Attack Path Amplification
            if f.id in path_finding_ids:
                item_score += 10.0
            if f.related_findings:
                item_score += 5.0

            # 5. Blast Radius Amplification
            if blast_radius.tier_level == 3:
                # Docker socket or root escalation context
                if "docker" in f.title.lower() or "command" in f.title.lower() or f.category == "container":
                    item_score += 15.0
                else:
                    item_score += 5.0
            elif blast_radius.tier_level == 2:
                # Database / API key context
                if "sql" in f.title.lower() or f.category == "secret":
                    item_score += 10.0
                else:
                    item_score += 3.0

            # 6. Network Exposure Amplification
            if has_wildcard_binding and f.category in ("network_exposure", "authentication", "code_sast"):
                item_score += 8.0

            final_finding_score = min(100.0, round(item_score, 1))
            f.risk_score = final_finding_score

            # 7. Priority Assignment: P0, P1, P2, P3
            if final_finding_score >= 75.0 or (f.severity == "CRITICAL" and (f.status == "VALIDATED" or blast_radius.tier_level == 3)):
                prio = "P0"
            elif final_finding_score >= 50.0 or f.severity in ("CRITICAL", "HIGH"):
                prio = "P1"
            elif final_finding_score >= 30.0 or f.severity == "MEDIUM":
                prio = "P2"
            else:
                prio = "P3"

            f.priority = prio
            priority_dist[prio] = priority_dist.get(prio, 0) + 1
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            scored_findings.append(f)

        # 8. Calculate System-Wide Overall Risk Score (0 - 100)
        if not scored_findings:
            overall_score = 0
            risk_level = "LOW"
        else:
            sorted_scores = sorted([f.risk_score or 0.0 for f in scored_findings], reverse=True)
            top1 = sorted_scores[0]
            top2 = sorted_scores[1] if len(sorted_scores) > 1 else 0.0
            top3 = sorted_scores[2] if len(sorted_scores) > 2 else 0.0
            rem_sum = sum(sorted_scores[3:]) if len(sorted_scores) > 3 else 0.0

            # Weighted aggregate: Dominant flaw drives the score
            raw_aggregate = top1 + (0.35 * top2) + (0.15 * top3) + (0.05 * rem_sum)
            overall_score = min(100, max(0, int(round(raw_aggregate))))

            if overall_score >= 80:
                risk_level = "CRITICAL"
            elif overall_score >= 60:
                risk_level = "HIGH"
            elif overall_score >= 40:
                risk_level = "MEDIUM"
            elif overall_score >= 20:
                risk_level = "LOW"
            else:
                risk_level = "INFO"

        assessment = RiskAssessment(
            overall_score=overall_score,
            risk_level=risk_level,
            priority_distribution=priority_dist,
            critical_findings_count=sev_counts.get("CRITICAL", 0),
            high_findings_count=sev_counts.get("HIGH", 0),
            medium_findings_count=sev_counts.get("MEDIUM", 0),
            low_findings_count=sev_counts.get("LOW", 0),
            info_findings_count=sev_counts.get("INFORMATIONAL", 0),
            validated_findings_count=validated_count,
            calculation_factors={
                "top_finding_score": sorted_scores[0] if scored_findings else 0,
                "blast_radius_tier": blast_radius.tier,
                "attack_paths_count": len(attack_paths),
                "wildcard_exposure": has_wildcard_binding,
            },
        )

        return scored_findings, assessment
