"""Markdown Report Exporter for NSAT Phase 4A."""

from nsat.correlation.models import Phase4SecurityModel


def export_markdown_report(model: Phase4SecurityModel) -> str:
    """Generate detailed developer-readable Markdown security audit report."""
    md: list[str] = []

    proj_name = model.project.get("name", "Project")
    proj_type = model.project.get("primary_type", "Application")
    risk = model.risk
    br = model.blast_radius

    # Title
    md.append(f"# NSAT Security Audit & Threat Assessment Report")
    md.append(f"**Target Project:** `{proj_name}` | **Archetype:** {proj_type} | **Timestamp:** {model.timestamp}\n")
    md.append("---\n")

    # 1. Executive Security Summary
    md.append("## 1. Executive Security Summary\n")
    md.append(f"- **Total Security Findings:** {len(model.findings)}")
    md.append(f"- **Critical Findings:** {risk.critical_findings_count}")
    md.append(f"- **High Severity Findings:** {risk.high_findings_count}")
    md.append(f"- **Medium Severity Findings:** {risk.medium_findings_count}")
    md.append(f"- **Low / Informational:** {risk.low_findings_count + risk.info_findings_count}")
    md.append(f"- **Actively Validated Flaws:** {risk.validated_findings_count}")
    md.append(f"- **Synthesized Attack Paths:** {len(model.attack_paths)}")
    md.append(f"- **Post-Compromise Blast Radius:** `{br.tier}`\n")

    # 2. Overall Risk Score
    md.append("## 2. Overall Risk Score\n")
    md.append(f"| Metric | Value |")
    md.append(f"| :--- | :--- |")
    md.append(f"| **Overall Risk Score** | **{risk.overall_score} / 100** |")
    md.append(f"| **Threat Posture Level** | **{risk.risk_level}** |")
    md.append(f"| **P0 (Immediate Remediation)** | {risk.priority_distribution.get('P0', 0)} |")
    md.append(f"| **P1 (High Priority)** | {risk.priority_distribution.get('P1', 0)} |")
    md.append(f"| **P2 (Medium Priority)** | {risk.priority_distribution.get('P2', 0)} |")
    md.append(f"| **P3 (Low / Hygiene)** | {risk.priority_distribution.get('P3', 0)} |\n")

    # 3. Critical & High Priority Findings
    md.append("## 3. Critical & High Priority Findings\n")
    important = [f for f in model.findings if f.priority in ("P0", "P1") or f.severity in ("CRITICAL", "HIGH")]
    if important:
        md.append("| Priority | ID | Severity | Title | Asset / Location | Status |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in important:
            loc = f"{f.file_path or f.asset}:{f.line_number or ''}"
            md.append(f"| **{f.priority or 'P1'}** | `{f.id}` | `{f.severity}` | {f.title} | `{loc}` | {f.status} |")
        md.append("")
    else:
        md.append("_No Critical or High priority findings detected._\n")

    # 4. Correlated Attack Paths
    md.append("## 4. Correlated Attack Paths\n")
    if model.attack_paths:
        for ap in model.attack_paths:
            md.append(f"### {ap.id}: {ap.title}")
            md.append(f"**Path Type:** {ap.path_type} | **Severity:** `{ap.severity}` | **Confidence:** {ap.confidence:.2f}\n")
            md.append("```text")
            for i, step in enumerate(ap.steps, start=1):
                md.append(f"[{i}] {step}")
            md.append("```")
            md.append(f"**Impact:** {ap.impact}\n")
            md.append(f"**Defensive Recommendation:** {ap.recommendation}\n")
    else:
        md.append("_No multi-hop attack paths synthesized._\n")

    # 5. Detailed Findings
    md.append("## 5. Detailed Security Findings\n")
    for f in model.findings:
        md.append(f"### {f.id} — {f.title}\n")
        md.append(f"- **Severity:** `{f.severity}`")
        md.append(f"- **Confidence:** {f.confidence:.2f} ({f.confidence_label})")
        md.append(f"- **Lifecycle Status:** `{f.status}`")
        md.append(f"- **Remediation Priority:** `{f.priority or 'P2'}` (Risk Score: {f.risk_score or 0.0}/100)")
        
        loc = f.primary_location or {}
        md.append(f"\n#### Primary Location")
        md.append(f"- **File:** `{loc.get('file_path') or f.file_path or f.asset}`")
        md.append(f"- **Line:** `{loc.get('line_number') or f.line_number or 'N/A'}`")
        md.append(f"- **Function:** `{loc.get('function_name') or f.function_name or 'Not reliably resolved'}`")
        md.append(f"- **Class:** `{loc.get('class_name') or f.class_name or 'Not reliably resolved'}`")
        if loc.get("endpoint") or f.endpoint:
            md.append(f"- **Endpoint:** `{loc.get('endpoint') or f.endpoint}`")

        md.append(f"\n#### Why Detected")
        md.append(f"{f.description}\n")

        md.append("#### Evidence")
        if f.evidence:
            for ev in f.evidence:
                md.append(f"- **[{ev.type}]** {ev.description}")
                if ev.snippet:
                    md.append(f"  ```\n  {ev.snippet.strip()}\n  ```")
        else:
            md.append("- Structural pattern match identified by AST analysis.")

        if f.related_findings:
            md.append("\n#### Related Findings")
            for rf in f.related_findings:
                md.append(f"- `{rf}`")

        if f.attack_path:
            md.append("\n#### Attack Path")
            for p in f.attack_path:
                md.append(f"- {p}")

        md.append(f"\n#### Potential Impact")
        md.append(f"{f.impact}\n")

        md.append(f"#### Recommended Remediation")
        md.append(f"{f.recommendation}\n")

        v_text = "Actively Verified by NSAT Swarm" if f.status == "VALIDATED" else "Not yet remediated"
        md.append(f"**Verification:** {v_text}\n")
        md.append("---\n")

    # 6. Network / Deployment Exposure
    md.append("## 6. Network / Deployment Exposure\n")
    net_findings = [f for f in model.findings if f.category == "network_exposure" or f.port]
    if net_findings:
        for f in net_findings:
            md.append(f"- **{f.title}**: Port `{f.port or 'N/A'}` bound to `{f.binding_address or '0.0.0.0'}`")
    else:
        md.append("_No public network listeners flagged._")
    md.append("")

    # 7. Authentication / Authorization
    md.append("## 7. Authentication / Authorization\n")
    auth_findings = [f for f in model.findings if f.category == "authentication" or "admin" in f.title.lower() or "rate limit" in f.title.lower()]
    if auth_findings:
        for f in auth_findings:
            md.append(f"- **[{f.severity}]** {f.title} (`{f.file_path or f.asset}:{f.line_number or ''}`)")
    else:
        md.append("_No authentication/authorization vulnerabilities flagged._")
    md.append("")

    # 8. Information Leakage / Developer Oversights
    md.append("## 8. Information Leakage / Developer Oversights\n")
    oversight_findings = [
        f for f in model.findings
        if any(w in f.title.lower() for w in ["url", "log", "stack trace", "debug", "cookie", "redirect", "price", "order"])
    ]
    if oversight_findings:
        for f in oversight_findings:
            md.append(f"- **[{f.severity}]** {f.title} (`{f.file_path or f.asset}:{f.line_number or ''}`)")
    else:
        md.append("_No hidden developer loopholes or information leaks detected._")
    md.append("")

    # 9. Post-Compromise Blast Radius
    md.append("## 9. Post-Compromise Blast Radius\n")
    md.append(f"- **Blast Radius Tier:** `{br.tier}`")
    md.append(f"- **Assumed Privilege Level:** `{br.privilege_level}`")
    md.append(f"- **Impact Summary:** {br.summary}\n")
    if br.accessible_assets:
        md.append("### Accessible Assets Post-Compromise:")
        for a in br.accessible_assets:
            md.append(f"- {a}")
        md.append("")
    if br.lateral_movement_paths:
        md.append("### Lateral Movement Paths:")
        for lp in br.lateral_movement_paths:
            md.append(f"- `{lp}`")
        md.append("")

    # 10. Dependencies / Secrets
    md.append("## 10. Dependencies & Secrets\n")
    sec_findings = [f for f in model.findings if f.category in ("secret", "dependency")]
    if sec_findings:
        for f in sec_findings:
            md.append(f"- **[{f.severity}]** {f.title} in `{f.asset}`")
    else:
        md.append("_No vulnerable dependencies or exposed secrets detected._")
    md.append("")

    # 11. Coverage
    md.append("## 11. Coverage\n")
    cov = model.coverage
    md.append(f"- **Languages Analyzed:** {', '.join(cov.languages)}")
    md.append(f"- **Files Analyzed:** {cov.files_analyzed} ({cov.lines_of_code} LOC)")
    md.append("### Evaluated Security Domains:")
    for d in cov.security_domains:
        md.append(f"- {d}")
    md.append("")

    # 12. Blind Spots / Limitations
    md.append("## 12. Blind Spots & Limitations\n")
    lim = model.limitations
    md.append("### Known Blind Spots:")
    for bs in lim.known_blind_spots:
        md.append(f"- {bs}")
    md.append("\n### Scope Restrictions:")
    for sr in lim.scope_restrictions:
        md.append(f"- {sr}")
    md.append("\n### Deferred Capabilities:")
    for df in lim.deferred_features:
        md.append(f"- {df}")
    md.append("")

    return "\n".join(md)
