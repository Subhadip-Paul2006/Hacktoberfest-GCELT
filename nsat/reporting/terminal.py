"""Terminal Reporting Engine for NSAT Phase 4A."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from nsat.correlation.models import Phase4SecurityModel
from nsat.normalization.models import CanonicalFinding

console = Console()


def print_terminal_report(model: Phase4SecurityModel) -> None:
    """Render the full 12-section NSAT Phase 4A terminal security report."""

    # Banner
    banner = (
        "[bold cyan]  _  _ ___   _ _____ \n"
        " | \\| / __| /_\\_   _|  NETWORK SECURITY AUDIT & THREAT ASSESSMENT\n"
        " | .` \\__ \\/ _ \\| |    v1.0.0 | Phase 4A Correlation & Threat Engine\n"
        " |_|\\_|___/_/ \\_\\_|  [/bold cyan]"
    )
    console.print(banner)
    console.print("[dim]-[/dim]" * 70)

    # 1. Executive Security Summary
    _print_executive_summary(model)

    # 2. Overall Risk Score
    _print_overall_risk_score(model)

    # 3. Critical & High Priority Findings
    _print_critical_high_findings(model)

    # 4. Correlated Attack Paths
    _print_correlated_attack_paths(model)

    # 5. Detailed Findings
    _print_detailed_findings(model)

    # 6. Network / Deployment Exposure
    _print_network_exposure(model)

    # 7. Authentication / Authorization
    _print_auth_section(model)

    # 8. Information Leakage / Developer Oversights
    _print_oversight_section(model)

    # 9. Post-Compromise Blast Radius
    _print_blast_radius(model)

    # 10. Dependencies / Secrets
    _print_deps_and_secrets(model)

    # 11. Coverage
    _print_coverage(model)

    # 12. Blind Spots / Limitations
    _print_limitations(model)


def _print_executive_summary(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]1. Executive Security Summary[/bold cyan]")
    risk = model.risk
    total = len(model.findings)

    summary_text = (
        f"Target audited: [bold white]{model.project.get('name', 'Project')}[/bold white] "
        f"({model.project.get('primary_type', 'Application')})\n"
        f"Total Findings: [bold]{total}[/bold] | "
        f"[bold red]CRITICAL: {risk.critical_findings_count}[/bold red] | "
        f"[bold yellow]HIGH: {risk.high_findings_count}[/bold yellow] | "
        f"[yellow]MEDIUM: {risk.medium_findings_count}[/yellow] | "
        f"[blue]LOW: {risk.low_findings_count}[/blue] | "
        f"[dim]INFO: {risk.info_findings_count}[/dim]\n"
        f"Actively Validated Findings: [bold green]{risk.validated_findings_count}[/bold green] | "
        f"Multi-Hop Attack Paths: [bold magenta]{len(model.attack_paths)}[/bold magenta] | "
        f"Post-Compromise Blast Radius: [bold]{model.blast_radius.tier}[/bold]"
    )
    console.print(Panel(summary_text, title="[bold]Security Executive Brief[/bold]", border_style="cyan"))


def _print_overall_risk_score(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]2. Overall Risk Score[/bold cyan]")
    score = model.risk.overall_score
    level = model.risk.risk_level

    color = "red" if score >= 75 else ("yellow" if score >= 50 else "green")
    content = (
        f"  [bold]Risk Score:[/] [bold {color}]{score}/100[/]  "
        f"[bold]Risk Level:[/] [bold {color}]{level}[/]\n"
        f"  [dim]Priorities:[/] [bold red]P0: {model.risk.priority_distribution.get('P0', 0)}[/]  "
        f"[bold yellow]P1: {model.risk.priority_distribution.get('P1', 0)}[/]  "
        f"[yellow]P2: {model.risk.priority_distribution.get('P2', 0)}[/]  "
        f"[dim]P3: {model.risk.priority_distribution.get('P3', 0)}[/]"
    )
    console.print(Panel(content, border_style=color))


def _print_critical_high_findings(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]3. Critical & High Priority Findings[/bold cyan]")
    important = [f for f in model.findings if f.priority in ("P0", "P1") or f.severity in ("CRITICAL", "HIGH")]

    if not important:
        console.print("[green]No Critical or High priority findings detected.[/green]")
        return

    table = Table(box=None, pad_edge=False)
    table.add_column("Priority", style="bold", width=10)
    table.add_column("ID", style="cyan", width=20)
    table.add_column("Severity", width=12)
    table.add_column("Title", style="white")
    table.add_column("Location", style="dim")
    table.add_column("Status", width=14)

    for f in important:
        sev_colored = f"[bold red]{f.severity}[/]" if f.severity == "CRITICAL" else f"[bold yellow]{f.severity}[/]"
        prio_colored = f"[bold red]{f.priority or 'P1'}[/]" if f.priority == "P0" else f"[yellow]{f.priority or 'P1'}[/]"
        loc_str = f"{f.file_path or f.asset}:{f.line_number or ''}"
        stat_colored = f"[green]{f.status}[/]" if f.status == "VALIDATED" else f"[dim]{f.status}[/]"
        table.add_row(prio_colored, f.id, sev_colored, f.title, loc_str, stat_colored)

    console.print(table)


def _print_correlated_attack_paths(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]4. Correlated Attack Paths[/bold cyan]")
    if not model.attack_paths:
        console.print("[dim]No multi-hop attack paths synthesized.[/dim]")
        return

    for ap in model.attack_paths:
        tree = Tree(f"[bold magenta]{ap.id}: {ap.title}[/bold magenta] ({ap.path_type} - [bold red]{ap.severity}[/bold red])")
        for i, step in enumerate(ap.steps, start=1):
            tree.add(f"[cyan]{i}.[/cyan] {step}")
        tree.add(f"[bold yellow]Impact:[/] {ap.impact}")
        tree.add(f"[bold green]Defense:[/] {ap.recommendation}")
        console.print(tree)
        console.print()


def _print_detailed_findings(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]5. Detailed Findings[/bold cyan]")
    for f in model.findings:
        console.print("[dim]-[/dim]" * 60)
        console.print(f"[bold white]{f.id}[/bold white]")
        console.print(f"[bold]{f.title}[/bold]")
        console.print("[dim]-[/dim]" * 60)

        sev_col = "[bold red]" if f.severity == "CRITICAL" else ("[bold yellow]" if f.severity == "HIGH" else "[yellow]")
        console.print(f"Severity:       {sev_col}{f.severity}[/]")
        console.print(f"Confidence:     {f.confidence:.2f} ({f.confidence_label})")
        console.print(f"Status:         [bold]{f.status}[/bold]")
        console.print(f"Priority:       [bold]{f.priority or 'P2'}[/bold]")
        console.print(f"Risk Score:     {f.risk_score or 0.0}/100")

        # Primary Location
        loc = f.primary_location or {}
        console.print("\n[bold]Primary Location[/bold]")
        console.print(f"  File:         {loc.get('file_path') or f.file_path or f.asset}")
        console.print(f"  Line:         {loc.get('line_number') or f.line_number or 'N/A'}")
        console.print(f"  Function:     {loc.get('function_name') or f.function_name or 'Not reliably resolved'}")
        console.print(f"  Class:        {loc.get('class_name') or f.class_name or 'Not reliably resolved'}")
        if loc.get("module"):
            console.print(f"  Module:       {loc.get('module')}")
        if loc.get("endpoint") or f.endpoint:
            console.print(f"  Endpoint:     {loc.get('endpoint') or f.endpoint}")
        if f.port:
            console.print(f"  Port:         {f.port}")

        console.print("\n[bold]Why Detected[/bold]")
        console.print(f"  {f.description}")

        console.print("\n[bold]Evidence[/bold]")
        if f.evidence:
            for ev in f.evidence:
                console.print(f"  [{ev.type}] {ev.description}")
                if ev.snippet:
                    console.print(f"    [dim]{ev.snippet.strip()}[/dim]")
        else:
            console.print("  Structural pattern match identified by AST analysis.")

        if f.related_findings:
            console.print("\n[bold]Related Findings[/bold]")
            for rel in f.related_findings:
                console.print(f"  - {rel}")

        if f.attack_path:
            console.print("\n[bold]Attack Path[/bold]")
            for p in f.attack_path:
                console.print(f"  -> {p}")

        console.print("\n[bold]Potential Impact[/bold]")
        console.print(f"  {f.impact}")

        console.print("\n[bold]Recommended Remediation[/bold]")
        console.print(f"  {f.recommendation}")

        console.print("\n[bold]Verification Status[/bold]")
        v_status = "Actively Verified by NSAT Swarm" if f.status == "VALIDATED" else "Not yet remediated (Pending surgical verification)"
        console.print(f"  {v_status}\n")


def _print_network_exposure(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]6. Network / Deployment Exposure[/bold cyan]")
    net_findings = [f for f in model.findings if f.category == "network_exposure" or f.port or f.binding_address]
    if net_findings:
        for f in net_findings:
            console.print(f"  - [bold]{f.title}[/bold] (Port: {f.port or 'N/A'}, Address: {f.binding_address or '0.0.0.0'})")
    else:
        console.print("  [dim]No wildcard listeners or exposed internal ports flagged.[/dim]")


def _print_auth_section(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]7. Authentication / Authorization[/bold cyan]")
    auth_findings = [f for f in model.findings if f.category == "authentication" or "admin" in f.title.lower() or "rate limit" in f.title.lower()]
    if auth_findings:
        for f in auth_findings:
            console.print(f"  - [{f.severity}] {f.title} ({f.file_path or f.asset}:{f.line_number or ''})")
    else:
        console.print("  [dim]No authentication or authorization vulnerabilities flagged.[/dim]")


def _print_oversight_section(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]8. Information Leakage / Developer Oversights[/bold cyan]")
    oversight_findings = [
        f for f in model.findings
        if any(w in f.title.lower() for w in ["url", "log", "stack trace", "debug", "cookie", "redirect", "price", "order"])
    ]
    if oversight_findings:
        for f in oversight_findings:
            console.print(f"  - [{f.severity}] {f.title} ({f.file_path or f.asset}:{f.line_number or ''})")
    else:
        console.print("  [dim]No hidden developer loopholes or information leaks detected.[/dim]")


def _print_blast_radius(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]9. Post-Compromise Blast Radius[/bold cyan]")
    br = model.blast_radius
    console.print(f"  Blast Radius Tier: [bold red]{br.tier}[/bold red]")
    console.print(f"  Privilege Level:   {br.privilege_level}")
    console.print(f"  Summary:           {br.summary}")
    if br.accessible_assets:
        console.print("  Accessible Assets Post-Compromise:")
        for a in br.accessible_assets:
            console.print(f"    * {a}")
    if br.lateral_movement_paths:
        console.print("  Lateral Movement Vector:")
        for lp in br.lateral_movement_paths:
            console.print(f"    -> {lp}")


def _print_deps_and_secrets(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]10. Dependencies / Secrets[/bold cyan]")
    sec_findings = [f for f in model.findings if f.category in ("secret", "dependency")]
    if sec_findings:
        for f in sec_findings:
            console.print(f"  - [{f.severity}] {f.title} in {f.asset} (Redacted)")
    else:
        console.print("  [dim]No vulnerable dependencies or exposed secret tokens found.[/dim]")


def _print_coverage(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]11. Coverage[/bold cyan]")
    cov = model.coverage
    console.print(f"  Languages Analyzed: {', '.join(cov.languages)}")
    console.print(f"  Security Domains:   {len(cov.security_domains)} domains evaluated")
    for d in cov.security_domains:
        console.print(f"    * {d}")
    console.print(f"  Total Files Analyzed: {cov.files_analyzed} ({cov.lines_of_code} LOC)")


def _print_limitations(model: Phase4SecurityModel) -> None:
    console.print("\n[bold cyan]12. Blind Spots / Limitations[/bold cyan]")
    lim = model.limitations
    console.print("  Known Blind Spots:")
    for bs in lim.known_blind_spots:
        console.print(f"    - {bs}")

    console.print("\n  Scope Restrictions & Defensive Policy:")
    for sr in lim.scope_restrictions:
        console.print(f"    - {sr}")

    console.print("\n  Deferred Capabilities:")
    for df in lim.deferred_features:
        console.print(f"    - {df}")
