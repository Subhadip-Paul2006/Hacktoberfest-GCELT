"""Terminal user interface and Rich layout renderers for NSAT."""

import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from nsat.core.capability import ToolStatus
from nsat.core.models import ProjectIntelligence

# Use standard safe output console
console = Console()


def print_banner():
    """Render high-impact NSAT ASCII header."""
    banner = (
        "+------------------------------------------------------------------+\n"
        "|       NSAT -- NETWORK SECURITY AUDIT & THREAT ASSESSMENT         |\n"
        "|        Defensive Multi-Layer Security Platform -- v0.1.0         |\n"
        "+------------------------------------------------------------------+"
    )
    console.print(f"[bold cyan]{banner}[/bold cyan]")


def print_doctor(core_tools: list[ToolStatus], external_tools: list[ToolStatus]):
    """Render doctor capability assessment."""
    console.print("\n[bold cyan]NSAT Doctor -- System Capability Registry[/bold cyan]\n")

    # Core Environment & Language Analyzers Table
    core_table = Table(title="Core Environment & Language Analyzers", show_header=True, header_style="bold magenta")
    core_table.add_column("Component", style="bold white", width=32)
    core_table.add_column("Status", width=16)
    core_table.add_column("Details", style="dim")

    for tool in core_tools:
        status_str = "[bold green][OK] AVAILABLE[/bold green]" if tool.is_available else "[bold red][X] MISSING[/bold red]"
        core_table.add_row(tool.name, status_str, tool.version or "")
    console.print(core_table)
    console.print()

    # Optional External Tools Table
    ext_table = Table(title="Optional External Tools (Graceful Fallbacks)", show_header=True, header_style="bold magenta")
    ext_table.add_column("Scanner / Engine", style="bold white", width=22)
    ext_table.add_column("Status", width=18)
    ext_table.add_column("Fallback / Detail", style="dim")

    for tool in external_tools:
        if tool.is_available:
            status_str = "[bold green][OK] AVAILABLE[/bold green]"
            detail = tool.version or "Active"
        else:
            status_str = "[bold yellow]NOT FOUND[/bold yellow]"
            detail = tool.fallback_message

        ext_table.add_row(tool.name, status_str, detail)
    console.print(ext_table)
    console.print("\n[dim]Note: External tools enhance NSAT but are optional. NSAT native checks remain 100% operational.[/dim]\n")


def print_audit_phase1(intel: ProjectIntelligence):
    """Render Phase 1 Project Intelligence results."""
    print_banner()

    console.print(f"\n[bold]Target:[/bold] [cyan]{intel.metadata.target_path}[/cyan]\n")

    # Discovery Checklist
    disc_text = Text()
    disc_text.append("[+] Repository discovered and traversed\n", style="green")
    disc_text.append("[+] Language syntax detection completed\n", style="green")
    disc_text.append("[+] Framework signature analysis completed\n", style="green")
    disc_text.append("[+] Project archetype classified based on evidence\n", style="green")
    console.print(Panel(disc_text, title="[bold]Project Discovery[/bold]", border_style="green", expand=False))

    # Languages Table
    lang_table = Table(title="Detected Languages", show_header=True, header_style="bold blue")
    lang_table.add_column("Language", style="bold white")
    lang_table.add_column("Files", justify="right")
    lang_table.add_column("Lines of Code", justify="right")
    lang_table.add_column("Percentage", justify="right")

    if intel.languages:
        for lang in intel.languages:
            lang_table.add_row(
                lang.language.capitalize(),
                str(lang.file_count),
                str(lang.line_count),
                f"{lang.percentage}%",
            )
    else:
        lang_table.add_row("[yellow]None detected[/yellow]", "0", "0", "0%")
    console.print(lang_table)
    console.print()

    # Classification & Frameworks Panel
    summary_text = Text()
    summary_text.append("Primary Archetype: ", style="bold")
    summary_text.append(f"{intel.project_type.primary_type}\n", style="bold yellow")

    if intel.project_type.secondary_types:
        summary_text.append(f"Secondary Traits:  {', '.join(intel.project_type.secondary_types)}\n")

    if intel.project_type.supporting_evidence:
        summary_text.append(f"Evidence Basis:    {'; '.join(intel.project_type.supporting_evidence)}\n")

    if intel.frameworks:
        fw_names = [f.name for f in intel.frameworks]
        summary_text.append(f"Frameworks Found:  {', '.join(fw_names)}\n", style="bold cyan")

    console.print(Panel(summary_text, title="[bold]Project Classification[/bold]", border_style="yellow"))

    # Structural Metrics Table
    struct_table = Table(title="Structural & Semantic Metrics", show_header=True, header_style="bold cyan")
    struct_table.add_column("Structural Component", style="bold white")
    struct_table.add_column("Discovered Count", justify="right", style="bold")

    routes_count = sum(1 for ep in intel.entry_points if ep.entry_type == "http_route")
    main_count = sum(1 for ep in intel.entry_points if ep.entry_type == "main")

    struct_table.add_row("Total Source Files Analyzed", str(intel.metadata.analyzable_files_count))
    struct_table.add_row("Main Entry Points", str(main_count))
    struct_table.add_row("HTTP / API Route Handlers", str(routes_count))
    struct_table.add_row("Network Listeners & Sockets", str(len(intel.network_components)))
    struct_table.add_row("Database Query / ORM Sinks", str(len(intel.database_components)))
    struct_table.add_row("Authentication Controls", str(len(intel.authentication_indicators)))
    struct_table.add_row("Security-Sensitive Operations", str(len(intel.security_relevant_operations)))
    struct_table.add_row("Manifest Dependencies", str(len(intel.dependencies)))

    console.print(struct_table)

    # Next steps message
    console.print(
        "\n[bold green]Phase 1 complete.[/bold green] "
        "[dim]Project intelligence established. Security scanners, correlation, and remediation will execute in subsequent phases.[/dim]\n"
    )


_SEVERITY_STYLE = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[bold yellow]HIGH    [/bold yellow]",
    "MEDIUM":   "[bold magenta]MEDIUM  [/bold magenta]",
    "LOW":      "[bold blue]LOW     [/bold blue]",
    "INFORMATIONAL": "[dim]INFO    [/dim]",
}

_CATEGORY_LABEL = {
    "code_sast":        "Code / SAST",
    "secret":           "Secret / Credential",
    "dependency":       "Dependency CVE",
    "network_exposure": "Network Exposure",
    "web_security":     "Web Security",
    "container":        "Container",
    "authentication":   "Auth / Rate-Limit",
    "dos_resource":     "DoS / Resource",
}


def _severity_badge(sev: str) -> str:
    return _SEVERITY_STYLE.get(sev.upper(), f"[white]{sev}[/white]")


def print_audit_phase2(findings: list, surface) -> None:
    """Render Phase 2 security findings in a structured Rich table."""
    if not findings:
        console.print("\n[bold green]Phase 2 Complete -- No security findings detected.[/bold green]\n")
        return

    # Summary counts
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        n = counts.get(sev, 0)
        if n:
            summary_parts.append(f"{_severity_badge(sev)}  {n}")

    summary_line = "   ".join(summary_parts)
    console.print(Panel(
        f"[bold white]{len(findings)} findings across all security domains[/bold white]\n\n{summary_line}",
        title="[bold red]Security Findings Summary[/bold red]",
        border_style="red",
    ))

    # Findings Table
    table = Table(
        title="Security Audit Findings",
        show_header=True,
        header_style="bold magenta",
        show_lines=True,
        expand=True,
    )
    table.add_column("ID", style="bold white", no_wrap=True, width=18)
    table.add_column("Severity", width=12)
    table.add_column("Category", width=18)
    table.add_column("Title", style="bold")
    table.add_column("Asset / File", style="dim")
    table.add_column("Line", justify="right", width=6)

    for f in findings:
        asset_display = f.asset
        if f.file_path:
            try:
                from pathlib import Path
                asset_display = Path(f.file_path).name
            except Exception:
                pass
        line_str = str(f.line_number) if f.line_number else (str(f.port) if f.port else "-")
        table.add_row(
            f.id,
            _severity_badge(f.severity),
            _CATEGORY_LABEL.get(f.category, f.category),
            f.title,
            asset_display,
            line_str,
        )

    console.print(table)

    # Critical / High detail panels
    critical_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    if critical_high:
        console.print("\n[bold red]-- Critical & High Severity Details --[/bold red]\n")
        for f in critical_high[:6]:
            ev_text = ""
            for ev in f.evidence:
                snippet = f"  Snippet: {ev.snippet}" if ev.snippet else ""
                ev_text += f"  [{ev.type}] {ev.description}{snippet}\n"

            detail_text = (
                f"[bold]Description:[/bold] {f.description}\n"
                f"[bold]Impact:[/bold]      {f.impact}\n"
                f"[bold]Fix:[/bold]         {f.recommendation}\n"
            )
            if ev_text:
                detail_text += f"[bold]Evidence:[/bold]\n{ev_text}"
            if f.file_path:
                detail_text += f"[dim]File: {f.file_path}  Line: {f.line_number or '-'}[/dim]"

            console.print(Panel(
                detail_text,
                title=f"{_severity_badge(f.severity)}  [bold white]{f.id}[/bold white] -- {f.title}",
                border_style="red" if f.severity == "CRITICAL" else "yellow",
                expand=False,
            ))

    # Surface summary
    secret_count = len(surface.data.secrets)
    binding_count = len(surface.infrastructure.bindings)
    docker_flag = "Yes" if surface.infrastructure.docker_present else "No"

    console.print(Panel(
        f"[bold]Secrets Detected:[/bold]      {secret_count}\n"
        f"[bold]Network Bindings:[/bold]      {binding_count}\n"
        f"[bold]Docker Present:[/bold]        {docker_flag}\n"
        f"[bold]Auth Endpoints:[/bold]        {len(surface.application.auth_endpoints)}\n"
        f"[bold]Execution Sinks:[/bold]       {len(surface.code.execution_sinks)}",
        title="[bold cyan]Security Surface Summary[/bold cyan]",
        border_style="cyan",
        expand=False,
    ))

    console.print(
        "\n[bold yellow]Phase 2 complete.[/bold yellow] "
        "[dim]Use `nsat validate --target <URL>` for active validation swarm. "
        "Use `nsat explain <ID>` for AI root cause analysis.[/dim]\n"
    )


def print_active_validation_swarm(result) -> None:
    """Render Phase 3 Active Validation Swarm execution and results."""
    console.print("\n[bold cyan]NSAT ACTIVE VALIDATION SWARM[/bold cyan]\n")
    console.print(f"[bold]Target:[/bold]\n  [cyan]{result.target}[/cyan]\n")

    console.print("[dim]Planning swarm...[/dim]")
    console.print("[green][+][/green] Project profile loaded")
    console.print("[green][+][/green] Endpoint inventory loaded")
    console.print("[green][+][/green] Security findings loaded\n")

    console.print("[bold]Agents selected:[/bold]\n")
    for agent_name in result.agents_selected:
        console.print(f"  [bold green][+][/bold green] {agent_name}")

    if result.agents_skipped:
        console.print("\n[bold]Agents skipped:[/bold]\n")
        for agent_name, reason in result.agents_skipped:
            console.print(f"  [dim][-][/dim] {agent_name} [dim]({reason})[/dim]")

    console.print("\n[bold]Running validation...[/bold]\n")

    # Results Table
    table = Table(
        title="Validation Results",
        show_header=True,
        header_style="bold magenta",
        expand=False,
    )
    table.add_column("Agent", style="bold white", width=30)
    table.add_column("Validation Status", width=18)
    table.add_column("Evidence Count", justify="right", width=16)

    status_styles = {
        "VALIDATED": "[bold red]FAIL (VULN)[/bold red]",
        "NOT_VALIDATED": "[bold green]PASS (SECURE)[/bold green]",
        "POTENTIAL": "[bold yellow]POTENTIAL[/bold yellow]",
        "NOT_APPLICABLE": "[dim]NOT APPLICABLE[/dim]",
        "BLOCKED": "[bold magenta]BLOCKED[/bold magenta]",
        "ERROR": "[red]ERROR[/red]",
    }

    for name, res in result.agent_results.items():
        st = res.status.value if hasattr(res.status, "value") else str(res.status)
        badge = status_styles.get(st, st)
        table.add_row(name, badge, str(len(res.evidence)))

    console.print(table)
    console.print()

    summary_text = (
        f"[bold]Evidence collected:[/bold] {len(result.all_evidence)}\n"
        f"[bold]Findings upgraded:[/bold]   {result.upgraded_count}\n"
        f"[bold]New findings:[/bold]        {result.new_findings_count}\n"
        f"[bold]Duration:[/bold]            {result.duration_seconds}s"
    )
    console.print(Panel(summary_text, title="[bold cyan]Swarm Execution Summary[/bold cyan]", border_style="cyan"))


def print_developer_oversight(oversight_result) -> None:
    """Render Phase 3.5 Developer Oversight and Information Leakage audit."""
    console.print("\n[bold cyan]NSAT DEVELOPER OVERSIGHT AUDIT[/bold cyan]\n")

    for rule_name in oversight_result.rules_evaluated:
        console.print(f"  [bold green][+][/bold green] {rule_name}")

    console.print()

    # Severity Summary
    sev_counts = oversight_result.summary.by_severity
    sev_lines = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        count = sev_counts.get(sev, 0)
        sev_lines.append(f"{_severity_badge(sev)}  {count}")

    console.print(Panel(
        "   ".join(sev_lines) if any(sev_counts.values()) else "[dim]No oversight issues identified.[/dim]",
        title="[bold yellow]Oversight Findings by Severity[/bold yellow]",
        border_style="yellow",
    ))

    # Findings Table
    if oversight_result.findings:
        table = Table(
            title="Developer Oversight & Hidden Loophole Findings",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
        )
        table.add_column("ID", style="bold white", no_wrap=True)
        table.add_column("Severity", width=10)
        table.add_column("Category", width=18)
        table.add_column("Title", style="bold", ratio=2)
        table.add_column("Asset", style="dim", ratio=1)
        table.add_column("Line", justify="right", width=6)

        for f in oversight_result.findings:
            asset_display = f.asset
            if f.file_path:
                try:
                    from pathlib import Path
                    asset_display = Path(f.file_path).name
                except Exception:
                    pass
            table.add_row(
                f.id,
                _severity_badge(f.severity),
                f.category,
                f.title,
                asset_display,
                str(f.line_number) if f.line_number else "-",
            )

        console.print(table)
        console.print()


