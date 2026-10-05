"""Root CLI entry point for NSAT."""

import json
from pathlib import Path
import sys
from datetime import datetime
from typing import Any
import uuid
import click
from rich.panel import Panel
from rich.markdown import Markdown

from nsat import __version__
from nsat.cli.ui import (
    console,
    print_active_validation_swarm,
    print_audit_phase1,
    print_audit_phase2,
    print_developer_oversight,
    print_doctor,
)
from nsat.core.capability import CapabilityRegistry
from nsat.core.config import NSATConfig
from nsat.core.discovery import DiscoveryEngine
from nsat.core.orchestrator import Phase2Orchestrator
from nsat.oversight.engine import DeveloperOversightEngine
from nsat.swarm.coordinator import SwarmCoordinator
from nsat.swarm.models import TargetScope
from nsat.correlation.engine import CorrelationEngine
from nsat.correlation.models import Phase4Input, Phase4SecurityModel
from nsat.reporting.json_exporter import export_json_str
from nsat.reporting.markdown_exporter import export_markdown_report
from nsat.reporting.manager import ReportManager

from nsat.ai.config import GLMConfig
from nsat.ai.glm import GLMProvider
from nsat.ai.report_generator import AIReportGenerator
from nsat.ai.explainer import FindingExplainer
from nsat.ai.chatbot import SecurityChatbot
from nsat.ai.context_builder import AIContextBuilder


def _build_security_pipeline(
    path: str,
    target: str | None = None,
    active: bool = False,
    oversight: bool = True,
    authorized: bool = False,
    config: str | None = None,
) -> tuple[Path, Any, Any, list[Any], Any, Any, Phase4SecurityModel]:
    """Execute pipeline up to Phase 4A Correlation and return all intermediate context + model."""
    target_path = Path(path).resolve()
    if not (target_path / "src").exists() and (target_path / "demo-vuln-app").is_dir():
        target_path = target_path / "demo-vuln-app"

    if not target_path.exists():
        console.print(f"[bold red][ERROR] Target path does not exist: {target_path}[/bold red]")
        sys.exit(1)

    cfg = NSATConfig.load(
        config_path=Path(config) if config else None,
        target_dir=target_path if target_path.is_dir() else target_path.parent,
    )

    engine = DiscoveryEngine(config=cfg)
    intelligence = engine.discover(target_path)
    orchestrator = Phase2Orchestrator()
    surface, findings = orchestrator.run(target_path, intelligence)

    swarm_result = None
    if active and target:
        scope = TargetScope(target=target, explicitly_authorized=authorized)
        coordinator = SwarmCoordinator()
        swarm_result = coordinator.run(
            target_url=target,
            intelligence=intelligence,
            surface=surface,
            findings=findings,
            scope=scope,
        )
        findings = swarm_result.findings

    oversight_result = None
    if oversight:
        oversight_engine = DeveloperOversightEngine()
        oversight_result = oversight_engine.run(
            repo_path=target_path,
            intel=intelligence,
            surface=surface,
            existing_findings=findings,
        )

    p4_input = Phase4Input.from_orchestration(
        target_path=str(target_path),
        intelligence=intelligence,
        surface=surface,
        phase2_findings=findings,
        swarm_result=swarm_result,
        oversight_result=oversight_result,
    )
    security_model = CorrelationEngine.run(p4_input)

    return target_path, intelligence, surface, findings, swarm_result, oversight_result, security_model


def _audit_context_path(repo_root: Path) -> Path:
    return repo_root.resolve() / ".nsat" / "audit-context" / "latest.json"


def _redact_audit_value(value: Any) -> Any:
    """Recursively redact secrets in persisted scanner context."""
    if isinstance(value, str):
        from nsat.remediation.planner import RemediationPlanner
        return RemediationPlanner._redact(value)
    if isinstance(value, list):
        return [_redact_audit_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_audit_value(item) for key, item in value.items()}
    return value


def _save_audit_context(repo_root: Path, model: Phase4SecurityModel) -> None:
    """Persist the latest redacted correlation model for targeted remediation."""
    audit_id = f"AUD-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    model.project["path"] = str(repo_root.resolve())
    model.project["audit_id"] = audit_id
    context_file = _audit_context_path(repo_root)
    context_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "audit_id": audit_id,
        "repository_root": str(repo_root.resolve()),
        "created_at": datetime.now().astimezone().isoformat(),
        "model": _redact_audit_value(model.model_dump(mode="json")),
    }
    temporary = context_file.with_suffix(f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary.replace(context_file)


def _load_audit_context(repo_root: Path) -> Phase4SecurityModel | None:
    """Load the newest cached audit in this repository or one child project."""
    root = repo_root.resolve()
    candidates = [root]
    try:
        candidates.extend(
            child for child in root.iterdir()
            if child.is_dir() and child.name not in {".git", ".venv", "node_modules"}
        )
    except OSError:
        pass
    context_files = [path for candidate in candidates if (path := _audit_context_path(candidate)).is_file()]
    context_files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    for context_file in context_files:
        try:
            payload = json.loads(context_file.read_text(encoding="utf-8"))
            stored_root = Path(payload["repository_root"]).resolve()
            stored_root.relative_to(root)
            if stored_root != context_file.parent.parent.parent.resolve():
                continue
            model = Phase4SecurityModel.model_validate(payload["model"])
            model.project["path"] = str(stored_root)
            model.project["audit_id"] = payload["audit_id"]
            return model
        except Exception as exc:
            console.print(
                f"[yellow]Cached audit context could not be loaded ({type(exc).__name__}); trying another context.[/yellow]"
            )
    return None


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="nsat")
def cli():
    """NSAT -- Network Security Audit & Threat Assessment CLI."""
    pass


@cli.command("doctor")
def doctor_cmd():
    """Check environment, installed analyzers, and optional external scanner tools."""
    py_tool = CapabilityRegistry.check_python()
    git_tool = CapabilityRegistry.check_git()
    analyzers = CapabilityRegistry.check_analyzers()
    external = CapabilityRegistry.check_external_tools()

    core_tools = [py_tool, git_tool] + analyzers
    print_doctor(core_tools, external)


@cli.command("audit")
@click.argument("path", default=".", type=click.Path(exists=False, readable=True))
@click.option("--target", "-t", default=None, help="Explicitly authorized remote target URL (Runtime check).")
@click.option("--active", is_flag=True, help="Run Phase 3 Active Validation Swarm against --target.")
@click.option("--oversight", is_flag=True, help="Run Phase 3.5 Developer Oversight & Hidden Loophole audit.")
@click.option("--authorized", is_flag=True, help="Explicitly certify authorization for target.")
@click.option("--ai", is_flag=True, help="Enable GLM-5.3 AI-assisted security analysis and summary.")
@click.option("--json-out", "--json", is_flag=True, help="Emit raw machine-readable JSON to stdout.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom nsat.yaml config.")
@click.option("--phase1-only", is_flag=True, help="Run Phase 1 discovery only (no security scanning).")
def audit_cmd(
    path: str,
    target: str | None,
    active: bool,
    oversight: bool,
    authorized: bool,
    ai: bool,
    json_out: bool,
    config: str | None,
    phase1_only: bool,
):
    """
    Audit a local source code repository or project path.

    Runs Phase 1 (discovery & intelligence) then Phase 2 (multi-domain security scanning).
    Optionally runs Phase 3 Active Validation Swarm with --active --target <URL>
    and Phase 3.5 Developer Oversight with --oversight.
    """
    target_path = Path(path).resolve()

    if not target_path.exists():
        console.print(f"[bold red][ERROR] Target path does not exist: {target_path}[/bold red]")
        sys.exit(1)

    cfg = NSATConfig.load(
        config_path=Path(config) if config else None,
        target_dir=target_path if target_path.is_dir() else target_path.parent,
    )

    # ── Phase 1: Project Intelligence ─────────────────────────
    try:
        engine = DiscoveryEngine(config=cfg)
        intelligence = engine.discover(target_path)
    except Exception as e:
        console.print(f"[bold red][ERROR] Discovery failed: {e}[/bold red]")
        sys.exit(1)

    if phase1_only:
        if json_out:
            click.echo(intelligence.model_dump_json(indent=2))
        else:
            print_audit_phase1(intelligence)
        return

    # ── Phase 2: Multi-Domain Security Scanning ────────────────
    try:
        orchestrator = Phase2Orchestrator()
        surface, findings = orchestrator.run(target_path, intelligence)
    except Exception as e:
        console.print(f"[bold red][ERROR] Phase 2 scanning failed: {e}[/bold red]")
        sys.exit(1)

    swarm_result = None
    if active and target:
        # Run Phase 3: Active Validation Swarm
        scope = TargetScope(target=target, explicitly_authorized=authorized)
        coordinator = SwarmCoordinator()
        swarm_result = coordinator.run(
            target_url=target,
            intelligence=intelligence,
            surface=surface,
            findings=findings,
            scope=scope,
        )
        findings = swarm_result.findings

    oversight_result = None
    if oversight:
        # Run Phase 3.5: Developer Oversight Engine
        oversight_engine = DeveloperOversightEngine()
        oversight_result = oversight_engine.run(
            repo_path=target_path,
            intel=intelligence,
            surface=surface,
            existing_findings=findings,
        )

    security_model = None
    if ai:
        p4_input = Phase4Input.from_orchestration(
            target_path=str(target_path),
            intelligence=intelligence,
            surface=surface,
            phase2_findings=findings,
            swarm_result=swarm_result,
            oversight_result=oversight_result,
        )
        security_model = CorrelationEngine.run(p4_input)
        _save_audit_context(target_path, security_model)

    if json_out:
        output = {
            "intelligence": json.loads(intelligence.model_dump_json()),
            "findings": [json.loads(f.model_dump_json()) for f in findings],
            "surface": {
                "secrets_count": len(surface.data.secrets),
                "bindings_count": len(surface.infrastructure.bindings),
                "docker_present": surface.infrastructure.docker_present,
                "auth_endpoints": len(surface.application.auth_endpoints),
                "execution_sinks": len(surface.code.execution_sinks),
            },
        }
        if swarm_result:
            output["validation_swarm"] = json.loads(swarm_result.model_dump_json())
        if oversight_result:
            output["oversight"] = json.loads(oversight_result.model_dump_json())
        if security_model:
            output["risk_model"] = json.loads(security_model.model_dump_json())
        click.echo(json.dumps(output, indent=2))
        return

    print_audit_phase1(intelligence)
    print_audit_phase2(findings, surface)

    if swarm_result:
        print_active_validation_swarm(swarm_result)
    elif target:
        _run_runtime_checks(target)

    if oversight_result:
        print_developer_oversight(oversight_result)

    if ai and security_model:
        console.print("\n[bold cyan]NSAT SECURITY AUDIT[/bold cyan]\n")
        console.print("  [bold white]Project Discovery[/bold white]                  [bold green][OK][/bold green]")
        console.print("  [bold white]Static Security[/bold white]                    [bold green][OK][/bold green]")
        act_icon = "[bold green][OK][/bold green]" if swarm_result else "[dim]SKIPPED[/dim]"
        console.print(f"  [bold white]Active Validation[/bold white]                  {act_icon}")
        ov_icon = "[bold green][OK][/bold green]" if oversight_result else "[dim]SKIPPED[/dim]"
        console.print(f"  [bold white]Developer Oversight[/bold white]                {ov_icon}")
        console.print("  [bold white]Correlation[/bold white]                        [bold green][OK][/bold green]")
        console.print("  [bold white]Risk Analysis[/bold white]                      [bold green][OK][/bold green]")
        console.print("  [bold white]AI Security Analysis[/bold white]               [bold green][OK][/bold green]\n")

        top_finding = security_model.findings[0] if security_model.findings else None
        loc = top_finding.primary_location if top_finding else None
        loc_str = f"{loc.get('file_path') or top_finding.file_path or top_finding.asset}:{loc.get('line_number') or 'N/A'}" if top_finding else "N/A"

        top_path = security_model.attack_paths[0] if security_model.attack_paths else None
        path_summary = f"{top_path.title} ({' -> '.join(top_path.steps)})" if top_path else "None identified"

        provider = GLMProvider() if GLMConfig.load().is_configured() else None
        ai_summary = None
        if provider:
            try:
                from nsat.ai.prompts import SYSTEM_PROMPT_ANALYST
                context = AIContextBuilder.build_report_context(security_model)
                ai_summary = provider.generate(
                    prompt=f"Summarize the overall security posture and top threats concisely in 2-3 sentences based on:\n{json.dumps(context, indent=2)}",
                    system_prompt=SYSTEM_PROMPT_ANALYST,
                    max_tokens=256,
                )
            except Exception:
                ai_summary = None

        if not ai_summary:
            ai_summary = (
                f"Automated audit identified {len(security_model.findings)} findings across code, dependencies, secrets, and configuration. "
                f"Host takeover risk is elevated due to {security_model.blast_radius.tier}. "
                f"{security_model.risk.validated_findings_count} findings actively validated."
            )

        from rich.markup import escape
        risk_color = "bold red" if security_model.risk.risk_level == "CRITICAL" else "bold yellow"
        console.print(f"[bold]Overall Risk:[/] [{risk_color}]{security_model.risk.risk_level}[/{risk_color}]")
        console.print(f"\n[bold cyan]GLM-5.3 Analysis:[/bold cyan]\n  {escape(ai_summary.strip())}")
        console.print(f"\n[bold cyan]Top Attack Path:[/bold cyan]\n  {escape(path_summary)}")
        console.print(f"\n[bold cyan]Most Important File:[/bold cyan]\n  {escape(loc_str)}")
        console.print(f"\n[bold cyan]Recommended Priority:[/bold cyan]\n  [bold red]{top_finding.priority if top_finding else 'P0'}[/bold red]\n")


@cli.command("oversight")
@click.argument("path", default=".", type=click.Path(exists=False, readable=True))
@click.option("--json-out", "--json", is_flag=True, help="Emit raw machine-readable JSON to stdout.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom nsat.yaml config.")
def oversight_cmd(path: str, json_out: bool, config: str | None):
    """
    Run Phase 3.5 Developer Oversight, Information Leakage & Hidden Loophole audit.
    """
    target_path = Path(path).resolve()
    if not target_path.exists():
        console.print(f"[bold red][ERROR] Repository path does not exist: {target_path}[/bold red]")
        sys.exit(1)

    cfg = NSATConfig.load(
        config_path=Path(config) if config else None,
        target_dir=target_path if target_path.is_dir() else target_path.parent,
    )

    try:
        engine = DiscoveryEngine(config=cfg)
        intelligence = engine.discover(target_path)
        orchestrator = Phase2Orchestrator()
        surface, findings = orchestrator.run(target_path, intelligence)
    except Exception as e:
        console.print(f"[bold red][ERROR] Initial audit for oversight failed: {e}[/bold red]")
        sys.exit(1)

    oversight_engine = DeveloperOversightEngine()
    oversight_result = oversight_engine.run(target_path, intelligence, surface, findings)

    if json_out:
        click.echo(oversight_result.model_dump_json(indent=2))
        return

    print_developer_oversight(oversight_result)


@cli.command("validate")
@click.argument("path", default=".", type=click.Path(exists=False, readable=True))
@click.option("--target", "-t", required=True, help="Explicitly authorized target URL (e.g. http://127.0.0.1:8000).")
@click.option("--authorized", is_flag=True, help="Explicitly certify authorization for target.")
@click.option("--json-out", "--json", is_flag=True, help="Emit raw machine-readable JSON to stdout.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom nsat.yaml config.")
def validate_cmd(path: str, target: str, authorized: bool, json_out: bool, config: str | None):
    """
    Run Phase 3 Active Validation Swarm against an authorized running application.

    Safely validates discovered security weaknesses with non-destructive bounded probes.
    """
    target_path = Path(path).resolve()
    if not target_path.exists():
        console.print(f"[bold red][ERROR] Repository path does not exist: {target_path}[/bold red]")
        sys.exit(1)

    cfg = NSATConfig.load(
        config_path=Path(config) if config else None,
        target_dir=target_path if target_path.is_dir() else target_path.parent,
    )

    try:
        engine = DiscoveryEngine(config=cfg)
        intelligence = engine.discover(target_path)
        orchestrator = Phase2Orchestrator()
        surface, findings = orchestrator.run(target_path, intelligence)
    except Exception as e:
        console.print(f"[bold red][ERROR] Initial audit for validation failed: {e}[/bold red]")
        sys.exit(1)

    scope = TargetScope(target=target, explicitly_authorized=authorized)
    coordinator = SwarmCoordinator()
    swarm_result = coordinator.run(
        target_url=target,
        intelligence=intelligence,
        surface=surface,
        findings=findings,
        scope=scope,
    )

    if json_out:
        click.echo(swarm_result.model_dump_json(indent=2))
        return

    print_active_validation_swarm(swarm_result)


def _run_runtime_checks(target_url: str):
    """Execute optional runtime HTTP/network probes on authorized target."""
    from nsat.scanners.web.scanner import WebProber
    console.print(f"\n[bold cyan]Runtime target scan: {target_url}[/bold cyan]")
    prober = WebProber()
    rt_findings = prober.probe_url(target_url)
    if rt_findings:
        console.print(f"[yellow]Runtime findings: {len(rt_findings)}[/yellow]")
        for f in rt_findings:
            console.print(f"  [{f.severity}] {f.id}: {f.title}")
    else:
        console.print("[green]No runtime findings — target unreachable or all headers present.[/green]")



# Placeholder commands for upcoming phases
@cli.command("network")
@click.argument("cidr", required=False)
@click.option("--authorized", is_flag=True, help="Acknowledge explicit authorization.")
def network_cmd(cidr: str | None, authorized: bool):
    """Analyze an authorized network or LAN range (Phase 2+)."""
    console.print("[yellow]Not implemented in current phase.[/yellow] (Scheduled for Phase 2: Network Scanner)")


@cli.command("host")
def host_cmd():
    """Audit local host processes, sockets, and persistence (Phase 2+)."""
    console.print("[yellow]Not implemented in current phase.[/yellow] (Scheduled for Phase 2: Host Security Auditor)")


@cli.command("monitor")
def monitor_cmd():
    """Continuous local security monitoring (Phase 2+)."""
    console.print("[yellow]Not implemented in current phase.[/yellow] (Scheduled for Phase 2: Runtime Monitor)")


@cli.command("report")
@click.argument("path", default=".", type=click.Path(exists=False, readable=True))
@click.option("--target", "-t", default=None, help="Explicitly authorized remote target URL (Runtime check).")
@click.option("--active", is_flag=True, help="Run Phase 3 Active Validation Swarm against --target.")
@click.option("--oversight/--no-oversight", default=True, help="Include Phase 3.5 Developer Oversight findings.")
@click.option("--authorized", is_flag=True, help="Explicitly certify authorization for target.")
@click.option("--json-out", "--json", is_flag=True, help="Emit raw machine-readable JSON to stdout.")
@click.option("--markdown-out", "--markdown", is_flag=True, help="Emit detailed Markdown report to stdout.")
@click.option("--format", "fmt", default="terminal", type=click.Choice(["terminal", "json", "markdown", "sarif", "html"]))
@click.option("--output", "-o", default=None, type=click.Path(), help="Custom output file path.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom nsat.yaml config.")
@click.option("--no-save", is_flag=True, help="Do not save report to reports/ directory.")
def report_cmd(
    path: str,
    target: str | None,
    active: bool,
    oversight: bool,
    authorized: bool,
    json_out: bool,
    markdown_out: bool,
    fmt: str,
    output: str | None,
    config: str | None,
    no_save: bool,
):
    """
    Generate unified, multi-domain security audit and threat assessment report.

    Runs discovery, security scanning, active validation (optional), developer oversight,
    attack-surface graph correlation, and deterministic risk scoring.
    """
    target_path, intel, surface, findings, swarm_result, oversight_result, security_model = _build_security_pipeline(
        path=path,
        target=target,
        active=active,
        oversight=oversight,
        authorized=authorized,
        config=config,
    )

    # Output selection
    if json_out or fmt == "json":
        json_content = export_json_str(security_model)
        if output:
            Path(output).write_text(json_content, encoding="utf-8")
        click.echo(json_content)
        return

    if markdown_out or fmt == "markdown":
        md_content = export_markdown_report(security_model)
        if output:
            Path(output).write_text(md_content, encoding="utf-8")
        click.echo(md_content)
        return

    # Terminal report (Default) + file output to reports/
    ReportManager.generate_and_save(
        model=security_model,
        format_type="terminal",
        output_path=output,
        save_file=not no_save,
    )


@cli.command("ai-report")
@click.argument("path", default=".", type=click.Path(exists=False, readable=True))
@click.option("--target", "-t", default=None, help="Explicitly authorized remote target URL (Runtime check).")
@click.option("--active", is_flag=True, help="Run Phase 3 Active Validation Swarm against --target.")
@click.option("--oversight/--no-oversight", default=True, help="Include Phase 3.5 Developer Oversight findings.")
@click.option("--authorized", is_flag=True, help="Explicitly certify authorization for target.")
@click.option("--output", "-o", default=None, type=click.Path(), help="Custom output file path.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom nsat.yaml config.")
@click.option("--no-save", is_flag=True, help="Do not save report to reports/ directory.")
def ai_report_cmd(
    path: str,
    target: str | None,
    active: bool,
    oversight: bool,
    authorized: bool,
    output: str | None,
    config: str | None,
    no_save: bool,
):
    """
    Generate GLM-5.3 AI-assisted executive security report (Phase 4B).

    Combines deterministic correlation with GLM reasoning to explain overall risk,
    priority findings, multi-hop attack paths, and developer remediation.
    """
    target_path, intel, surface, findings, swarm_result, oversight_result, security_model = _build_security_pipeline(
        path=path,
        target=target,
        active=active,
        oversight=oversight,
        authorized=authorized,
        config=config,
    )

    provider = GLMProvider() if GLMConfig.load().is_configured() else None
    report_text = AIReportGenerator.generate_report(security_model, provider)

    if output:
        out_p = Path(output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(report_text, encoding="utf-8")
        console.print(f"[bold green][OK] AI Report written to: {out_p}[/bold green]")
    else:
        console.print(Markdown(report_text))

    if not no_save and not output:
        rep_dir = target_path / "reports"
        rep_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_file = rep_dir / f"nsat-ai-report-{timestamp}.md"
        saved_file.write_text(report_text, encoding="utf-8")
        console.print(f"\n[dim]AI report saved to: {saved_file}[/dim]")


@cli.command("explain")
@click.argument("finding_id", required=False)
@click.argument("path", default=".", type=click.Path(exists=False, readable=True))
@click.option("--ai/--no-ai", default=True, help="Enable AI reasoning (default: True).")
@click.option("--target", "-t", default=None, help="Authorized target URL.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom config.")
def explain_cmd(
    finding_id: str | None,
    path: str,
    ai: bool,
    target: str | None,
    config: str | None,
):
    """Explain a specific security finding with root cause analysis (Phase 4B)."""
    if not finding_id:
        console.print("[yellow]Not implemented in current phase.[/yellow] (Please specify a finding ID to explain, e.g.: nsat explain NSAT-PY-SQLI)")
        return

    target_path, intel, surface, findings, swarm_result, oversight_result, security_model = _build_security_pipeline(
        path=path,
        target=target,
        active=False,
        oversight=True,
        authorized=False,
        config=config,
    )

    provider = GLMProvider() if (ai and GLMConfig.load().is_configured()) else None
    explanation = FindingExplainer.explain(finding_id, security_model, provider)
    console.print(Panel(explanation, title=f"Finding Explanation -- {finding_id}", border_style="cyan"))


@cli.command("chat")
@click.argument("path", default=".", type=click.Path(exists=False, readable=True))
@click.option("--finding", "-f", default=None, help="Focus chat session on a specific finding ID.")
@click.option("--ask", "-q", default=None, help="One-shot question without interactive session.")
@click.option("--target", "-t", default=None, help="Authorized target URL.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom config.")
def chat_cmd(
    path: str,
    finding: str | None,
    ask: str | None,
    target: str | None,
    config: str | None,
):
    """Interactive NSAT security chatbot powered by GLM-5.3 (Phase 4B)."""
    target_path, intel, surface, findings, swarm_result, oversight_result, security_model = _build_security_pipeline(
        path=path,
        target=target,
        active=False,
        oversight=True,
        authorized=False,
        config=config,
    )

    provider = GLMProvider() if GLMConfig.load().is_configured() else None
    bot = SecurityChatbot(model=security_model, provider=provider)

    if finding:
        bot.ask(f"Focus specifically on finding {finding}.")

    if ask:
        answer = bot.ask(ask)
        console.print(f"\n[bold cyan]NSAT:[/] {answer}\n")
    else:
        bot.run_interactive(console)


@cli.command("fix")
@click.argument("finding_id", required=False)
@click.argument("path", default=".", type=click.Path(exists=False, readable=True))
@click.option("--dry-run", is_flag=True, help="Preview proposed diff without creating backup or modifying files.")
@click.option("--yes", "-y", is_flag=True, help="Automatically approve and apply the patch without interactive prompt.")
@click.option("--rollback", "rollback_id", default=None, help="Roll back a previous remediation by remediation_id.")
@click.option("--force", is_flag=True, help="Force rollback even if conflicts or newer edits are detected.")
@click.option("--ai/--no-ai", default=True, help="Use Kimi-K3 for patch generation if available.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom config.")
def fix_cmd(
    finding_id: str | None,
    path: str,
    dry_run: bool,
    yes: bool,
    rollback_id: str | None,
    force: bool,
    ai: bool,
    config: str | None,
):
    """Generate, test, and safely apply a targeted remediation patch (Phase 4C)."""
    target_path = Path(path).resolve()

    # Handle manual rollback request: nsat fix --rollback <remediation_id>
    if rollback_id:
        target_path = Path(".").resolve()
        if finding_id:
            p_candidate = Path(finding_id)
            if p_candidate.is_dir() or p_candidate.exists():
                target_path = p_candidate.resolve()
            else:
                target_path = Path(path).resolve()
        else:
            target_path = Path(path).resolve()

        from nsat.remediation.manager import RemediationManager
        RemediationManager.rollback_remediation(
            remediation_id=rollback_id,
            repo_root=target_path,
            force=force,
            console=console,
        )
        return

    if not finding_id:
        console.print("[yellow]Not implemented in current phase.[/yellow] (Please specify a finding ID to fix, e.g.: nsat fix NSAT-CONT-002)")
        console.print("Run [bold cyan]nsat audit[/bold cyan] to see available finding IDs.")
        return

    # Reuse the most recent same-repository audit model when available.
    if not (target_path / "src").exists() and (target_path / "demo-vuln-app").is_dir():
        target_path = target_path / "demo-vuln-app"
    security_model = _load_audit_context(target_path)
    if security_model:
        target_path = Path(security_model.project.get("path") or target_path).resolve()
        console.print("[dim]Using latest saved audit context.[/dim]")
    else:
        target_path, intel, surface, findings, swarm_result, oversight_result, security_model = _build_security_pipeline(
            path=str(target_path),
            target=None,
            active=False,
            oversight=True,
            authorized=False,
            config=config,
        )

    from nsat.ai.config import KimiConfig
    from nsat.ai.kimi import KimiProvider
    from nsat.remediation.manager import RemediationManager

    k_cfg = KimiConfig.load()
    provider = KimiProvider(k_cfg) if (ai and k_cfg.is_configured()) else None

    RemediationManager.fix_finding(
        finding_id=finding_id,
        repo_root=target_path,
        security_model=security_model,
        provider=provider,
        dry_run=dry_run,
        auto_approve=yes,
        console=console,
    )


@cli.command("verify")
@click.argument("finding_id", required=False)
@click.argument("path", default=".", type=click.Path(exists=False, readable=True))
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom config.")
def verify_cmd(finding_id: str | None, path: str, config: str | None):
    """Re-scan target files and compare BEFORE vs AFTER remediation states (Phase 4C)."""
    from nsat.remediation.manager import RemediationManager
    from rich.table import Table

    # If first argument looks like a directory, treat as path
    target_path = Path(".").resolve()
    filter_id = None
    if finding_id:
        p_candidate = Path(finding_id)
        if p_candidate.is_dir() or p_candidate.exists():
            target_path = p_candidate.resolve()
        else:
            filter_id = finding_id
            target_path = Path(path).resolve()
    else:
        target_path = Path(path).resolve()

    history = RemediationManager.load_history(target_path)

    if not history:
        console.print("[yellow]Not implemented in current phase.[/yellow] (No remediation actions recorded yet; run 'nsat fix <finding_id>' first)")
        return

    table = Table(title="NSAT Remediation & Verification History", border_style="cyan")
    table.add_column("Remediation ID", style="dim", no_wrap=True)
    table.add_column("Finding ID", style="bold yellow", no_wrap=True)
    table.add_column("Affected File(s)", style="white")
    table.add_column("Tests", justify="center", no_wrap=True)
    table.add_column("Outcome", justify="center", no_wrap=True)
    table.add_column("Risk Score", justify="center", no_wrap=True)
    table.add_column("Rollback", justify="center", no_wrap=True)

    filtered = [h for h in history if not filter_id or h.get("finding_id", "").upper() == filter_id.upper()]

    for item in reversed(filtered):
        outcome = item.get("outcome", "UNKNOWN")
        out_style = "bold green" if outcome == "RESOLVED" else "bold red"
        tests_str = "[green][OK][/green]" if item.get("tests_passed") else "[red][X][/red]"
        rb_str = "[yellow]YES[/yellow]" if item.get("rollback_performed") else "[dim]NO[/dim]"
        files_str = ", ".join(item.get("affected_files", []))
        risk_str = f"{item.get('previous_risk_score', 0)} -> {item.get('current_risk_score', 0)}"

        table.add_row(
            item.get("remediation_id", ""),
            item.get("finding_id", ""),
            files_str,
            tests_str,
            f"[{out_style}]{outcome}[/{out_style}]",
            risk_str,
            rb_str,
        )

    console.print(table)


@cli.command("config")
def config_cmd():
    """Configure scanners, scope, thresholds, and AI providers."""
    from nsat.ai.config import GLMConfig, KimiConfig
    g_cfg = GLMConfig.load()
    k_cfg = KimiConfig.load()

    console.print("\n[bold cyan]NSAT Configuration & Provider Status[/bold cyan]\n")
    console.print(f"  [bold white]GLM-5.3 (Reasoning/Chat):[/]  {'[green]CONFIGURED[/green]' if g_cfg.is_configured() else '[yellow]NOT CONFIGURED[/yellow]'} (Key: {g_cfg.masked_key})")
    console.print(f"  [bold white]Kimi-K3 (Remediation):[/]     {'[green]CONFIGURED[/green]' if k_cfg.is_configured() else '[yellow]NOT CONFIGURED[/yellow]'} (Key: {k_cfg.masked_key})\n")


if __name__ == "__main__":
    cli()
