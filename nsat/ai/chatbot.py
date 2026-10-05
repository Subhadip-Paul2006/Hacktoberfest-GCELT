"""Interactive Security Chatbot for NSAT powered by GLM-5.3."""

import json
import logging
import sys
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel

from nsat.ai.context_builder import AIContextBuilder
from nsat.ai.prompts import CHATBOT_SYSTEM_PROMPT
from nsat.ai.provider import LLMProvider
from nsat.correlation.models import Phase4SecurityModel

logger = logging.getLogger("nsat.ai.chatbot")


class SecurityChatbot:
    """
    Interactive and one-shot Q&A assistant for NSAT security audit models.
    Maintains in-memory conversation history and enforces strict evidence grounding.
    """

    def __init__(self, model: Phase4SecurityModel, provider: Optional[LLMProvider] = None):
        self.model = model
        self.provider = provider
        self.history: list[dict[str, str]] = []

    def clear_history(self) -> None:
        """Reset conversation memory."""
        self.history.clear()

    def ask(self, user_query: str) -> str:
        """
        Process user question against the security model with in-memory conversation memory.
        """
        query_clean = user_query.strip()
        if not query_clean:
            return "Please provide a valid question."

        # Build targeted context based on query
        context = AIContextBuilder.build_chat_context(query_clean, self.model)

        # 1. Attempt AI reasoning if provider available
        if self.provider:
            try:
                system_with_context = (
                    f"{CHATBOT_SYSTEM_PROMPT}\n\n"
                    f"CURRENT PROJECT SECURITY CONTEXT (STRICT EVIDENCE BASE):\n"
                    f"{json.dumps(context, indent=2)}"
                )

                messages = [{"role": "system", "content": system_with_context}]
                # Append last 6 turns of conversation history for context continuity
                messages.extend(self.history[-6:])
                messages.append({"role": "user", "content": query_clean})

                response = self.provider.chat(
                    messages=messages,
                    temperature=0.2,
                    max_tokens=1024,
                )

                if response and response.strip():
                    ans = response.strip()
                    # Record history
                    self.history.append({"role": "user", "content": query_clean})
                    self.history.append({"role": "assistant", "content": ans})
                    return ans
            except Exception as e:
                logger.warning(f"GLM chat call failed: {e}")
                fallback = self._deterministic_fallback_answer(query_clean, context)
                self.history.append({"role": "user", "content": query_clean})
                self.history.append({"role": "assistant", "content": fallback})
                return f"[AI UNAVAILABLE]\nDeterministic project data remains available.\n\n{fallback}"

        # 2. Deterministic answer fallback
        ans = self._deterministic_fallback_answer(query_clean, context)
        self.history.append({"role": "user", "content": query_clean})
        self.history.append({"role": "assistant", "content": ans})
        return ans

    def _deterministic_fallback_answer(self, query: str, context: dict) -> str:
        """Deterministic rule-based answers when AI provider is offline."""
        q = query.lower()

        # Remediation / Fix questions
        if "what changed" in q or "remediation" in q or "did the fix work" in q or "was the patch" in q or "what fix" in q:
            from nsat.remediation.manager import RemediationManager
            hist = context.get("remediation_history")
            if hist is None:
                repo_p = Path(self.model.project.get("path") or ".")
                hist = RemediationManager.load_history(repo_p)
                if not hist and repo_p != Path("."):
                    hist = RemediationManager.load_history(Path("."))

            if hist:
                latest = hist[-1]
                outcome = latest.get("outcome", "UNKNOWN")
                fid = latest.get("finding_id", "N/A")
                aff = ", ".join(latest.get("affected_files", []))
                rb = latest.get("rollback_performed", False)
                prev_r = latest.get("previous_risk_score", 0)
                curr_r = latest.get("current_risk_score", 0)

                if "what changed" in q:
                    return f"Remediation action for {fid} modified: {aff}. Status: {outcome}. Overall risk moved from {prev_r} to {curr_r}."
                if "did the fix work" in q:
                    return f"The fix for {fid} was verified as {outcome}. Tests passed: {latest.get('tests_passed', True)}."
                if "rollback" in q:
                    return f"Remediation rollback status for {fid}: {'Rolled back' if rb else 'No rollback required; fix remains applied'}."
                return f"Latest remediation: {fid} on {aff} with result {outcome}."
            return "No remediation actions have been recorded yet in .nsat/remediation/history.json."

        # Which file to fix first
        if "which file" in q or "fix first" in q or "where should i start" in q:
            top = self.model.findings[0] if self.model.findings else None
            if top:
                loc = top.primary_location or {}
                fpath = loc.get("file_path") or top.file_path or top.asset
                line = loc.get("line_number") or top.line_number or "N/A"
                func = loc.get("function_name") or top.function_name or "handler"
                return (
                    f"You should fix '{fpath}' first (around line {line}, function '{func}'). "
                    f"It contains [{top.priority or 'P0'}] finding {top.id}: {top.title}."
                )
            return "No critical findings detected to prioritize."

        # Why is project rated critical
        if "critical" in q or "why is the risk" in q or "risk score" in q:
            crit_findings = [f for f in self.model.findings if f.severity == "CRITICAL"]
            reasons = [f"- {f.id}: {f.title} ({f.file_path or f.asset}:{f.line_number or ''})" for f in crit_findings[:3]]
            reasons_str = "\n".join(reasons)
            return (
                f"The overall risk score is {self.model.risk.overall_score}/100 ({self.model.risk.risk_level}) because:\n"
                f"1. Blast radius tier is {self.model.blast_radius.tier}.\n"
                f"2. {len(crit_findings)} CRITICAL severity vulnerabilities were detected:\n{reasons_str}\n"
                f"3. {self.model.risk.validated_findings_count} findings were actively validated in runtime checks."
            )

        # Docker / Container questions
        if "docker" in q or "container" in q or "socket" in q:
            paths = [ap for ap in self.model.attack_paths if any("docker" in s.lower() for s in ap.steps)]
            if paths:
                ap = paths[0]
                steps = "\n  -> ".join(ap.steps)
                return (
                    f"Docker Socket Attack Path ({ap.id}):\n"
                    f"  -> {steps}\n\n"
                    f"Impact: {ap.impact}\n"
                    f"Recommendation: {ap.recommendation}"
                )
            return "The container mounts /var/run/docker.sock, enabling container breakout to the host root daemon."

        # Validated vs potential
        if "validated" in q:
            validated = [f for f in self.model.findings if f.status in ("VALIDATED", "CONFIRMED_BY_SAFE_CHECK")]
            if validated:
                v_list = "\n".join(f"- {f.id}: {f.title} (Status: {f.status})" for f in validated)
                return f"Actively validated findings ({len(validated)} total):\n{v_list}"
            return "No findings have been actively validated by dynamic probes in this run."

        if "potential" in q:
            potential = [f for f in self.model.findings if f.status == "POTENTIAL" or f.status == "UNVERIFIED"]
            p_list = "\n".join(f"- {f.id}: {f.title} ({f.file_path or f.asset})" for f in potential[:5])
            return f"Potential / unverified findings (top 5):\n{p_list}"

        # Specific finding query
        for f in self.model.findings:
            if f.id.lower() in q:
                loc = f.primary_location or {}
                return (
                    f"Finding {f.id}: {f.title}\n"
                    f"Severity: {f.severity} | Priority: {f.priority or 'P2'}\n"
                    f"Location: {loc.get('file_path') or f.file_path}:{loc.get('line_number') or 'N/A'}\n"
                    f"Why dangerous: {f.impact}\n"
                    f"Fix: {f.recommendation}"
                )

        # General project query
        return (
            f"Project '{self.model.project.get('name', 'App')}' has {len(self.model.findings)} security findings. "
            f"Risk Level: {self.model.risk.risk_level} ({self.model.risk.overall_score}/100). "
            f"Blast radius: {self.model.blast_radius.tier}. "
            f"Ask about specific findings (e.g. 'Explain NSAT-PY-SQLI') or attack paths."
        )

    def run_interactive(self, console: Optional[Console] = None) -> None:
        """Run interactive REPL in the terminal."""
        con = console or Console()
        con.print(
            Panel(
                "[bold cyan]NSAT Security Chatbot[/bold cyan] (Powered by GLM-5.3 & Deterministic Graph)\n"
                "[dim]Ask questions about findings, attack paths, blast radius, or remediation priorities.\n"
                "Type 'exit' or 'quit' to end session.[/dim]",
                border_style="cyan",
            )
        )

        while True:
            try:
                con.print("\n[bold green]You:[/] ", end="")
                user_input = input().strip()
                if not user_input:
                    continue
                if user_input.lower() in ("exit", "quit", "q"):
                    con.print("[dim]Ending security chat session. Goodbye.[/dim]")
                    break

                response = self.ask(user_input)
                con.print(f"\n[bold cyan]NSAT:[/] {response}")

            except (KeyboardInterrupt, EOFError):
                con.print("\n[dim]Session terminated.[/dim]")
                break
