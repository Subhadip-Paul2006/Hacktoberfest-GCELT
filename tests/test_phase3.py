"""Phase 3 Test Suite — Active Validation Swarm."""

import json
from pathlib import Path
import sys
import pytest
from starlette.testclient import TestClient

# Add demo-vuln-app to path
demo_dir = Path(__file__).parent.parent / "demo-vuln-app"
if str(demo_dir) not in sys.path:
    sys.path.insert(0, str(demo_dir))

from src.api.handlers import app as demo_fastapi_app
from nsat.core.config import NSATConfig
from nsat.core.discovery import DiscoveryEngine
from nsat.core.orchestrator import Phase2Orchestrator
from nsat.core.surface import SecuritySurface, ApplicationSurface, Endpoint, NetworkBinding, SecretLocation
from nsat.core.models import ProjectIntelligence, ProjectMetadata, ProjectTypeClassification
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.swarm.models import (
    AgentExecutionResult,
    AgentResultStatus,
    SwarmConfig,
    SwarmResult,
    TargetScope,
    ValidationEvidence,
)
from nsat.swarm.planner import SwarmPlanner
from nsat.swarm.coordinator import SwarmCoordinator
from nsat.swarm.agents.auth_agent import AuthenticationValidationAgent
from nsat.swarm.agents.authz_agent import AuthorizationValidationAgent
from nsat.swarm.agents.api_agent import APISecurityAgent
from nsat.swarm.agents.base import SwarmValidationContext
from nsat.swarm.agents.blast_radius_agent import PostCompromiseExposureAgent
from nsat.swarm.agents.business_logic_agent import BusinessLogicAgent
from nsat.swarm.agents.file_upload_agent import FileUploadAgent
from nsat.swarm.agents.input_validation_agent import InputValidationAgent
from nsat.swarm.agents.network_agent import NetworkValidationAgent
from nsat.swarm.agents.payment_agent import PaymentFlowAgent
from nsat.swarm.agents.rate_limit_agent import RateLimitAgent
from nsat.swarm.agents.websocket_agent import WebSocketAgent


@pytest.fixture
def demo_context():
    """Build project intelligence, security surface, and findings for the demo application."""
    cfg = NSATConfig.load(target_dir=demo_dir)
    engine = DiscoveryEngine(config=cfg)
    intel = engine.discover(demo_dir)
    orchestrator = Phase2Orchestrator()
    surface, findings = orchestrator.run(demo_dir, intel)
    return intel, surface, findings


# ── 1. Swarm Planner ──────────────────────────────────────────────────────────
def test_swarm_planner(demo_context):
    intel, surface, findings = demo_context
    planner = SwarmPlanner()
    scope = TargetScope(target="http://127.0.0.1:8000")

    selected, skipped = planner.plan(intel, surface, findings, scope)

    assert isinstance(selected, list)
    assert isinstance(skipped, list)
    assert len(selected) > 0, "Expected at least some agents selected for demo app"
    # Key agents for demo app must be selected
    assert "Authentication Agent" in selected
    assert "Authorization Agent" in selected
    assert "Input Validation Agent" in selected
    assert "Rate Limit Agent" in selected
    assert "Post-Compromise Exposure Agent" in selected


# ── 2. Agent Selection Skips Irrelevant ───────────────────────────────────────
def test_agent_selection_skips_irrelevant():
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path="dummy", project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="cli_tool"),
        languages=[],
    )
    # Empty surface with no endpoints, no sockets, no secrets
    surface = SecuritySurface(target_path="dummy")
    findings = []
    scope = TargetScope(target="http://127.0.0.1:8000")

    planner = SwarmPlanner()
    selected, skipped = planner.plan(intel, surface, findings, scope)

    skipped_names = [name for name, _ in skipped]
    assert "WebSocket Agent" in skipped_names
    assert "Payment Agent" in skipped_names
    assert "File Upload Agent" in skipped_names
    assert "Authentication Agent" in skipped_names


# ── 3. Scope Enforcement: Allows Localhost ────────────────────────────────────
def test_scope_enforcement_allows_localhost():
    assert TargetScope(target="http://localhost:8000").is_authorized()
    assert TargetScope(target="http://127.0.0.1:8000").is_authorized()
    assert TargetScope(target="http://0.0.0.0:8000").is_authorized()
    assert TargetScope(target="http://[::1]:8000").is_authorized()


# ── 4. Scope Enforcement: Blocks External Targets Without Auth ────────────────
def test_scope_enforcement_blocks_external():
    scope_unauth = TargetScope(target="https://example.com")
    assert not scope_unauth.is_authorized()

    scope_auth = TargetScope(target="https://example.com", explicitly_authorized=True)
    assert scope_auth.is_authorized()


# ── 5. Authentication Validation Agent ────────────────────────────────────────
def test_authentication_validation(demo_context):
    intel, surface, findings = demo_context
    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")
    ctx = SwarmValidationContext(
        target_url="http://127.0.0.1:8000",
        surface=surface,
        intelligence=intel,
        findings=findings,
        config=SwarmConfig(),
        scope=TargetScope(target="http://127.0.0.1:8000"),
        http_client=client,
    )

    agent = AuthenticationValidationAgent()
    result = agent.validate(ctx)

    assert result.agent_name == "Authentication Agent"
    assert len(result.evidence) > 0
    assert result.status in (AgentResultStatus.VALIDATED, AgentResultStatus.POTENTIAL, AgentResultStatus.NOT_VALIDATED)


# ── 6. Authorization Validation Agent ─────────────────────────────────────────
def test_authorization_validation(demo_context):
    intel, surface, findings = demo_context
    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")
    ctx = SwarmValidationContext(
        target_url="http://127.0.0.1:8000",
        surface=surface,
        intelligence=intel,
        findings=findings,
        config=SwarmConfig(),
        scope=TargetScope(target="http://127.0.0.1:8000"),
        http_client=client,
    )

    agent = AuthorizationValidationAgent()
    result = agent.validate(ctx)

    # Demo app exposes unauthenticated /api/v1/admin/dashboard
    assert result.status == AgentResultStatus.VALIDATED
    assert any("200" in ev.observed_response for ev in result.evidence)


# ── 7. API Security Agent ─────────────────────────────────────────────────────
def test_api_validation(demo_context):
    intel, surface, findings = demo_context
    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")
    ctx = SwarmValidationContext(
        target_url="http://127.0.0.1:8000",
        surface=surface,
        intelligence=intel,
        findings=findings,
        config=SwarmConfig(),
        scope=TargetScope(target="http://127.0.0.1:8000"),
        http_client=client,
    )

    agent = APISecurityAgent()
    result = agent.validate(ctx)

    assert result.agent_name == "API Agent"
    assert result.status in (AgentResultStatus.VALIDATED, AgentResultStatus.POTENTIAL, AgentResultStatus.NOT_VALIDATED)


# ── 8. Rate Limit Validation Agent ────────────────────────────────────────────
def test_rate_limit_validation(demo_context):
    intel, surface, findings = demo_context
    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")
    ctx = SwarmValidationContext(
        target_url="http://127.0.0.1:8000",
        surface=surface,
        intelligence=intel,
        findings=findings,
        config=SwarmConfig(),
        scope=TargetScope(target="http://127.0.0.1:8000"),
        http_client=client,
    )

    agent = RateLimitAgent()
    result = agent.validate(ctx)

    # Demo app has NO rate limiting on /api/v1/login -> returns VALIDATED vulnerability
    assert result.status == AgentResultStatus.VALIDATED
    assert any("Missing rate limiting" in ev.observed_response for ev in result.evidence)


# ── 9. Business Logic Validation Agent ────────────────────────────────────────
def test_business_logic_validation(demo_context):
    intel, surface, findings = demo_context
    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")
    ctx = SwarmValidationContext(
        target_url="http://127.0.0.1:8000",
        surface=surface,
        intelligence=intel,
        findings=findings,
        config=SwarmConfig(),
        scope=TargetScope(target="http://127.0.0.1:8000"),
        http_client=client,
    )

    agent = BusinessLogicAgent()
    result = agent.validate(ctx)

    # Demo app accepts direct /api/v1/order/confirm without prior payment
    assert result.status == AgentResultStatus.VALIDATED
    assert any("Insecure state transition" in ev.observed_response or "200" in ev.observed_response for ev in result.evidence)


# ── 10. Payment Flow Validation Agent ─────────────────────────────────────────
def test_payment_flow_validation(demo_context):
    intel, surface, findings = demo_context
    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")
    ctx = SwarmValidationContext(
        target_url="http://127.0.0.1:8000",
        surface=surface,
        intelligence=intel,
        findings=findings,
        config=SwarmConfig(),
        scope=TargetScope(target="http://127.0.0.1:8000"),
        http_client=client,
    )

    agent = PaymentFlowAgent()
    result = agent.validate(ctx)

    # Demo app accepts client-trusted price tampering ($0.01) on /api/v1/checkout
    assert result.status == AgentResultStatus.VALIDATED
    assert any("Server accepted client-specified price" in ev.observed_response for ev in result.evidence)


# ── 11. WebSocket Validation Agent ────────────────────────────────────────────
def test_websocket_validation(demo_context):
    intel, surface, findings = demo_context
    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")
    ctx = SwarmValidationContext(
        target_url="http://127.0.0.1:8000",
        surface=surface,
        intelligence=intel,
        findings=findings,
        config=SwarmConfig(),
        scope=TargetScope(target="http://127.0.0.1:8000"),
        http_client=client,
    )

    agent = WebSocketAgent()
    result = agent.validate(ctx)

    assert result.agent_name == "WebSocket Agent"
    assert result.status in (AgentResultStatus.VALIDATED, AgentResultStatus.POTENTIAL, AgentResultStatus.NOT_VALIDATED, AgentResultStatus.NOT_APPLICABLE)


# ── 12. File Upload Validation Agent ──────────────────────────────────────────
def test_file_upload_validation(demo_context):
    intel, surface, findings = demo_context
    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")
    ctx = SwarmValidationContext(
        target_url="http://127.0.0.1:8000",
        surface=surface,
        intelligence=intel,
        findings=findings,
        config=SwarmConfig(),
        scope=TargetScope(target="http://127.0.0.1:8000"),
        http_client=client,
    )

    agent = FileUploadAgent()
    result = agent.validate(ctx)

    # Demo app accepts .sh script upload on /upload
    assert result.status == AgentResultStatus.VALIDATED
    assert any("Missing file type whitelist" in ev.observed_response for ev in result.evidence)


# ── 13. Network Validation Agent ──────────────────────────────────────────────
def test_network_validation(demo_context):
    intel, surface, findings = demo_context
    ctx = SwarmValidationContext(
        target_url="http://127.0.0.1:8000",
        surface=surface,
        intelligence=intel,
        findings=findings,
        config=SwarmConfig(request_timeout=0.5),
        scope=TargetScope(target="http://127.0.0.1:8000"),
    )

    agent = NetworkValidationAgent()
    result = agent.validate(ctx)

    assert result.agent_name == "Network Validation Agent"
    assert result.status in (AgentResultStatus.VALIDATED, AgentResultStatus.NOT_VALIDATED, AgentResultStatus.POTENTIAL)


# ── 14. Post-Compromise Exposure Agent ────────────────────────────────────────
def test_blast_radius_validation(demo_context):
    intel, surface, findings = demo_context
    ctx = SwarmValidationContext(
        target_url="http://127.0.0.1:8000",
        surface=surface,
        intelligence=intel,
        findings=findings,
        config=SwarmConfig(),
        scope=TargetScope(target="http://127.0.0.1:8000"),
    )

    agent = PostCompromiseExposureAgent()
    result = agent.validate(ctx)

    # Demo app has Dockerfile with root user, secrets, and docker.sock mount
    assert result.status == AgentResultStatus.VALIDATED
    ev = result.evidence[0]
    assert "TIER 3" in ev.details.get("blast_radius_tier", "") or "TIER 2" in ev.details.get("blast_radius_tier", "")


# ── 15. Evidence Generation & Redaction ───────────────────────────────────────
def test_evidence_generation():
    agent = AuthenticationValidationAgent()
    raw = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fake and password='supersecret_pass'"
    redacted = agent.redact(raw)
    assert "supersecret_pass" not in redacted
    assert "eyJ...[REDACTED_JWT]" in redacted

    evidence = ValidationEvidence(
        agent="TestAgent",
        target="http://127.0.0.1:8000",
        endpoint="/api/v1/test",
        request_type="HTTP_GET",
        safe_test_description="Safe probe test",
        observed_response=redacted,
        status=AgentResultStatus.VALIDATED,
        confidence=0.90,
    )
    assert evidence.agent == "TestAgent"
    assert evidence.confidence == 0.90
    assert evidence.timestamp


# ── 16. Finding Upgrade ───────────────────────────────────────────────────────
def test_finding_upgrade(demo_context):
    intel, surface, findings = demo_context
    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")

    # Add a mock unverified finding
    test_finding = CanonicalFinding(
        id="TEST-AUTHZ-001",
        title="Admin dashboard unauthenticated access",
        category="web_security",
        severity="HIGH",
        confidence=0.60,
        asset="demo-vuln-app/src/api/handlers.py",
        description="Admin dashboard may lack authorization",
        impact="Unauthorized admin access",
        recommendation="Enforce auth middleware",
    )
    findings_list = findings + [test_finding]

    coordinator = SwarmCoordinator()
    result = coordinator.run(
        target_url="http://127.0.0.1:8000",
        intelligence=intel,
        surface=surface,
        findings=findings_list,
        http_client=client,
    )

    upgraded = next((f for f in result.findings if f.id == "TEST-AUTHZ-001"), None)
    assert upgraded is not None
    assert upgraded.status == "VALIDATED"
    assert upgraded.confidence > 0.60
    assert any(ev.type == "ACTIVE_VALIDATION" for ev in upgraded.evidence)


# ── 17. Blocked Scope Stops Execution ─────────────────────────────────────────
def test_blocked_scope_stops_execution(demo_context):
    intel, surface, findings = demo_context
    unauth_scope = TargetScope(target="https://unauthorized-remote-host.com")

    coordinator = SwarmCoordinator()
    result = coordinator.run(
        target_url="https://unauthorized-remote-host.com",
        intelligence=intel,
        surface=surface,
        findings=findings,
        scope=unauth_scope,
    )

    assert result.scope_enforced is True
    assert len(result.agents_selected) == 0
    assert len(result.all_evidence) == 0
    assert result.correlation_handoff.get("scope_blocked") is True


# ── 18. Agent Failure Isolation ───────────────────────────────────────────────
def test_agent_failure_isolation(demo_context):
    intel, surface, findings = demo_context

    class CrashingAgent(AuthenticationValidationAgent):
        @property
        def name(self):
            return "Crashing Agent"

        def validate(self, ctx):
            raise RuntimeError("Simulated agent catastrophic crash!")

    coordinator = SwarmCoordinator()
    coordinator.agents_registry["Crashing Agent"] = CrashingAgent()
    coordinator.planner.ALL_AGENTS.append("Crashing Agent")

    # Monkey patch planner to select Crashing Agent
    orig_plan = coordinator.planner.plan
    def mock_plan(*args, **kwargs):
        sel, skip = orig_plan(*args, **kwargs)
        return sel + ["Crashing Agent"], skip

    coordinator.planner.plan = mock_plan

    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")
    result = coordinator.run(
        target_url="http://127.0.0.1:8000",
        intelligence=intel,
        surface=surface,
        findings=findings,
        http_client=client,
    )

    # Swarm must survive without raising an exception!
    assert "Crashing Agent" in result.agent_results
    assert result.agent_results["Crashing Agent"].status == AgentResultStatus.ERROR
    assert "Simulated agent catastrophic crash!" in result.agent_results["Crashing Agent"].error_message


# ── 19. Full End-to-End Coordinator on Demo App ───────────────────────────────
def test_full_swarm_coordinator_on_demo_app(demo_context):
    intel, surface, findings = demo_context
    client = TestClient(demo_fastapi_app, base_url="http://127.0.0.1:8000")

    coordinator = SwarmCoordinator()
    result = coordinator.run(
        target_url="http://127.0.0.1:8000",
        intelligence=intel,
        surface=surface,
        findings=findings,
        http_client=client,
    )

    assert len(result.agents_selected) >= 5
    assert len(result.all_evidence) > 0
    assert result.correlation_handoff["target"] == "http://127.0.0.1:8000"


# ── 20. CLI Validate Command ──────────────────────────────────────────────────
def test_cli_validate_command():
    from click.testing import CliRunner
    from nsat.cli.main import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["validate", str(demo_dir), "--target", "http://127.0.0.1:8000", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["target"] == "http://127.0.0.1:8000"
    assert "agents_selected" in data
    assert "agent_results" in data
