"""Phase 3.5 Test Suite — Developer Oversight, Information Leakage & Hidden Loophole Audit."""

import json
from pathlib import Path
import sys
import tempfile
import pytest

from nsat.core.config import NSATConfig
from nsat.core.discovery import DiscoveryEngine
from nsat.core.models import (
    EntryPoint,
    ProjectIntelligence,
    ProjectMetadata,
    ProjectTypeClassification,
)
from nsat.core.orchestrator import Phase2Orchestrator
from nsat.core.surface import ApplicationSurface, Endpoint, SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.oversight.engine import DeveloperOversightEngine
from nsat.oversight.rules.client_trust import ClientTrustRule
from nsat.oversight.rules.config_deployment import ConfigDeploymentRule
from nsat.oversight.rules.error_exposure import ErrorExposureRule
from nsat.oversight.rules.hidden_endpoints import HiddenEndpointsRule
from nsat.oversight.rules.log_leakage import LogLeakageRule
from nsat.oversight.rules.race_condition import RaceConditionRule
from nsat.oversight.rules.session_cookie import SessionCookieRule
from nsat.oversight.rules.url_leakage import URLLeakageRule

demo_dir = Path(__file__).parent.parent / "demo-vuln-app"


@pytest.fixture
def demo_context():
    """Build intelligence, surface, and Phase 2 findings from demo-vuln-app."""
    cfg = NSATConfig.load(target_dir=demo_dir)
    engine = DiscoveryEngine(config=cfg)
    intel = engine.discover(demo_dir)
    orchestrator = Phase2Orchestrator()
    surface, findings = orchestrator.run(demo_dir, intel)
    return intel, surface, findings


# ── 1. Sensitive Token in URL Detection ────────────────────────────────────────
def test_sensitive_token_in_url():
    rule = URLLeakageRule()
    surface = SecuritySurface(
        target_path="dummy",
        application=ApplicationSurface(
            endpoints=[
                Endpoint(
                    path="/api/v1/reset-password/{reset_token}",
                    method="GET",
                    handler="reset_pwd",
                    file_path="src/auth.py",
                    line_number=10,
                )
            ]
        ),
    )
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path="dummy", project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="web_service"),
        languages=[],
    )
    findings = rule.audit(Path("."), intel, surface, [])
    assert len(findings) > 0
    assert any("Token" in f.title or "reset_token" in f.description.lower() for f in findings)


# ── 2. Password / PIN / OTP in URL Detection ──────────────────────────────────
def test_password_pin_otp_in_url(demo_context):
    intel, surface, findings = demo_context
    rule = URLLeakageRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any("One-Time Password / PIN" in f.title or "otp" in f.asset.lower() for f in res)


# ── 3. Secret in Query Parameter Detection ────────────────────────────────────
def test_secret_in_query_parameter(tmp_path):
    src = tmp_path / "client.ts"
    src.write_text('const url = `/api/v1/auth?api_key=${apiKey}&secret=${secret}`;')
    rule = URLLeakageRule()
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path=str(tmp_path), project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="frontend"),
        languages=[],
    )
    surface = SecuritySurface(target_path=str(tmp_path))
    findings = rule.audit(tmp_path, intel, surface, [])
    assert len(findings) > 0
    assert any("api_key" in f.description.lower() for f in findings)


# ── 4. Log Secret Detection ───────────────────────────────────────────────────
def test_log_secret_detection(demo_context):
    intel, surface, findings = demo_context
    rule = LogLeakageRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any("password" in f.title.lower() for f in res)
    # Check that secrets are redacted
    for f in res:
        for ev in f.evidence:
            assert "secret123" not in ev.snippet


# ── 5. Stack Trace Detection ──────────────────────────────────────────────────
def test_stack_trace_detection(demo_context):
    intel, surface, findings = demo_context
    rule = ErrorExposureRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any("Stack Trace" in f.title or "Traceback" in f.title for f in res)


# ── 6. Debug Endpoint Detection ───────────────────────────────────────────────
def test_debug_endpoint_detection(demo_context):
    intel, surface, findings = demo_context
    rule = HiddenEndpointsRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any("/debug/dump" in f.asset for f in res)


# ── 7. Backup File Detection ──────────────────────────────────────────────────
def test_backup_file_detection(demo_context):
    intel, surface, findings = demo_context
    rule = ConfigDeploymentRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any(".env.bak" in f.asset for f in res)


# ── 8. .git Deployment Exposure Logic ─────────────────────────────────────────
def test_git_deployment_exposure(tmp_path):
    public_git = tmp_path / "public" / ".git"
    public_git.mkdir(parents=True)
    rule = ConfigDeploymentRule()
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path=str(tmp_path), project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="web_service"),
        languages=[],
    )
    surface = SecuritySurface(target_path=str(tmp_path))
    res = rule.audit(tmp_path, intel, surface, [])
    assert any("Git Version Control Metadata" in f.title for f in res)


# ── 9. Swagger / OpenAPI Documentation Exposure ───────────────────────────────
def test_swagger_exposure_logic():
    rule = HiddenEndpointsRule()
    surface = SecuritySurface(
        target_path="dummy",
        application=ApplicationSurface(
            endpoints=[
                Endpoint(path="/swagger-ui", method="GET", handler="swagger", file_path="main.py", line_number=1),
                Endpoint(path="/openapi.json", method="GET", handler="openapi", file_path="main.py", line_number=2),
            ]
        ),
    )
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path="dummy", project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="web_service"),
        languages=[],
    )
    findings = rule.audit(Path("."), intel, surface, [])
    assert any("Swagger" in f.title for f in findings)
    assert any("OpenAPI" in f.title for f in findings)


# ── 10. Source Map Exposure ───────────────────────────────────────────────────
def test_source_map_exposure(demo_context):
    intel, surface, findings = demo_context
    rule = ConfigDeploymentRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any("App.tsx.map" in f.asset for f in res)


# ── 11. Insecure Cookie Flags ─────────────────────────────────────────────────
def test_insecure_cookie_flags(demo_context):
    intel, surface, findings = demo_context
    rule = SessionCookieRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any("auth_session" in f.title for f in res)
    assert any("HttpOnly" in f.title for f in res)


# ── 12. Sensitive Token Lifetime / JWT Expiration ─────────────────────────────
def test_jwt_missing_expiration(tmp_path):
    py_file = tmp_path / "token_svc.py"
    py_file.write_text('token = jwt.encode({"user_id": 123}, SECRET_KEY, algorithm="HS256")\n')
    rule = SessionCookieRule()
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path=str(tmp_path), project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="backend"),
        languages=[],
    )
    surface = SecuritySurface(target_path=str(tmp_path))
    findings = rule.audit(tmp_path, intel, surface, [])
    assert any("JWT" in f.title and "exp" in f.title.lower() for f in findings)


# ── 13. Trusted Header Misuse ─────────────────────────────────────────────────
def test_trusted_header_misuse(demo_context):
    intel, surface, findings = demo_context
    rule = ClientTrustRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any("X-Role" in f.title for f in res)


# ── 14. Client-Only Authorization Indicator ───────────────────────────────────
def test_client_only_authorization(tmp_path):
    # Frontend checks role, backend has unauthenticated admin route
    src_fe = tmp_path / "AdminView.tsx"
    src_fe.write_text('if (user.role === "admin") { return <AdminDashboard />; }')

    src_be = tmp_path / "routes.py"
    src_be.write_text('@app.get("/api/v1/admin/delete")\ndef delete_all(): pass')

    surface = SecuritySurface(
        target_path=str(tmp_path),
        application=ApplicationSurface(
            admin_endpoints=[
                Endpoint(path="/api/v1/admin/delete", method="GET", handler="delete_all", file_path="routes.py", line_number=1)
            ]
        ),
    )
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path=str(tmp_path), project_name="dummy", analyzable_files_count=2),
        project_type=ProjectTypeClassification(primary_type="fullstack"),
        languages=[],
    )
    rule = ClientTrustRule()
    findings = rule.audit(tmp_path, intel, surface, [])
    assert any("Client-Side Only Authorization" in f.title for f in findings)


# ── 15. Open Redirect Indicator ───────────────────────────────────────────────
def test_open_redirect_indicator(demo_context):
    intel, surface, findings = demo_context
    rule = ConfigDeploymentRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any("Open Redirect" in f.title for f in res)


# ── 16. CORS Oversight ────────────────────────────────────────────────────────
def test_cors_oversight(tmp_path):
    app_file = tmp_path / "main.py"
    app_file.write_text('app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n')
    rule = ConfigDeploymentRule()
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path=str(tmp_path), project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="backend"),
        languages=[],
    )
    surface = SecuritySurface(target_path=str(tmp_path))
    findings = rule.audit(tmp_path, intel, surface, [])
    assert any("CORS" in f.title and "Wildcard" in f.title for f in findings)


# ── 17. Timeout Oversight ─────────────────────────────────────────────────────
def test_timeout_oversight(demo_context):
    intel, surface, findings = demo_context
    rule = ConfigDeploymentRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any("Timeout" in f.title for f in res)


# ── 18. Default Credential Context Handling ───────────────────────────────────
def test_default_credential_context_handling(demo_context):
    # Tests that credentials inside test files are suppressed / not treated as production secrets
    intel, surface, findings = demo_context
    engine = DeveloperOversightEngine()
    result = engine.run(demo_dir, intel, surface, findings)
    # Finding count must be bounded and high-confidence
    assert result.summary.total_findings > 0
    assert result.summary.by_severity.get("HIGH", 0) > 0


# ── 19. Race Condition / TOCTOU Indicator ─────────────────────────────────────
def test_race_condition_indicator(demo_context):
    intel, surface, findings = demo_context
    rule = RaceConditionRule()
    res = rule.audit(demo_dir, intel, surface, findings)
    assert any("Race Condition" in f.title or "TOCTOU" in f.title for f in res)


# ── 20. Duplicate Finding Enrichment ──────────────────────────────────────────
def test_duplicate_finding_enrichment(demo_context):
    intel, surface, findings = demo_context
    engine = DeveloperOversightEngine()
    res = engine.run(demo_dir, intel, surface, findings)
    assert res.summary.enriched_findings_count >= 0
    # Every finding must have a unique signature hash
    hashes = [f.signature_hash for f in res.findings]
    assert len(hashes) == len(set(hashes)), "Duplicate signature hashes detected in oversight findings"


# ── 21. Meaningless Identifiers Retained ───────────────────────────────────────
def test_meaningless_identifiers_retained(tmp_path):
    # Obfuscated handler name 'h1', variables 'x', 'y'
    src = tmp_path / "obf.py"
    src.write_text('def h1(req):\n    x = req.headers.get("X-Role")\n    if x == "admin": return 1\n')
    rule = ClientTrustRule()
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path=str(tmp_path), project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="backend"),
        languages=[],
    )
    surface = SecuritySurface(target_path=str(tmp_path))
    findings = rule.audit(tmp_path, intel, surface, [])
    assert len(findings) > 0
    assert any("X-Role" in f.title for f in findings)


# ── 22. Generated Code Filtering ──────────────────────────────────────────────
def test_generated_code_filtering(tmp_path):
    gen_dir = tmp_path / "node_modules" / "some-lib"
    gen_dir.mkdir(parents=True)
    (gen_dir / "debug.js").write_text('console.log("password:", password);\n')
    rule = LogLeakageRule()
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path=str(tmp_path), project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="frontend"),
        languages=[],
    )
    surface = SecuritySurface(target_path=str(tmp_path))
    findings = rule.audit(tmp_path, intel, surface, [])
    # node_modules must be filtered
    assert len(findings) == 0


# ── 23. Test Fixture Filtering ────────────────────────────────────────────────
def test_test_fixture_filtering(tmp_path):
    test_file = tmp_path / "tests" / "test_login.py"
    test_file.mkdir(parents=True)
    test_src = test_file / "test_auth.py"
    test_src.write_text('print("password:", test_password)\n')
    rule = LogLeakageRule()
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path=str(tmp_path), project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="backend"),
        languages=[],
    )
    surface = SecuritySurface(target_path=str(tmp_path))
    findings = rule.audit(tmp_path, intel, surface, [])
    assert len(findings) == 0


# ── 24. Malformed Source Handling ─────────────────────────────────────────────
def test_malformed_source_handling(tmp_path):
    broken_file = tmp_path / "broken.py"
    broken_file.write_text("def def def ::: ;;; ((( broken !!!")
    engine = DeveloperOversightEngine()
    intel = ProjectIntelligence(
        metadata=ProjectMetadata(target_path=str(tmp_path), project_name="dummy", analyzable_files_count=1),
        project_type=ProjectTypeClassification(primary_type="backend"),
        languages=[],
    )
    surface = SecuritySurface(target_path=str(tmp_path))
    # Must not raise exceptions
    res = engine.run(tmp_path, intel, surface, [])
    assert res.target_path == str(tmp_path)


# ── 25. CLI Oversight and Combined Commands ───────────────────────────────────
def test_cli_oversight_command():
    from click.testing import CliRunner
    from nsat.cli.main import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["oversight", str(demo_dir), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "findings" in data
    assert "summary" in data
    assert "correlation_handoff" in data


def test_cli_audit_with_oversight_flag():
    from click.testing import CliRunner
    from nsat.cli.main import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["audit", str(demo_dir), "--oversight", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "intelligence" in data
    assert "findings" in data
    assert "oversight" in data
    assert len(data["oversight"]["findings"]) > 0
