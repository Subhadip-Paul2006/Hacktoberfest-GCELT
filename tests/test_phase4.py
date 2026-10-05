"""Phase 4A Test Suite — Correlation, Risk Engine, Attack Graph & Reporting for NSAT."""

import json
from pathlib import Path
import tempfile
import pytest
from click.testing import CliRunner

from nsat.cli.main import cli
from nsat.core.config import NSATConfig
from nsat.core.discovery import DiscoveryEngine
from nsat.core.orchestrator import Phase2Orchestrator
from nsat.core.surface import (
    ApplicationSurface,
    CodeSecuritySurface,
    DataSecuritySurface,
    Endpoint,
    InfrastructureSurface,
    NetworkBinding,
    SecretLocation,
    SecuritySurface,
)
from nsat.correlation.blast_radius import BlastRadiusEngine
from nsat.correlation.engine import CorrelationEngine
from nsat.correlation.graph import AttackSurfaceGraphBuilder
from nsat.correlation.location import SourceLocationResolver
from nsat.correlation.models import (
    AttackPath,
    BlastRadiusReport,
    FindingRelationship,
    Phase4Input,
    Phase4SecurityModel,
    PrimaryLocation,
    RelationshipType,
    RiskAssessment,
)
from nsat.correlation.risk import RiskEngine
from nsat.correlation.rules import CorrelationRuleEngine
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.reporting.json_exporter import export_json_report, export_json_str
from nsat.reporting.manager import ReportManager
from nsat.reporting.markdown_exporter import export_markdown_report
from nsat.reporting.terminal import print_terminal_report

DEMO_PATH = Path(__file__).parent.parent / "demo-vuln-app"


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sample_findings():
    f1 = CanonicalFinding(
        id="NSAT-PY-SQLI",
        title="SQL Injection in Database Query Handler",
        category="code_sast",
        severity="CRITICAL",
        confidence=0.95,
        source="nsat_native",
        asset="src/api/handlers.py",
        file_path="src/api/handlers.py",
        line_number=40,
        endpoint="GET /search",
        description="Unsanitized user input formatted directly into cursor.execute() query sink.",
        impact="Direct database exfiltration and arbitrary SQL query execution.",
        recommendation="Use parameterized query with placeholder bindings.",
        evidence=[
            FindingEvidence(
                type="AST_SINK",
                description="Call to cursor.execute() with string interpolation",
                snippet='cur.execute(f"SELECT * FROM users WHERE name = \'{x1}\'")',
                line_number=40,
            )
        ],
    )
    f2 = CanonicalFinding(
        id="NSAT-SEC-001",
        title="Hardcoded Database Password",
        category="secret",
        severity="HIGH",
        confidence=0.90,
        source="secret_scanner",
        asset="config/default.env",
        file_path="config/default.env",
        line_number=8,
        description="High-entropy database password exposed in plaintext configuration file.",
        impact="Unauthorized persistent access to application datastore.",
        recommendation="Migrate credentials to external secrets manager.",
        evidence=[
            FindingEvidence(
                type="RAW_SECRET",
                description="Database password assignment",
                snippet="DB_PASSWORD=secret_postgres_pass_9988",
                line_number=8,
            )
        ],
    )
    f3 = CanonicalFinding(
        id="NSAT-CONT-002",
        title="Mounted Host Docker Daemon Socket",
        category="container",
        severity="CRITICAL",
        confidence=0.95,
        source="container_scanner",
        asset="Dockerfile",
        file_path="Dockerfile",
        line_number=12,
        description="Container specification mounts /var/run/docker.sock allowing host control.",
        impact="Catastrophic container breakout to host root execution context.",
        recommendation="Remove /var/run/docker.sock mount from container specification.",
        evidence=[
            FindingEvidence(
                type="CONTAINER_CONFIG",
                description="Docker socket mount volume directive",
                snippet="VOLUME /var/run/docker.sock:/var/run/docker.sock",
                line_number=12,
            )
        ],
    )
    f4 = CanonicalFinding(
        id="NSAT-PY-CMDI",
        title="Command Injection via Unsanitized Subprocess Execution",
        category="code_sast",
        severity="CRITICAL",
        confidence=0.95,
        source="nsat_native",
        asset="src/api/handlers.py",
        file_path="src/api/handlers.py",
        line_number=52,
        endpoint="POST /run",
        description="Untrusted user input passed into subprocess.run with shell=True.",
        impact="Arbitrary remote code execution within application container.",
        recommendation="Pass arguments as safe sequence and avoid shell=True.",
        evidence=[
            FindingEvidence(
                type="AST_SINK",
                description="Call to subprocess.run(cmd, shell=True)",
                snippet="subprocess.run(cmd, shell=True, capture_output=True)",
                line_number=52,
            )
        ],
    )
    f5 = CanonicalFinding(
        id="NSAT-URL-LEAK-001",
        title="Sensitive OTP Transmitted in URL",
        category="web_security",
        severity="HIGH",
        confidence=0.85,
        source="developer_oversight",
        asset="src/api/handlers.py",
        file_path="src/api/handlers.py",
        line_number=117,
        endpoint="GET /verify-otp",
        description="Authentication-sensitive OTP passed through URL query parameter.",
        impact="Credentials leak into access logs, web proxies, and browser history.",
        recommendation="Transmit OTP in secure request body.",
        evidence=[
            FindingEvidence(
                type="URL_LEAKAGE",
                description="Sensitive OTP parameter in GET route",
                snippet='async def verify_otp(otp: str, user_id: int):',
                line_number=117,
            )
        ],
    )
    f6 = CanonicalFinding(
        id="NSAT-AUTH-008",
        title="Missing Rate Limiting on Authentication Endpoint",
        category="authentication",
        severity="MEDIUM",
        confidence=0.80,
        source="nsat_native",
        asset="src/api/handlers.py",
        file_path="src/api/handlers.py",
        line_number=58,
        endpoint="POST /api/v1/login",
        description="Login endpoint lacks rate limiting, lockout, or brute-force throttling.",
        impact="Automated credential stuffing and dictionary attacks against user accounts.",
        recommendation="Implement IP rate limiting middleware.",
        evidence=[
            FindingEvidence(
                type="AUTH_ABUSE",
                description="No rate limit decorator on login route",
                snippet='async def login(request: Request):',
                line_number=58,
            )
        ],
    )
    f7 = CanonicalFinding(
        id="NSAT-LOGIC-001",
        title="Client-Controlled Price & Unverified Payment Status",
        category="web_security",
        severity="HIGH",
        confidence=0.85,
        source="developer_oversight",
        asset="src/api/handlers.py",
        file_path="src/api/handlers.py",
        line_number=92,
        endpoint="POST /api/v1/checkout",
        description="Payment endpoint accepts client-submitted price and payment status.",
        impact="Attackers can purchase items at arbitrary prices without verification.",
        recommendation="Enforce server-side price lookup.",
        evidence=[
            FindingEvidence(
                type="CLIENT_TRUST",
                description="Trusts client amount",
                snippet='amount = data.get("price") or 100.0',
                line_number=92,
            )
        ],
    )
    f8 = CanonicalFinding(
        id="NSAT-LOGIC-002",
        title="Premature Order Confirmation Without Payment Verification",
        category="web_security",
        severity="HIGH",
        confidence=0.85,
        source="developer_oversight",
        asset="src/api/handlers.py",
        file_path="src/api/handlers.py",
        line_number=82,
        endpoint="POST /api/v1/order/confirm",
        description="Confirms order without verifying payment gateway state.",
        impact="Unpaid orders transitioned to completed state.",
        recommendation="Require verified payment webhook before confirmation.",
        evidence=[
            FindingEvidence(
                type="STATE_TRANSITION",
                description="Direct completion",
                snippet='return {"status": "completed", "order_id": order_id}',
                line_number=82,
            )
        ],
    )
    f9 = CanonicalFinding(
        id="NSAT-NET-001",
        title="Network Listener Bound to Wildcard Address (0.0.0.0)",
        category="network_exposure",
        severity="MEDIUM",
        confidence=0.90,
        source="network_scanner",
        asset="server.py",
        file_path="server.py",
        line_number=10,
        port=8000,
        binding_address="0.0.0.0",
        description="Server listening on 0.0.0.0 exposing application to LAN and public network.",
        impact="Unrestricted network exposure to external interfaces.",
        recommendation="Bind to 127.0.0.1 for local services.",
        evidence=[
            FindingEvidence(
                type="NETWORK_BINDING",
                description="Wildcard socket bind",
                snippet='uvicorn.run(app, host="0.0.0.0", port=8000)',
                line_number=10,
            )
        ],
    )
    return [f1, f2, f3, f4, f5, f6, f7, f8, f9]


@pytest.fixture
def sample_surface():
    return SecuritySurface(
        target_path="demo-vuln-app",
        application=ApplicationSurface(
            endpoints=[
                Endpoint(path="/search", method="GET", handler="handler2", file_path="src/api/handlers.py", line_number=36),
                Endpoint(path="/run", method="POST", handler="run_task", file_path="src/api/handlers.py", line_number=48),
                Endpoint(path="/api/v1/login", method="POST", handler="login", file_path="src/api/handlers.py", line_number=58),
                Endpoint(path="/verify-otp", method="GET", handler="verify_otp", file_path="src/api/handlers.py", line_number=117),
                Endpoint(path="/api/v1/checkout", method="POST", handler="checkout", file_path="src/api/handlers.py", line_number=89),
                Endpoint(path="/api/v1/order/confirm", method="POST", handler="order_confirm", file_path="src/api/handlers.py", line_number=80),
            ]
        ),
        code=CodeSecuritySurface(),
        infrastructure=InfrastructureSurface(
            bindings=[
                NetworkBinding(host="0.0.0.0", port=8000, exposure="PUBLIC_WILDCARD", file_path="server.py", line_number=10)
            ],
            docker_present=True,
        ),
        data=DataSecuritySurface(
            secrets=[
                SecretLocation(secret_type="password", redacted_value="***REDACTED***", file_path="config/default.env", line_number=8)
            ]
        ),
    )


# =============================================================================
# 1. Finding Correlation
# =============================================================================

def test_finding_correlation(sample_findings, sample_surface):
    """Test deterministic correlation identifies multi-vector relationships."""
    rels, paths = CorrelationRuleEngine.correlate(sample_findings, sample_surface)
    assert len(rels) >= 4
    assert len(paths) >= 3

    # Check SQLi + DB Secret correlation
    db_rels = [r for r in rels if r.source_id == "NSAT-SEC-001" and r.target_id == "NSAT-PY-SQLI"]
    assert len(db_rels) == 1
    assert db_rels[0].relation_type == RelationshipType.CONTRIBUTES_TO


# =============================================================================
# 2. Related Finding Creation
# =============================================================================

def test_related_finding_creation(sample_findings, sample_surface):
    """Test related finding links with correct relationship types."""
    rels, paths = CorrelationRuleEngine.correlate(sample_findings, sample_surface)

    types = {r.relation_type for r in rels}
    assert RelationshipType.CONTRIBUTES_TO in types
    assert RelationshipType.AMPLIFIES in types
    assert RelationshipType.RELATED in types

    # Check finding attributes updated
    sqli = next(f for f in sample_findings if f.id == "NSAT-PY-SQLI")
    assert any("NSAT-SEC-001" in rf for rf in sqli.related_findings)


# =============================================================================
# 3. Attack Path Generation
# =============================================================================

def test_attack_path_generation(sample_findings, sample_surface):
    """Test synthesis of human-readable attack paths."""
    _, paths = CorrelationRuleEngine.correlate(sample_findings, sample_surface)

    titles = [p.title for p in paths]
    assert any("Database" in t for t in titles)
    assert any("Container Breakout" in t for t in titles)
    assert any("Financial" in t or "Order" in t for t in titles)

    for p in paths:
        assert len(p.steps) >= 3
        assert p.severity in ("CRITICAL", "HIGH", "MEDIUM")
        assert p.impact != ""
        assert p.recommendation != ""
        assert p.path_type in ("Potential attack path", "Validated exposure path", "Post-compromise path")


# =============================================================================
# 4. Risk Scoring
# =============================================================================

def test_risk_scoring(sample_findings, sample_surface):
    """Test deterministic risk scoring per finding and overall system score."""
    br = BlastRadiusEngine.evaluate(sample_findings, sample_surface)
    _, paths = CorrelationRuleEngine.correlate(sample_findings, sample_surface)
    scored, assessment = RiskEngine.evaluate(sample_findings, br, paths, sample_surface)

    assert 0 <= assessment.overall_score <= 100
    assert assessment.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    # High severity / critical findings should score higher
    sqli = next(f for f in scored if f.id == "NSAT-PY-SQLI")
    rl = next(f for f in scored if f.id == "NSAT-AUTH-008")
    assert (sqli.risk_score or 0) > (rl.risk_score or 0)


# =============================================================================
# 5. Priority Classification (P0, P1, P2, P3)
# =============================================================================

def test_priority_classification(sample_findings, sample_surface):
    """Test remediation priorities are accurately assigned."""
    br = BlastRadiusEngine.evaluate(sample_findings, sample_surface)
    _, paths = CorrelationRuleEngine.correlate(sample_findings, sample_surface)
    scored, assessment = RiskEngine.evaluate(sample_findings, br, paths, sample_surface)

    priorities = {f.priority for f in scored}
    assert "P0" in priorities or "P1" in priorities
    assert assessment.priority_distribution["P0"] + assessment.priority_distribution["P1"] > 0


# =============================================================================
# 6. File / Line Selection
# =============================================================================

def test_file_line_selection(sample_findings):
    """Test source location extraction returns file and line correctly."""
    sqli = sample_findings[0]
    loc = SourceLocationResolver.resolve_location(sqli, target_path=DEMO_PATH)
    assert loc.file_path == "src/api/handlers.py"
    assert loc.line_number == 40


# =============================================================================
# 7. Function Resolution via AST
# =============================================================================

def test_function_resolution():
    """Test Python AST resolves exact function name enclosing line."""
    f = CanonicalFinding(
        id="TEST-01",
        title="Test",
        category="code_sast",
        severity="HIGH",
        confidence=0.9,
        source="test",
        asset="src/api/handlers.py",
        file_path="src/api/handlers.py",
        line_number=40,
        description="test",
        impact="test",
        recommendation="test",
    )
    loc = SourceLocationResolver.resolve_location(f, target_path=DEMO_PATH)
    assert loc.function_name == "handler2"


# =============================================================================
# 8. Evidence Aggregation
# =============================================================================

def test_evidence_aggregation():
    """Test CorrelationEngine preserves evidence from multiple phases."""
    f_p2 = CanonicalFinding(
        id="NSAT-01",
        title="SQL Injection",
        category="code_sast",
        severity="CRITICAL",
        confidence=0.8,
        source="nsat_native",
        asset="src/api/handlers.py",
        file_path="src/api/handlers.py",
        line_number=40,
        description="test",
        impact="test",
        recommendation="test",
        evidence=[FindingEvidence(type="AST_SINK", description="Static AST call")],
    )
    f_p3 = CanonicalFinding(
        id="NSAT-01",
        title="SQL Injection",
        category="code_sast",
        severity="CRITICAL",
        confidence=0.95,
        source="active_swarm",
        asset="src/api/handlers.py",
        file_path="src/api/handlers.py",
        line_number=40,
        status="VALIDATED",
        description="test",
        impact="test",
        recommendation="test",
        evidence=[FindingEvidence(type="ACTIVE_VALIDATION", description="Probe returned 200")],
    )

    merged = CorrelationEngine._deduplicate_and_merge([f_p2, f_p3])
    assert len(merged) == 1
    assert len(merged[0].evidence) == 2
    assert "active_swarm" in merged[0].sources
    assert "nsat_native" in merged[0].sources
    assert merged[0].status == "VALIDATED"


# =============================================================================
# 9. Deduplication
# =============================================================================

def test_deduplication():
    """Test deduplication merges identical findings across tools."""
    f1 = CanonicalFinding(
        id="F-1",
        title="Hardcoded Secret",
        category="secret",
        severity="HIGH",
        confidence=0.85,
        source="scanner_a",
        asset="config/default.env",
        file_path="config/default.env",
        line_number=8,
        description="secret",
        impact="test",
        recommendation="test",
    )
    f2 = CanonicalFinding(
        id="F-2",
        title="Hardcoded Secret",
        category="secret",
        severity="HIGH",
        confidence=0.90,
        source="scanner_b",
        asset="config/default.env",
        file_path="config/default.env",
        line_number=8,
        description="secret",
        impact="test",
        recommendation="test",
    )
    merged = CorrelationEngine._deduplicate_and_merge([f1, f2])
    assert len(merged) == 1
    assert set(merged[0].sources) == {"scanner_a", "scanner_b"}
    assert merged[0].confidence == 0.90


# =============================================================================
# 10. Validated Finding State
# =============================================================================

def test_validated_finding_state():
    """Test validated findings retain VALIDATED status and receive risk score bonus."""
    f = CanonicalFinding(
        id="NSAT-VAL",
        title="Admin Bypass",
        category="authentication",
        severity="HIGH",
        confidence=0.9,
        source="test",
        asset="src/api/handlers.py",
        status="VALIDATED",
        description="test",
        impact="test",
        recommendation="test",
    )
    br = BlastRadiusReport()
    scored, _ = RiskEngine.evaluate([f], br, [])
    assert scored[0].status == "VALIDATED"
    # Should receive +15 validation bonus
    assert (scored[0].risk_score or 0) >= 45.0


# =============================================================================
# 11. Blast Radius Integration
# =============================================================================

def test_blast_radius_integration(sample_findings, sample_surface):
    """Test blast radius categorizes Docker socket mount as Tier 3."""
    br = BlastRadiusEngine.evaluate(sample_findings, sample_surface)
    assert br.tier_level == 3
    assert "TIER 3" in br.tier
    assert any("docker.sock" in a.lower() for a in br.accessible_assets)


# =============================================================================
# 12. JSON Output Structure
# =============================================================================

def test_json_output_structure(sample_findings, sample_surface):
    """Test JSON export matches required schema: summary, risk, findings, attack_paths, graph, coverage, limitations."""
    p4_in = Phase4Input.from_orchestration(
        target_path=str(DEMO_PATH),
        surface=sample_surface,
        phase2_findings=sample_findings,
    )
    model = CorrelationEngine.run(p4_in)
    data = export_json_report(model)

    required_keys = ["summary", "risk", "findings", "attack_paths", "graph", "coverage", "limitations"]
    for k in required_keys:
        assert k in data, f"Missing required top-level JSON key: {k}"

    assert isinstance(data["findings"], list)
    assert isinstance(data["attack_paths"], list)
    assert isinstance(data["risk"], dict)


# =============================================================================
# 13. Markdown Report
# =============================================================================

def test_markdown_report(sample_findings, sample_surface):
    """Test Markdown report generator produces formatted document with all sections."""
    p4_in = Phase4Input.from_orchestration(
        target_path=str(DEMO_PATH),
        surface=sample_surface,
        phase2_findings=sample_findings,
    )
    model = CorrelationEngine.run(p4_in)
    md = export_markdown_report(model)

    assert "# NSAT Security Audit & Threat Assessment Report" in md
    assert "## 1. Executive Security Summary" in md
    assert "## 2. Overall Risk Score" in md
    assert "## 4. Correlated Attack Paths" in md
    assert "## 5. Detailed Security Findings" in md
    assert "## 9. Post-Compromise Blast Radius" in md
    assert "## 11. Coverage" in md
    assert "## 12. Blind Spots & Limitations" in md


# =============================================================================
# 14. Terminal Report
# =============================================================================

def test_terminal_report(sample_findings, sample_surface):
    """Test print_terminal_report executes without error."""
    p4_in = Phase4Input.from_orchestration(
        target_path=str(DEMO_PATH),
        surface=sample_surface,
        phase2_findings=sample_findings,
    )
    model = CorrelationEngine.run(p4_in)
    # Execute terminal printer
    print_terminal_report(model)


# =============================================================================
# 15. Coverage Reporting
# =============================================================================

def test_coverage_reporting(sample_findings, sample_surface):
    """Test coverage report lists analyzed languages and security domains."""
    p4_in = Phase4Input.from_orchestration(
        target_path=str(DEMO_PATH),
        surface=sample_surface,
        phase2_findings=sample_findings,
    )
    model = CorrelationEngine.run(p4_in)
    cov = model.coverage
    assert len(cov.languages) >= 4
    assert len(cov.security_domains) >= 8
    assert "Source Code (SAST)" in cov.security_domains
    assert "Container Security & Dockerfile" in cov.security_domains


# =============================================================================
# 16. Limitations and Blind Spots
# =============================================================================

def test_limitations_and_blind_spots(sample_findings, sample_surface):
    """Test limitations report contains known boundaries and deferred features."""
    p4_in = Phase4Input.from_orchestration(
        target_path=str(DEMO_PATH),
        surface=sample_surface,
        phase2_findings=sample_findings,
    )
    model = CorrelationEngine.run(p4_in)
    lim = model.limitations
    assert len(lim.known_blind_spots) >= 3
    assert any("kernel" in bs.lower() for bs in lim.known_blind_spots)
    assert any("Not implemented in current phase" in df for df in lim.deferred_features)


# =============================================================================
# 17. Missing Location Handling
# =============================================================================

def test_missing_location_handling():
    """Test graceful handling when function or class cannot be reliably resolved."""
    f = CanonicalFinding(
        id="NONEXISTENT",
        title="Unknown File Finding",
        category="code_sast",
        severity="LOW",
        confidence=0.5,
        source="test",
        asset="nonexistent/fake_path.py",
        file_path="nonexistent/fake_path.py",
        line_number=999,
        description="test",
        impact="test",
        recommendation="test",
    )
    loc = SourceLocationResolver.resolve_location(f)
    assert loc.function_name == "Not reliably resolved"
    assert loc.class_name == "Not reliably resolved"


# =============================================================================
# 18. Redaction of Sensitive Data
# =============================================================================

def test_redaction_of_sensitive_data():
    """Test that passwords and cloud keys in snippets are sanitized."""
    ev = FindingEvidence(
        type="RAW_SECRET",
        description="AWS Key leaked: AKIAIOSFODNN7EXAMPLE",
        snippet='password="SuperSecretPassword123"',
    )
    sanitized = CorrelationEngine._sanitize_evidence(ev)
    assert "SuperSecretPassword123" not in (sanitized.snippet or "")
    assert "***REDACTED***" in (sanitized.snippet or "")
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized.description


# =============================================================================
# 19. Deterministic Risk Calculation
# =============================================================================

def test_deterministic_risk_calculation(sample_findings, sample_surface):
    """Test two runs produce identical risk scores and priority distributions."""
    br = BlastRadiusEngine.evaluate(sample_findings, sample_surface)
    _, paths = CorrelationRuleEngine.correlate(sample_findings, sample_surface)

    scored1, a1 = RiskEngine.evaluate(sample_findings, br, paths, sample_surface)
    scored2, a2 = RiskEngine.evaluate(sample_findings, br, paths, sample_surface)

    assert a1.overall_score == a2.overall_score
    assert a1.risk_level == a2.risk_level
    assert a1.priority_distribution == a2.priority_distribution
    for f1, f2 in zip(scored1, scored2):
        assert f1.risk_score == f2.risk_score
        assert f1.priority == f2.priority


# =============================================================================
# 20. Phase 4 Handoff Serialization
# =============================================================================

def test_phase4_handoff_serialization(sample_findings, sample_surface):
    """Test Phase4SecurityModel serializes and parses without loss."""
    p4_in = Phase4Input.from_orchestration(
        target_path=str(DEMO_PATH),
        surface=sample_surface,
        phase2_findings=sample_findings,
    )
    model = CorrelationEngine.run(p4_in)
    json_str = model.model_dump_json()

    reconstructed = Phase4SecurityModel.model_validate_json(json_str)
    assert len(reconstructed.findings) == len(model.findings)
    assert reconstructed.risk.overall_score == model.risk.overall_score
    assert len(reconstructed.attack_paths) == len(model.attack_paths)
    assert reconstructed.blast_radius.tier == model.blast_radius.tier


# =============================================================================
# 21. CLI Report Command Integration Tests
# =============================================================================

def test_cli_report_command(runner):
    """Test nsat report CLI command executes on demo app."""
    if not DEMO_PATH.exists():
        pytest.skip("demo-vuln-app not present")

    res = runner.invoke(cli, ["report", str(DEMO_PATH), "--no-save"])
    assert res.exit_code == 0
    assert "Executive Security Summary" in res.output
    assert "Overall Risk Score" in res.output
    assert "Correlated Attack Paths" in res.output


def test_cli_report_json_flag(runner):
    """Test nsat report --json outputs valid parseable JSON."""
    if not DEMO_PATH.exists():
        pytest.skip("demo-vuln-app not present")

    res = runner.invoke(cli, ["report", str(DEMO_PATH), "--json", "--no-save"])
    assert res.exit_code == 0
    parsed = json.loads(res.output)
    assert "findings" in parsed
    assert "risk" in parsed
    assert "attack_paths" in parsed
    assert "graph" in parsed


def test_cli_report_markdown_flag(runner):
    """Test nsat report --markdown outputs markdown report to stdout."""
    if not DEMO_PATH.exists():
        pytest.skip("demo-vuln-app not present")

    res = runner.invoke(cli, ["report", str(DEMO_PATH), "--markdown", "--no-save"])
    assert res.exit_code == 0
    assert "# NSAT Security Audit & Threat Assessment Report" in res.output
    assert "## 1. Executive Security Summary" in res.output


def test_report_saves_file(sample_findings, sample_surface):
    """Test ReportManager saves report file to reports/ directory."""
    p4_in = Phase4Input.from_orchestration(
        target_path=str(DEMO_PATH),
        surface=sample_surface,
        phase2_findings=sample_findings,
    )
    model = CorrelationEngine.run(p4_in)

    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "test-report.md"
        saved = ReportManager.generate_and_save(model, format_type="markdown", output_path=str(out_file))
        assert saved is not None
        assert saved.exists()
        assert out_file.read_text(encoding="utf-8").startswith("# NSAT Security Audit")
