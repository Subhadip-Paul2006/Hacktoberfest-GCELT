"""Phase 4B Test Suite — GLM-5.3 AI Security Report & NSAT Chatbot.

All tests are 100% deterministic and mock external API dependencies.
"""

import json
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch
import pytest
import requests
from click.testing import CliRunner

from nsat.ai.chatbot import SecurityChatbot
from nsat.ai.config import GLMConfig
from nsat.ai.context_builder import AIContextBuilder
from nsat.ai.explainer import FindingExplainer
from nsat.ai.glm import GLMProvider
from nsat.ai.prompts import (
    AI_SECURITY_REPORT_PROMPT,
    CHATBOT_SYSTEM_PROMPT,
    FINDING_EXPLANATION_PROMPT,
    SYSTEM_PROMPT_ANALYST,
)
from nsat.ai.report_generator import AIReportGenerator
from nsat.cli.main import cli
from nsat.correlation.engine import CorrelationEngine
from nsat.correlation.models import (
    AttackPath,
    BlastRadiusReport,
    Phase4Input,
    Phase4SecurityModel,
    RiskAssessment,
)
from nsat.core.surface import (
    ApplicationSurface,
    CodeSecuritySurface,
    DataSecuritySurface,
    InfrastructureSurface,
    NetworkBinding,
    SecuritySurface,
)
from nsat.normalization.models import CanonicalFinding, FindingEvidence

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
        function_name="handler",
        endpoint="GET /search",
        description="Unsanitized user input formatted directly into cursor.execute() query sink.",
        impact="Direct database exfiltration and arbitrary SQL query execution.",
        recommendation="Use parameterized query with placeholder bindings.",
        status="VALIDATED",
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
        status="POTENTIAL",
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
        title="Docker Socket Mounted in Container",
        category="container",
        severity="CRITICAL",
        confidence=0.95,
        source="container_scanner",
        asset="Dockerfile",
        file_path="Dockerfile",
        line_number=18,
        description="Host Docker socket /var/run/docker.sock mounted into container spec.",
        impact="Complete host daemon compromise via container breakout.",
        recommendation="Remove /var/run/docker.sock socket mount.",
        status="UNVERIFIED",
        evidence=[
            FindingEvidence(
                type="VOLUME_MOUNT",
                description="Docker socket mount in Dockerfile",
                snippet="VOLUME /var/run/docker.sock",
                line_number=18,
            )
        ],
    )
    return [f1, f2, f3]


@pytest.fixture
def sample_surface():
    return SecuritySurface(
        target_path=str(DEMO_PATH),
        application=ApplicationSurface(),
        code=CodeSecuritySurface(),
        data=DataSecuritySurface(),
        infrastructure=InfrastructureSurface(
            docker_present=True,
            bindings=[
                NetworkBinding(
                    host="0.0.0.0",
                    port=8000,
                    protocol="tcp",
                    exposure="PUBLIC_WILDCARD",
                    file_path="src/main.py",
                    line_number=20,
                )
            ],
        ),
    )


@pytest.fixture
def sample_security_model(sample_findings, sample_surface):
    p4_in = Phase4Input.from_orchestration(
        target_path=str(DEMO_PATH),
        surface=sample_surface,
        phase2_findings=sample_findings,
    )
    return CorrelationEngine.run(p4_in)


# =============================================================================
# 1. GLM Configuration Loading
# =============================================================================

def test_glm_config_loading(monkeypatch):
    """Test loading configuration from environment variables."""
    monkeypatch.setenv("GLM_API_KEY", "test-glm-key-12345")
    monkeypatch.setenv("GLM_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("GLM_MODEL", "z-ai/glm-5.3")
    monkeypatch.setenv("AI_ENABLED", "true")

    cfg = GLMConfig.load()
    assert cfg.enabled is True
    assert cfg.api_key == "test-glm-key-12345"
    assert cfg.base_url == "https://api.example.com/v1"
    assert cfg.model == "z-ai/glm-5.3"
    assert cfg.is_configured() is True
    assert "test-***" in cfg.masked_api_key


# =============================================================================
# 2. Missing API Key Handling
# =============================================================================

def test_missing_api_key_handling(monkeypatch):
    """Test unconfigured state when API key is missing."""
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.delenv("GLM_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    # Empty env file
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write("AI_ENABLED=true\n")
        tf_path = Path(tf.name)

    cfg = GLMConfig.load(env_path=tf_path)
    assert cfg.is_configured() is False

    provider = GLMProvider(cfg)
    with pytest.raises(ValueError, match="GLM API key not configured"):
        provider.generate("Hello")


# =============================================================================
# 3. API Timeout Handling
# =============================================================================

def test_api_timeout_handling(monkeypatch):
    """Test timeout exception handling and retries without crashing."""
    cfg = GLMConfig(
        api_key="mock-key",
        base_url="https://api.example.com/v1",
        timeout_seconds=0.1,
        max_retries=1,
    )
    provider = GLMProvider(cfg)

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Read timed out")):
        with pytest.raises(TimeoutError, match="timed out"):
            provider.generate("test prompt")


# =============================================================================
# 4. Invalid API Response Handling
# =============================================================================

def test_invalid_api_response_handling():
    """Test empty choices or HTTP error handling in GLM provider."""
    cfg = GLMConfig(api_key="mock-key")
    provider = GLMProvider(cfg)

    # Empty choices array
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"choices": []}

    with patch("requests.post", return_value=mock_resp):
        with pytest.raises(ValueError, match="empty choices"):
            provider.generate("test prompt")

    # 401 Unauthorized
    mock_resp.status_code = 401
    mock_resp.text = "Invalid token"
    with patch("requests.post", return_value=mock_resp):
        with pytest.raises(PermissionError, match="401 Unauthorized"):
            provider.generate("test prompt")


# =============================================================================
# 5. Provider Failure Fallback
# =============================================================================

def test_provider_failure_fallback(sample_security_model, capsys):
    """Test report generation seamlessly falls back to deterministic engine on API error."""
    mock_provider = MagicMock(spec=GLMProvider)
    mock_provider.generate.side_effect = RuntimeError("503 Gateway Timeout")

    report = AIReportGenerator.generate_report(sample_security_model, provider=mock_provider)
    captured = capsys.readouterr()

    assert "[WARN] GLM provider unavailable" in captured.out
    assert "[INFO] Falling back to deterministic report" in captured.out
    assert "## 1. Executive Security Summary" in report
    assert "## 2. Risk Score & Threat Posture Interpretation" in report


# =============================================================================
# 6. Context Builder
# =============================================================================

def test_context_builder(sample_security_model):
    """Test context builder creates compact structured summary."""
    ctx = AIContextBuilder.build_report_context(sample_security_model)

    assert "project" in ctx
    assert "risk" in ctx
    assert "blast_radius" in ctx
    assert "top_findings" in ctx
    assert "attack_paths" in ctx
    assert ctx["risk"]["score"] == sample_security_model.risk.overall_score
    assert len(ctx["top_findings"]) <= 10


# =============================================================================
# 7. Secret Redaction
# =============================================================================

def test_secret_redaction(sample_security_model):
    """Test that context builder redacts sensitive plaintext credentials."""
    ctx = AIContextBuilder.build_report_context(sample_security_model)
    json_dump = json.dumps(ctx)

    assert "secret_postgres_pass_9988" not in json_dump
    assert "***REDACTED***" in json_dump


# =============================================================================
# 8. Report Prompt Generation
# =============================================================================

def test_report_prompt_generation(sample_security_model):
    """Test report prompt correctly incorporates security model metrics."""
    ctx = AIContextBuilder.build_report_context(sample_security_model)
    prompt = AI_SECURITY_REPORT_PROMPT.format(
        context_json=json.dumps(ctx, indent=2),
        risk_score=sample_security_model.risk.overall_score,
        risk_level=sample_security_model.risk.risk_level,
        blast_radius_tier=sample_security_model.blast_radius.tier,
    )

    assert "Executive Security Summary" in prompt
    assert str(sample_security_model.risk.overall_score) in prompt
    assert sample_security_model.blast_radius.tier in prompt


# =============================================================================
# 9. Finding Explanation Prompt
# =============================================================================

def test_finding_explanation_prompt(sample_security_model):
    """Test finding prompt contains exact file, line, and evidence without hallucinations."""
    finding_dict, related_ctx = AIContextBuilder.build_finding_context("NSAT-PY-SQLI", sample_security_model)
    assert finding_dict is not None
    assert finding_dict["location"]["file"] == "src/api/handlers.py"
    assert finding_dict["location"]["line"] == 40

    prompt = FINDING_EXPLANATION_PROMPT.format(
        finding_json=json.dumps(finding_dict),
        context_json=json.dumps(related_ctx),
        finding_id="NSAT-PY-SQLI",
        title="SQL Injection",
        severity="CRITICAL",
        confidence="0.95",
        status="VALIDATED",
        priority="P0",
        file_path="src/api/handlers.py",
        line_number=40,
        function_name="handler",
        class_name="Not reliably resolved",
        endpoint="GET /search",
    )
    assert "src/api/handlers.py" in prompt
    assert "GET /search" in prompt


# =============================================================================
# 10. Chatbot Context Limiting
# =============================================================================

def test_chatbot_context_limiting(sample_security_model):
    """Test finding-specific question extracts only that finding's context."""
    ctx = AIContextBuilder.build_chat_context("Tell me about NSAT-CONT-002", sample_security_model)
    assert ctx["context_type"] == "finding_focused"
    assert ctx["focused_finding"]["id"] == "NSAT-CONT-002"
    assert "Dockerfile" in str(ctx["focused_finding"])


# =============================================================================
# 11. Chatbot Conversation History
# =============================================================================

def test_chatbot_conversation_history(sample_security_model):
    """Test multi-turn conversational memory within a single session."""
    mock_provider = MagicMock(spec=GLMProvider)
    mock_provider.chat.side_effect = [
        "NSAT-AUTH-007 indicates missing rate limiting on the login endpoint.",
        "It is dangerous because attackers can perform automated credential stuffing.",
    ]

    bot = SecurityChatbot(model=sample_security_model, provider=mock_provider)
    r1 = bot.ask("Explain NSAT-AUTH-007.")
    assert "missing rate limiting" in r1
    assert len(bot.history) == 2

    r2 = bot.ask("Why is that dangerous?")
    assert "credential stuffing" in r2
    assert len(bot.history) == 4
    assert bot.history[0]["content"] == "Explain NSAT-AUTH-007."
    assert bot.history[2]["content"] == "Why is that dangerous?"


# =============================================================================
# 12. Finding-Specific Question (Deterministic & Mocked)
# =============================================================================

def test_finding_specific_question(sample_security_model):
    """Test chatbot answering finding questions deterministically without LLM."""
    bot = SecurityChatbot(model=sample_security_model, provider=None)
    ans = bot.ask("Explain finding NSAT-PY-SQLI")

    assert "Finding NSAT-PY-SQLI" in ans
    assert "CRITICAL" in ans
    assert "src/api/handlers.py" in ans


# =============================================================================
# 13. Project-Wide Question (Deterministic & Mocked)
# =============================================================================

def test_project_wide_question(sample_security_model):
    """Test chatbot answering project risk and priority questions."""
    bot = SecurityChatbot(model=sample_security_model, provider=None)

    # Why is project critical
    ans1 = bot.ask("Why is this project rated critical?")
    assert "100/100" in ans1 or "CRITICAL" in ans1
    assert "TIER 3" in ans1

    # Which file should I fix first
    ans2 = bot.ask("Which file should I fix first?")
    assert "handlers.py" in ans2
    assert "NSAT-PY-SQLI" in ans2


# =============================================================================
# 14. Evidence-Only Reasoning
# =============================================================================

def test_evidence_only_reasoning(sample_security_model):
    """Test chatbot distinguishes between validated and potential findings."""
    bot = SecurityChatbot(model=sample_security_model, provider=None)

    val_ans = bot.ask("Which findings are validated?")
    assert "NSAT-PY-SQLI" in val_ans

    pot_ans = bot.ask("Which findings are potential?")
    assert "NSAT-SEC-001" in pot_ans


# =============================================================================
# 15. Hallucination Guard
# =============================================================================

def test_hallucination_guard(sample_security_model):
    """Test explainer safely rejects non-existent finding IDs."""
    expl = FindingExplainer.explain("NSAT-FAKE-9999", sample_security_model)
    assert "[ERROR] Finding ID 'NSAT-FAKE-9999' not found" in expl


# =============================================================================
# 16. AI-Disabled Mode
# =============================================================================

def test_ai_disabled_mode(monkeypatch, sample_security_model):
    """Test system functions 100% deterministically when AI_ENABLED=false."""
    monkeypatch.setenv("AI_ENABLED", "false")
    cfg = GLMConfig.load()
    assert cfg.enabled is False
    assert cfg.is_configured() is False

    report = AIReportGenerator.generate_report(sample_security_model, provider=None)
    assert "# NSAT AI Security Assessment Report" in report
    assert "Executive Security Summary" in report


# =============================================================================
# 17. CLI Explain Command
# =============================================================================

def test_cli_explain_command(runner):
    """Test nsat explain command on demo app."""
    if not DEMO_PATH.exists():
        pytest.skip("demo-vuln-app missing")

    res = runner.invoke(cli, ["explain", "NSAT-CONT-002", str(DEMO_PATH), "--no-ai"])
    assert res.exit_code == 0
    assert "Finding Explanation -- NSAT-CONT-002" in res.output
    assert "Where:" in res.output
    assert "Dockerfile" in res.output


# =============================================================================
# 18. CLI Chat Command
# =============================================================================

def test_cli_chat_command(runner):
    """Test nsat chat --ask one-shot CLI interaction."""
    if not DEMO_PATH.exists():
        pytest.skip("demo-vuln-app missing")

    res = runner.invoke(
        cli,
        ["chat", str(DEMO_PATH), "--ask", "Which file should I fix first?"],
    )
    assert res.exit_code == 0
    assert "NSAT:" in res.output
    assert "fix" in res.output.lower()


# =============================================================================
# 19. CLI AI-Report Command
# =============================================================================

def test_cli_ai_report_command(runner):
    """Test nsat ai-report generates 6-section report."""
    if not DEMO_PATH.exists():
        pytest.skip("demo-vuln-app missing")

    res = runner.invoke(cli, ["ai-report", str(DEMO_PATH), "--no-save"])
    assert res.exit_code == 0
    assert "Executive Security Summary" in res.output
    assert "Risk Score & Threat Posture Interpretation" in res.output
    assert "Priority Findings Breakdown" in res.output


# =============================================================================
# 20. Full Audit with AI Enabled
# =============================================================================

def test_full_audit_with_ai_enabled(runner):
    """Test nsat audit with --ai displays full step checklist and analysis."""
    if not DEMO_PATH.exists():
        pytest.skip("demo-vuln-app missing")

    res = runner.invoke(cli, ["audit", str(DEMO_PATH), "--ai"])
    assert res.exit_code == 0
    assert "Project Discovery" in res.output
    assert "Static Security" in res.output
    assert "Risk Analysis" in res.output
    assert "AI Security Analysis" in res.output
    assert "Overall Risk:" in res.output
    assert "GLM-5.3 Analysis:" in res.output


# =============================================================================
# 21. SETUP Examples Remain Accurate
# =============================================================================

def test_setup_examples_remain_accurate():
    """Verify SETUP.md exists and contains user commands."""
    setup_file = Path(__file__).parent.parent / "SETUP.md"
    assert setup_file.exists()
    content = setup_file.read_text(encoding="utf-8")
    assert "nsat audit" in content
    assert "nsat explain" in content
    assert "nsat chat" in content


# =============================================================================
# 22. JSON / Markdown Deterministic Data Preserved
# =============================================================================

def test_deterministic_data_preserved_with_ai(runner):
    """Test nsat audit --ai --json outputs valid JSON without Rich markup."""
    if not DEMO_PATH.exists():
        pytest.skip("demo-vuln-app missing")

    res = runner.invoke(cli, ["audit", str(DEMO_PATH), "--ai", "--json"])
    assert res.exit_code == 0
    parsed = json.loads(res.output)
    assert "intelligence" in parsed
    assert "findings" in parsed
    assert "risk_model" in parsed
    assert parsed["risk_model"]["risk"]["overall_score"] > 0
