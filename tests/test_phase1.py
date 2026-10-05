"""Phase 1 test suite for NSAT."""

from pathlib import Path
import pytest
from click.testing import CliRunner
from nsat import __version__
from nsat.cli.main import cli
from nsat.core.capability import CapabilityRegistry
from nsat.core.config import NSATConfig
from nsat.core.discovery import DiscoveryEngine
from nsat.core.models import ProjectIntelligence
from nsat.core.relevance import RelevanceFilter

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def runner():
    return CliRunner()


def test_cli_version(runner):
    """Test --version returns correct version."""
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_help(runner):
    """Test --help returns all registered commands."""
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "audit" in result.output
    assert "doctor" in result.output
    assert "network" in result.output
    assert "host" in result.output
    assert "explain" in result.output
    assert "fix" in result.output
    assert "verify" in result.output


def test_cli_doctor(runner):
    """Test nsat doctor command."""
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "NSAT Doctor" in result.output
    assert "Python Analyzer" in result.output
    assert "C++ Analyzer" in result.output
    assert "Java Analyzer" in result.output
    assert "JavaScript/TypeScript Analyzer" in result.output


def test_python_project_detection():
    """Test discovery on sample-python fixture."""
    path = FIXTURES_DIR / "sample-python"
    engine = DiscoveryEngine()
    intel = engine.discover(path)

    assert any(l.language == "python" for l in intel.languages)
    assert any(f.name == "FastAPI" for f in intel.frameworks)
    assert "REST API" in intel.project_type.primary_type
    assert len(intel.dependencies) >= 1
    # Check that meaningless identifier `handler2(x1)` was detected as an HTTP route
    assert any(ep.entry_type == "http_route" for ep in intel.entry_points)
    # Check that meaningless identifier `a(x)` was detected as a security-sensitive subprocess call
    assert any(op.operation_type == "process_execution" for op in intel.security_relevant_operations)


def test_java_project_detection():
    """Test discovery on sample-java fixture."""
    path = FIXTURES_DIR / "sample-java"
    engine = DiscoveryEngine()
    intel = engine.discover(path)

    assert any(l.language == "java" for l in intel.languages)
    assert any("Spring" in f.name for f in intel.frameworks)
    assert any(ep.entry_type == "main" for ep in intel.entry_points)
    assert any(ep.entry_type == "http_route" for ep in intel.entry_points)
    assert any(op.operation_type == "process_execution" for op in intel.security_relevant_operations)


def test_cpp_project_detection():
    """Test discovery on sample-cpp fixture."""
    path = FIXTURES_DIR / "sample-cpp"
    engine = DiscoveryEngine()
    intel = engine.discover(path)

    assert any(l.language == "cpp" for l in intel.languages)
    assert any("Crow" in f.name for f in intel.frameworks)
    assert any(ep.entry_type == "main" for ep in intel.entry_points)
    assert any(ep.entry_type == "http_route" for ep in intel.entry_points)
    assert any(op.operation_type == "process_execution" for op in intel.security_relevant_operations)


def test_js_ts_project_detection():
    """Test discovery on sample-js-ts fixture."""
    path = FIXTURES_DIR / "sample-js-ts"
    engine = DiscoveryEngine()
    intel = engine.discover(path)

    assert any(l.language == "javascript_typescript" for l in intel.languages)
    assert any(f.name == "React" for f in intel.frameworks)
    assert any(f.name == "Express" for f in intel.frameworks)
    assert "Web Application" in intel.project_type.primary_type
    assert any(ep.entry_type == "http_route" for ep in intel.entry_points)
    assert any(op.operation_type == "process_execution" for op in intel.security_relevant_operations)


def test_mixed_language_repository():
    """Test discovery on mixed repository containing Python + TS + C++."""
    path = FIXTURES_DIR / "sample-mixed"
    engine = DiscoveryEngine()
    intel = engine.discover(path)

    detected = {l.language for l in intel.languages}
    assert "python" in detected
    assert "javascript_typescript" in detected
    assert "cpp" in detected
    assert len(intel.languages) == 3


def test_trivial_hello_world_filtering():
    """Test that trivial single-print Hello World code is deprioritized."""
    path = FIXTURES_DIR / "sample-trivial"
    engine = DiscoveryEngine()
    intel = engine.discover(path)

    # The trivial print("Hello World") file should be filtered
    assert intel.metadata.analyzable_files_count == 0


def test_meaningless_identifiers_retained():
    """Test that code with meaningless identifiers but dangerous operations is retained."""
    content = """
def a(x):
    import subprocess
    return subprocess.run(x)
"""
    is_rel, reason = RelevanceFilter.assess_content(Path("dummy.py"), content)
    assert is_rel is True
    assert reason == "security_relevant_structure"


def test_malformed_syntax_graceful_handling():
    """Test that syntax errors in source files do not crash the engine."""
    path = FIXTURES_DIR / "sample-malformed"
    engine = DiscoveryEngine()
    intel = engine.discover(path)

    assert any(l.language == "python" for l in intel.languages)
    assert intel.metadata.analyzable_files_count == 1


def test_nonexistent_path(runner):
    """Test CLI error handling on nonexistent path."""
    result = runner.invoke(cli, ["audit", "/nonexistent/test/path"])
    assert result.exit_code != 0
    assert "does not exist" in result.output


def test_project_intelligence_serializable():
    """Test that ProjectIntelligence model is valid and JSON serializable."""
    path = FIXTURES_DIR / "sample-python"
    engine = DiscoveryEngine()
    intel = engine.discover(path)

    json_str = intel.model_dump_json()
    assert isinstance(json_str, str)
    assert "FastAPI" in json_str

    # Test roundtrip parsing
    reconstructed = ProjectIntelligence.model_validate_json(json_str)
    assert reconstructed.metadata.project_name == intel.metadata.project_name


def test_placeholder_commands(runner):
    """Test that Phase 2/3 placeholder commands give clean informative message."""
    for cmd in ["network", "host", "monitor", "report", "explain", "fix", "verify"]:
        res = runner.invoke(cli, [cmd])
        assert res.exit_code == 0
        assert "Not implemented in current phase" in res.output
