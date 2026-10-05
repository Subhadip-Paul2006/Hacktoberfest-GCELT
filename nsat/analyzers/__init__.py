"""Language analyzer package for NSAT."""

from nsat.analyzers.base import LanguageAnalyzer
from nsat.analyzers.python_analyzer import PythonAnalyzer
from nsat.analyzers.javascript_typescript_analyzer import JavaScriptTypeScriptAnalyzer
from nsat.analyzers.cpp_analyzer import CppAnalyzer
from nsat.analyzers.rust_analyzer import RustAnalyzer
from nsat.analyzers.go_analyzer import GoAnalyzer
from nsat.analyzers.php_analyzer import PhpAnalyzer
from nsat.analyzers.java_analyzer import JavaAnalyzer


def get_default_analyzers() -> list[LanguageAnalyzer]:
    """
    Returns the core language analyzers required for NSAT.
    MVP includes: C++, Python, Rust, Go, PHP, JavaScript/TypeScript,
    plus Java as a backward-compatible analyzer.
    """
    return [
        PythonAnalyzer(),
        JavaScriptTypeScriptAnalyzer(),
        CppAnalyzer(),
        RustAnalyzer(),
        GoAnalyzer(),
        PhpAnalyzer(),
        JavaAnalyzer(),
    ]


__all__ = [
    "LanguageAnalyzer",
    "PythonAnalyzer",
    "JavaScriptTypeScriptAnalyzer",
    "CppAnalyzer",
    "RustAnalyzer",
    "GoAnalyzer",
    "PhpAnalyzer",
    "JavaAnalyzer",
    "get_default_analyzers",
]
