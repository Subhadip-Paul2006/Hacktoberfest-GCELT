"""Base class and common contracts for all language analyzers in NSAT."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any
from nsat.core.models import (
    AuthIndicator,
    DatabaseComponent,
    EntryPoint,
    FrameworkEvidence,
    NetworkComponent,
    SecurityRelevantOperation,
)


class LanguageAnalyzer(ABC):
    """
    Abstract interface for language-specific structural and AST analysis.
    Decouples language syntax parsing from core discovery and correlation engines.
    """

    @property
    @abstractmethod
    def language_name(self) -> str:
        """Name of the supported language (e.g. 'python', 'javascript', 'typescript', 'java', 'cpp')."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> set[str]:
        """Set of file extensions associated with this language."""
        pass

    @abstractmethod
    def detect(self, file_path: Path, content: str) -> float:
        """
        Return confidence score (0.0 to 1.0) that the file belongs to this language.
        """
        pass

    @abstractmethod
    def extract_structure(self, file_path: Path, content: str) -> dict[str, Any]:
        """
        Extract structural artifacts (entry points, routes, sinks, bindings)
        using AST or syntactic parsing without relying on identifier names.
        """
        pass

    @abstractmethod
    def extract_frameworks(self, file_path: Path, content: str) -> list[FrameworkEvidence]:
        """Extract framework evidence based on imports, annotations, and structural calls."""
        pass

    @abstractmethod
    def extract_entry_points(self, file_path: Path, content: str) -> list[EntryPoint]:
        """Extract application entry points, HTTP route handlers, and CLI commands."""
        pass

    @abstractmethod
    def extract_network_operations(self, file_path: Path, content: str) -> list[NetworkComponent]:
        """Extract socket bindings, server listeners, and HTTP client invocations."""
        pass

    @abstractmethod
    def extract_database_components(self, file_path: Path, content: str) -> list[DatabaseComponent]:
        """Extract database queries, ORM models, and query execution sinks."""
        pass

    @abstractmethod
    def extract_auth_indicators(self, file_path: Path, content: str) -> list[AuthIndicator]:
        """Extract authentication controls, password hashing, and token handlers."""
        pass

    @abstractmethod
    def extract_security_operations(self, file_path: Path, content: str) -> list[SecurityRelevantOperation]:
        """Extract dangerous execution sinks (shell, eval, raw queries, unsafe memory buffers)."""
        pass
