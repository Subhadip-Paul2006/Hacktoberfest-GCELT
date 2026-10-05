"""Base scanner interface for NSAT security engines."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding


class BaseScanner(ABC):
    """
    Abstract interface for all NSAT security scanners.
    All scanners (native AST, secret, network, dependency, web, external)
    must implement this common contract and emit CanonicalFinding models.
    """

    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Name of the scanner (e.g. 'native_sast', 'secret_scanner', 'network_prober')."""
        pass

    @abstractmethod
    def scan(self, target_path: Path, surface: SecuritySurface) -> list[CanonicalFinding]:
        """
        Execute scan against target path using the extracted SecuritySurface.
        Returns a list of CanonicalFinding instances.
        """
        pass
