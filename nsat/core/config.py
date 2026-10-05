"""Configuration management for NSAT."""

from pathlib import Path
from typing import Any, Optional
import yaml
from pydantic import BaseModel, Field


DEFAULT_IGNORE_DIRS = [
    "node_modules",
    "vendor",
    ".git",
    ".svn",
    ".hg",
    "build",
    "dist",
    "target",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".idea",
    ".vscode",
    "out",
    "bin",
    "obj",
    "nsat.egg-info",
]


class ProjectConfig(BaseModel):
    """Configuration for target project discovery."""
    ignore_dirs: list[str] = Field(default_factory=lambda: list(DEFAULT_IGNORE_DIRS))
    max_file_size_mb: int = Field(default=10, ge=1, le=100)
    follow_symlinks: bool = False


class AnalysisConfig(BaseModel):
    """Configuration for language analyzers."""
    enabled_languages: list[str] = Field(
        default_factory=lambda: ["python", "javascript", "typescript", "cpp", "rust", "go", "php", "java"]
    )
    filter_trivial_hello_world: bool = True
    suppress_vendor_code: bool = True


class ScannersConfig(BaseModel):
    """Configuration for security scanners."""
    enable_external_tools: bool = True
    enable_native_checks: bool = True
    timeout_seconds: int = 30


class AIConfig(BaseModel):
    """Configuration for optional AI reasoning layer."""
    enabled: bool = False
    provider: str = "ollama"
    endpoint: str = "http://localhost:11434"
    model: str = "qwen2.5-coder:7b"
    temperature: float = 0.1


class NSATConfig(BaseModel):
    """Root configuration model for NSAT."""
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    ai: AIConfig = Field(default_factory=AIConfig)

    @classmethod
    def load(cls, config_path: Optional[Path] = None, target_dir: Optional[Path] = None) -> "NSATConfig":
        """
        Load configuration from a specific path, target directory, or user home directory.
        Falls back to safe defaults if no file is found or file is invalid.
        """
        candidate_paths: list[Path] = []
        if config_path:
            candidate_paths.append(config_path)
        if target_dir:
            candidate_paths.extend([
                target_dir / "nsat.yaml",
                target_dir / "nsat.yml",
                target_dir / "nsat.toml",
            ])
        candidate_paths.extend([
            Path.cwd() / "nsat.yaml",
            Path.cwd() / "nsat.yml",
            Path.home() / ".nsat" / "config.yaml",
        ])

        for path in candidate_paths:
            if path.is_file():
                try:
                    content = path.read_text(encoding="utf-8")
                    data = yaml.safe_load(content) or {}
                    return cls(**data)
                except Exception:
                    # Fall back gracefully to next candidate or default
                    pass

        return cls()
