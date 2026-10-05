"""Configuration loader for NSAT AI layer and GLM-5.3 provider."""

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field


class GLMConfig(BaseModel):
    """Configuration for GLM-5.3 and LLM providers."""
    enabled: bool = True
    api_key: Optional[str] = None
    base_url: str = "https://integrate.api.nvidia.com/v1"
    model: str = "z-ai/glm-5.3"
    timeout_seconds: float = 30.0
    max_retries: int = 2

    @classmethod
    def load(cls, env_path: Optional[Path] = None) -> "GLMConfig":
        """
        Load configuration from environment variables and optional .env file.
        Prioritizes GLM_*, with graceful fallback to NVIDIA_* or OPENAI_* variables.
        """
        # Load local .env if present
        target_env = env_path or Path(".env")
        if target_env.is_file():
            try:
                for line in target_env.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass

        # 1. AI Enabled flag
        ai_enabled_raw = os.getenv("AI_ENABLED", "true").lower()
        enabled = ai_enabled_raw in ("true", "1", "yes", "on")

        # 2. API Key resolution (GLM_API_KEY -> NVIDIA_API_KEY -> OPENAI_API_KEY)
        api_key = (
            os.getenv("GLM_API_KEY")
            or os.getenv("NVIDIA_API_KEY")
            or os.getenv("OPENAI_API_KEY")
        )

        # 3. Base URL resolution
        base_url = (
            os.getenv("GLM_BASE_URL")
            or os.getenv("NVIDIA_BASE_URL")
            or os.getenv("OPENAI_BASE_URL")
            or "https://integrate.api.nvidia.com/v1"
        )
        base_url = base_url.rstrip("/")

        # 4. Model resolution
        model = os.getenv("GLM_MODEL") or "z-ai/glm-5.3"

        # 5. Timeout
        try:
            timeout = float(os.getenv("GLM_TIMEOUT", "30.0"))
        except ValueError:
            timeout = 30.0

        return cls(
            enabled=enabled,
            api_key=api_key,
            base_url=base_url,
            model=model,
            timeout_seconds=timeout,
            max_retries=2,
        )

    def is_configured(self) -> bool:
        """Check if AI is both enabled and possesses an API key."""
        return self.enabled and bool(self.api_key and self.api_key.strip())

    def masked_key(self) -> str:
        """Return masked key safe for logging and diagnostics."""
        if not self.api_key:
            return "<UNSET>"
        clean = self.api_key.strip()
        if len(clean) <= 8:
            return "***"
        return f"{clean[:4]}...{clean[-4:]}"

    @property
    def masked_api_key(self) -> str:
        """Return masked key for diagnostics."""
        if not self.api_key:
            return "<UNSET>"
        clean = self.api_key.strip()
        if len(clean) <= 8:
            return "***"
        return f"{clean[:5]}***{clean[-4:]}"


class KimiConfig(BaseModel):
    """Configuration for Kimi-K3 remediation model."""
    enabled: bool = True
    api_key: Optional[str] = None
    base_url: str = "https://integrate.api.nvidia.com/v1"
    model: str = "moonshotai/kimi-k3"
    timeout_seconds: float = 45.0
    max_retries: int = 2

    @classmethod
    def load(cls, env_path: Optional[Path] = None) -> "KimiConfig":
        """
        Load configuration from environment variables and optional .env file.
        Prioritizes KIMI_*, with fallback to MOONSHOT_*, NVIDIA_*, or OPENAI_* variables.
        """
        target_env = env_path or Path(".env")
        if target_env.is_file():
            try:
                for line in target_env.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass

        # 1. AI / Kimi Enabled flag
        ai_enabled_raw = os.getenv("AI_ENABLED", "true").lower()
        kimi_enabled_raw = os.getenv("KIMI_ENABLED", ai_enabled_raw).lower()
        enabled = kimi_enabled_raw in ("true", "1", "yes", "on")

        # 2. API Key resolution
        api_key = (
            os.getenv("KIMI_API_KEY")
            or os.getenv("MOONSHOT_API_KEY")
            or os.getenv("NVIDIA_API_KEY")
            or os.getenv("OPENAI_API_KEY")
        )

        # 3. Base URL resolution
        base_url = (
            os.getenv("KIMI_BASE_URL")
            or os.getenv("MOONSHOT_BASE_URL")
            or os.getenv("NVIDIA_BASE_URL")
            or os.getenv("OPENAI_BASE_URL")
            or "https://integrate.api.nvidia.com/v1"
        ).rstrip("/")

        # 4. Model resolution
        model = os.getenv("KIMI_MODEL") or "moonshotai/kimi-k3"

        # 5. Timeout
        try:
            timeout = float(os.getenv("KIMI_TIMEOUT", "45.0"))
        except ValueError:
            timeout = 45.0

        return cls(
            enabled=enabled,
            api_key=api_key,
            base_url=base_url,
            model=model,
            timeout_seconds=timeout,
            max_retries=2,
        )

    def is_configured(self) -> bool:
        """Check if Kimi is enabled and possesses an API key."""
        return self.enabled and bool(self.api_key and self.api_key.strip())

    def masked_key(self) -> str:
        """Return masked key safe for logging and diagnostics."""
        if not self.api_key:
            return "<UNSET>"
        clean = self.api_key.strip()
        if len(clean) <= 8:
            return "***"
        return f"{clean[:4]}...{clean[-4:]}"

    @property
    def masked_api_key(self) -> str:
        """Return masked key for diagnostics."""
        if not self.api_key:
            return "<UNSET>"
        clean = self.api_key.strip()
        if len(clean) <= 8:
            return "***"
        return f"{clean[:5]}***{clean[-4:]}"
