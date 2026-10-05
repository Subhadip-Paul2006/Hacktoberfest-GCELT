"""GLM-5.3 Provider Implementation for NSAT."""

import json
import logging
import sys
import time
from typing import Any, Optional
import requests

from nsat.ai.config import GLMConfig
from nsat.ai.provider import LLMProvider

logger = logging.getLogger("nsat.ai.glm")


class GLMProvider(LLMProvider):
    """
    Client for GLM-5.3 compatible chat completion endpoints
    (supports NVIDIA NIM, Zhipu AI, OpenAI-compatible proxy gateways).
    """

    def __init__(self, config: Optional[GLMConfig] = None):
        self.config = config or GLMConfig.load()

    @property
    def provider_name(self) -> str:
        return f"GLM-5.3 ({self.config.model})"

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> str:
        """Single-shot completion via chat/completions endpoint."""
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        return self.chat(messages, temperature=temperature, max_tokens=max_tokens)

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> str:
        """Multi-turn chat completion with retries, timeout handling, and response validation."""
        if not self.config.enabled:
            raise RuntimeError("AI reasoning is disabled (AI_ENABLED=false).")

        if not self.config.api_key:
            raise ValueError(
                "GLM API key not configured. Set GLM_API_KEY (or NVIDIA_API_KEY) in environment."
            )

        url = f"{self.config.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.api_key.strip()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        attempts = 0
        last_exception: Optional[Exception] = None

        while attempts <= self.config.max_retries:
            attempts += 1
            try:
                resp = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=self.config.timeout_seconds,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if not choices:
                        raise ValueError("GLM response returned empty choices array.")
                    content = choices[0].get("message", {}).get("content", "")
                    return content.strip()

                # Retry on rate limit (429) or transient server errors (5xx)
                if resp.status_code in (429, 500, 502, 503, 504) and attempts <= self.config.max_retries:
                    time.sleep(1.0 * attempts)
                    continue

                if resp.status_code == 401:
                    raise PermissionError(f"GLM authentication failed (401 Unauthorized). Verify API key.")

                raise RuntimeError(
                    f"GLM API error HTTP {resp.status_code}: {resp.text[:200]}"
                )

            except requests.exceptions.Timeout as exc:
                last_exception = TimeoutError(
                    f"GLM request timed out after {self.config.timeout_seconds}s."
                )
                if attempts <= self.config.max_retries:
                    time.sleep(1.0)
                    continue
            except requests.exceptions.RequestException as exc:
                last_exception = RuntimeError(f"GLM connection error: {type(exc).__name__}: {str(exc)}")
                if attempts <= self.config.max_retries:
                    time.sleep(1.0)
                    continue

        if last_exception:
            raise last_exception
        raise RuntimeError("GLM execution failed after maximum retries.")

    def health_check(self) -> bool:
        """Quick probe to test credentials and endpoint responsiveness."""
        if not self.config.is_configured():
            return False
        try:
            res = self.generate(
                prompt="Ping",
                system_prompt="Respond with PONG",
                temperature=0.0,
                max_tokens=8,
            )
            return bool(res)
        except Exception:
            return False
