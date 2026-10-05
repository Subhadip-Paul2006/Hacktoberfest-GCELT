"""Abstract LLM Provider interface for NSAT AI reasoning layer."""

from abc import ABC, abstractmethod
from typing import Any, Optional


class LLMProvider(ABC):
    """Abstract base class for all AI reasoning and chat completion providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider identifier (e.g. 'GLM-5.3', 'Ollama', 'Offline')."""
        pass

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> str:
        """
        Execute single-shot prompt generation.

        Args:
            prompt: User/context prompt
            system_prompt: Optional role instruction
            temperature: Creativity/entropy parameter (default 0.2 for analytical stability)
            max_tokens: Output budget ceiling

        Returns:
            Generated response string
        """
        pass

    @abstractmethod
    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> str:
        """
        Execute multi-turn chat completion.

        Args:
            messages: List of message dictionaries with 'role' ('system', 'user', 'assistant') and 'content'
            temperature: Creativity/entropy parameter
            max_tokens: Output budget ceiling

        Returns:
            Assistant response string
        """
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Verify network connectivity and authentication with backend API endpoint."""
        pass
