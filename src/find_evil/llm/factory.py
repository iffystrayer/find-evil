"""Factory for creating an LLM provider from settings.

Central construction point for every provider. Reads `settings.llm_provider`
(a string: ollama | openai | anthropic) and instantiates the matching
implementation, threading the retry budget so a single transport timeout never
ends an investigation. CLI overrides take precedence over settings.
"""

from __future__ import annotations

from find_evil.config.settings import Settings
from find_evil.llm.protocol import LLMClient


def create_llm_provider(
    settings: Settings,
    provider_override: str | None = None,
    model_override: str | None = None,
) -> LLMClient:
    """Create an LLM provider instance based on settings.

    Args:
        settings: Application settings with the LLM configuration.
        provider_override: Optional provider name override.
        model_override: Optional model name override.

    Returns:
        An object conforming to the `LLMClient` protocol.

    Raises:
        ValueError: If the provider is unknown or a required API key is missing.
    """
    provider = (provider_override or settings.llm_provider).lower()
    model_name = model_override or settings.llm_model

    if provider == "ollama":
        from find_evil.llm.providers.ollama import OllamaProvider

        return OllamaProvider(
            base_url=settings.ollama_base_url,
            model_name=model_name,
            temperature=settings.llm_temperature,
            max_retries=settings.llm_max_retries,
        )

    if provider == "openai":
        if not settings.openai_api_key:
            raise ValueError(
                "OPENAI_API_KEY required for the openai provider. "
                "Set the environment variable or update .env."
            )
        from find_evil.llm.providers.openai import OpenAIProvider

        return OpenAIProvider(
            api_key=settings.openai_api_key,
            model_name=model_name,
            temperature=settings.llm_temperature,
            max_retries=settings.llm_max_retries,
        )

    if provider == "anthropic":
        if not settings.anthropic_api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY required for the anthropic provider. "
                "Set the environment variable or update .env."
            )
        from find_evil.llm.providers.anthropic import AnthropicProvider

        return AnthropicProvider(
            api_key=settings.anthropic_api_key,
            model_name=model_name,
            temperature=settings.llm_temperature,
            max_retries=settings.llm_max_retries,
        )

    raise ValueError(
        f"Unknown LLM provider: {provider!r}. "
        "Supported providers: ollama, openai, anthropic."
    )
