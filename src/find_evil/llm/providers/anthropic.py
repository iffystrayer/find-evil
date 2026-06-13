"""Anthropic provider. Messages API with tool-use structured output.

Adapted from the previous build to the `LLMClient` protocol with the
transport-retry fix. Anthropic uses native tool calling for structured output
rather than JSON mode, so it does not consume the shared schema-prompt
utilities. The structured path retries on validation failures and on transport
failures (timeouts, connection errors, rate limits, HTTP 5xx) with exponential
backoff. HTTP 4xx and authentication errors are fatal.

The anthropic SDK is an optional dependency, imported lazily so the package
imports cleanly when only the Ollama provider is in use.
"""

from __future__ import annotations

import asyncio

import structlog
from pydantic import BaseModel, ValidationError

logger = structlog.get_logger()

_STRUCTURED_TOOL_NAME = "provide_structured_response"


class AnthropicProvider:
    """Anthropic LLM provider using the Anthropic Python SDK."""

    def __init__(
        self,
        api_key: str,
        model_name: str,
        temperature: float = 0.1,
        timeout: float = 120.0,
        max_tokens: int = 4096,
        max_retries: int = 3,
        backoff_base_s: float = 0.5,
        client=None,
    ):
        """Initialize the Anthropic provider.

        Args:
            api_key: Anthropic API key.
            model_name: Model to use (e.g. claude-sonnet-4-20250514).
            temperature: Sampling temperature.
            timeout: Per-request timeout in seconds.
            max_tokens: Maximum tokens in the response.
            max_retries: Total attempts for a structured or text request.
            backoff_base_s: Base for exponential backoff between transport
                retries. Set to 0 to disable the delay.
            client: Optional pre-built AsyncAnthropic client. Injected in tests.
        """
        self._model_name = model_name
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._max_retries = max_retries
        self._backoff_base_s = backoff_base_s
        if client is not None:
            self._client = client
        else:
            from anthropic import AsyncAnthropic

            self._client = AsyncAnthropic(api_key=api_key, timeout=timeout)

    def get_model_name(self) -> str:
        """Return the configured model name."""
        return self._model_name

    async def chat(self, messages: list[dict], **kwargs) -> str:
        """Send a chat request and return the text response."""
        temperature = kwargs.get("temperature", self._temperature)
        max_tokens = kwargs.get("max_tokens", self._max_tokens)
        system, filtered = self._extract_system_message(messages)

        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.messages.create(
                    model=self._model_name,
                    messages=filtered,
                    system=system,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                return response.content[0].text
            except Exception as e:  # noqa: BLE001 - classified below
                last_error = e
                if not self._is_retryable(e):
                    raise RuntimeError(f"Anthropic chat failed: {e}")
                await self._maybe_backoff(attempt)
        raise RuntimeError(
            f"Anthropic chat failed after {self._max_retries} attempts: {last_error}"
        )

    async def chat_structured(
        self, messages: list[dict], schema: type[BaseModel], **kwargs
    ):
        """Return a validated instance of `schema` via tool use."""
        temperature = kwargs.get("temperature", self._temperature)
        max_tokens = kwargs.get("max_tokens", self._max_tokens)
        tool_def = self._build_tool_definition(schema)
        system, filtered = self._extract_system_message(messages)

        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.messages.create(
                    model=self._model_name,
                    messages=filtered,
                    system=system,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=[tool_def],
                    tool_choice={"type": "tool", "name": tool_def["name"]},
                )
                tool_use = next(
                    (b for b in response.content if b.type == "tool_use"), None
                )
                if tool_use is None:
                    raise ValidationError.from_exception_data(schema.__name__, [])
                validated = schema.model_validate(tool_use.input)
                logger.info(
                    "anthropic_structured_output_success",
                    schema=schema.__name__,
                    attempt=attempt + 1,
                )
                return validated

            except ValidationError as e:
                last_error = e
                logger.warning(
                    "anthropic_structured_output_invalid",
                    schema=schema.__name__,
                    attempt=attempt + 1,
                    error=str(e),
                )
                if attempt < self._max_retries - 1:
                    filtered.append(
                        {
                            "role": "user",
                            "content": (
                                f"Previous response was invalid: {e}. "
                                "Provide a response matching the exact schema structure."
                            ),
                        }
                    )

            except Exception as e:  # noqa: BLE001 - classified below
                last_error = e
                if not self._is_retryable(e):
                    raise RuntimeError(f"Anthropic structured request failed: {e}")
                logger.warning(
                    "anthropic_structured_transport_error",
                    schema=schema.__name__,
                    attempt=attempt + 1,
                    error=str(e),
                )
                await self._maybe_backoff(attempt)

        raise RuntimeError(
            f"Failed to get valid structured output from {self._model_name} "
            f"after {self._max_retries} attempts: {last_error}"
        )

    @staticmethod
    def _extract_system_message(
        messages: list[dict],
    ) -> tuple[str | None, list[dict]]:
        """Split a leading system message out. Anthropic takes it separately."""
        if messages and messages[0].get("role") == "system":
            return messages[0]["content"], list(messages[1:])
        return None, list(messages)

    @staticmethod
    def _build_tool_definition(schema: type[BaseModel]) -> dict:
        """Build an Anthropic tool definition from a Pydantic schema."""
        return {
            "name": _STRUCTURED_TOOL_NAME,
            "description": (
                f"Provide a structured response matching the {schema.__name__} schema"
            ),
            "input_schema": schema.model_json_schema(),
        }

    @staticmethod
    def _is_retryable(error: Exception) -> bool:
        """Classify an Anthropic SDK error as transport-retryable."""
        try:
            from anthropic import APIConnectionError, APITimeoutError, RateLimitError
            from anthropic import APIStatusError
        except ImportError:
            return False

        if isinstance(error, (APIConnectionError, APITimeoutError, RateLimitError)):
            return True
        if isinstance(error, APIStatusError):
            return error.status_code >= 500
        return False

    async def _maybe_backoff(self, attempt: int) -> None:
        if attempt < self._max_retries - 1 and self._backoff_base_s > 0:
            await asyncio.sleep(self._backoff_base_s * (2**attempt))

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.close()
