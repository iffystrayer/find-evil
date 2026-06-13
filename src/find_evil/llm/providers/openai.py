"""OpenAI provider. Chat Completions API with JSON-mode structured output.

Adapted from the previous build to the `LLMClient` protocol with the
transport-retry fix. The structured path retries on validation failures and on
transport failures (timeouts, connection errors, rate limits, HTTP 5xx) with
exponential backoff. HTTP 4xx and authentication errors are fatal.

The openai SDK is an optional dependency. It is imported lazily so the package
imports cleanly when only the Ollama provider is in use.
"""

from __future__ import annotations

import asyncio

import orjson
import structlog
from pydantic import BaseModel, ValidationError

from find_evil.llm.schema_utils import build_schema_prompt, inject_schema_prompt

logger = structlog.get_logger()


class OpenAIProvider:
    """OpenAI LLM provider using the OpenAI Python SDK."""

    def __init__(
        self,
        api_key: str,
        model_name: str,
        temperature: float = 0.1,
        timeout: float = 120.0,
        max_retries: int = 3,
        backoff_base_s: float = 0.5,
        client=None,
    ):
        """Initialize the OpenAI provider.

        Args:
            api_key: OpenAI API key.
            model_name: Model to use (e.g. gpt-4-turbo).
            temperature: Sampling temperature.
            timeout: Per-request timeout in seconds.
            max_retries: Total attempts for a structured or text request.
            backoff_base_s: Base for exponential backoff between transport
                retries. Set to 0 to disable the delay.
            client: Optional pre-built AsyncOpenAI client. Injected in tests.
        """
        self._model_name = model_name
        self._temperature = temperature
        self._max_retries = max_retries
        self._backoff_base_s = backoff_base_s
        if client is not None:
            self._client = client
        else:
            from openai import AsyncOpenAI

            self._client = AsyncOpenAI(api_key=api_key, timeout=timeout)

    def get_model_name(self) -> str:
        """Return the configured model name."""
        return self._model_name

    async def chat(self, messages: list[dict], **kwargs) -> str:
        """Send a chat request and return the text response."""
        temperature = kwargs.get("temperature", self._temperature)
        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.chat.completions.create(
                    model=self._model_name,
                    messages=messages,
                    temperature=temperature,
                )
                return response.choices[0].message.content
            except Exception as e:  # noqa: BLE001 - classified below
                last_error = e
                if not self._is_retryable(e):
                    raise RuntimeError(f"OpenAI chat failed: {e}")
                await self._maybe_backoff(attempt)
        raise RuntimeError(
            f"OpenAI chat failed after {self._max_retries} attempts: {last_error}"
        )

    async def chat_structured(
        self, messages: list[dict], schema: type[BaseModel], **kwargs
    ):
        """Return a validated instance of `schema` via JSON mode."""
        temperature = kwargs.get("temperature", self._temperature)
        schema_prompt = build_schema_prompt(schema)
        messages_with_schema = inject_schema_prompt(messages, schema_prompt)

        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.chat.completions.create(
                    model=self._model_name,
                    messages=messages_with_schema,
                    temperature=temperature,
                    response_format={"type": "json_object"},
                )
                json_str = response.choices[0].message.content
                json_obj = orjson.loads(json_str)
                validated = schema.model_validate(json_obj)
                logger.info(
                    "openai_structured_output_success",
                    schema=schema.__name__,
                    attempt=attempt + 1,
                )
                return validated

            except (orjson.JSONDecodeError, ValidationError) as e:
                last_error = e
                logger.warning(
                    "openai_structured_output_invalid",
                    schema=schema.__name__,
                    attempt=attempt + 1,
                    error=str(e),
                )
                if attempt < self._max_retries - 1:
                    messages_with_schema.append(
                        {
                            "role": "user",
                            "content": (
                                f"Previous response was invalid: {e}. "
                                "Respond with valid JSON matching the schema exactly."
                            ),
                        }
                    )

            except Exception as e:  # noqa: BLE001 - classified below
                last_error = e
                if not self._is_retryable(e):
                    raise RuntimeError(f"OpenAI structured request failed: {e}")
                logger.warning(
                    "openai_structured_transport_error",
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
    def _is_retryable(error: Exception) -> bool:
        """Classify an OpenAI SDK error as transport-retryable.

        Connection errors, timeouts, rate limits, and HTTP 5xx are retryable.
        Authentication errors and other 4xx client errors are fatal.
        """
        try:
            from openai import APIConnectionError, APITimeoutError, RateLimitError
            from openai import APIStatusError
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
