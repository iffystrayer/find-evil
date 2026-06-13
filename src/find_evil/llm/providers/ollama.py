"""Ollama provider. Direct HTTP against the Ollama /api/chat endpoint.

Adapted from the previous build to the `LLMClient` protocol (chat plus
chat_structured) with the transport-retry fix applied. The structured path
retries on BOTH validation failures AND transport failures (httpx timeouts,
connection errors, and HTTP 5xx responses) with exponential backoff. A single
Ollama timeout must not end an investigation. HTTP 4xx responses are fatal and
are not retried, because retrying a client error only wastes budget.

The HTTP client is injectable to keep the retry control flow testable with a
faked transport.
"""

from __future__ import annotations

import asyncio

import httpx
import orjson
import structlog
from pydantic import BaseModel, ValidationError

from find_evil.llm.schema_utils import build_schema_prompt, inject_schema_prompt

logger = structlog.get_logger()


def _is_retryable_status(status_code: int) -> bool:
    """HTTP 429 (rate limit) and 5xx (server) are transient and retryable.

    Other 4xx responses are client errors: the request is malformed or
    unauthorized, so retrying it only wastes budget.
    """
    return status_code == 429 or status_code >= 500


class OllamaProvider:
    """Ollama LLM provider using the HTTP API."""

    def __init__(
        self,
        base_url: str,
        model_name: str,
        temperature: float = 0.1,
        timeout: float = 120.0,
        max_retries: int = 3,
        backoff_base_s: float = 0.5,
        client: httpx.AsyncClient | None = None,
    ):
        """Initialize the Ollama provider.

        Args:
            base_url: Ollama server URL (e.g. http://localhost:11434).
            model_name: Model to use for inference.
            temperature: Sampling temperature. Lower is more deterministic.
            timeout: Per-request timeout in seconds.
            max_retries: Total attempts for a structured or text request.
            backoff_base_s: Base for exponential backoff between transport
                retries. Set to 0 to disable the delay.
            client: Optional pre-built async HTTP client. When omitted a default
                httpx.AsyncClient is created. Injected in tests with a faked
                transport.
        """
        self._base_url = base_url.rstrip("/")
        self._model_name = model_name
        self._temperature = temperature
        self._max_retries = max_retries
        self._backoff_base_s = backoff_base_s
        self._client = (
            client if client is not None else httpx.AsyncClient(timeout=timeout)
        )
        self._prompt_tokens = 0
        self._completion_tokens = 0
        self._calls = 0

    def get_model_name(self) -> str:
        """Return the configured model name."""
        return self._model_name

    def token_usage(self) -> dict:
        """Cumulative token usage across all calls made by this provider."""
        return {
            "prompt": self._prompt_tokens,
            "completion": self._completion_tokens,
            "total": self._prompt_tokens + self._completion_tokens,
            "calls": self._calls,
        }

    def _record_usage(self, data: dict) -> None:
        """Accumulate token counts from one Ollama response.

        Ollama reports prompt_eval_count and eval_count at the top level of the
        /api/chat response. Tokens are counted per HTTP call, so a validation
        retry counts each attempt it actually spent.
        """
        self._prompt_tokens += int(data.get("prompt_eval_count") or 0)
        self._completion_tokens += int(data.get("eval_count") or 0)
        self._calls += 1

    async def chat(self, messages: list[dict], **kwargs) -> str:
        """Send a chat request and return the text response.

        Retries on transport failures (timeout, connection, HTTP 5xx) with
        backoff. HTTP 4xx is fatal.
        """
        payload = self._build_payload(
            messages, kwargs.get("temperature"), json_mode=False
        )
        data = await self._post_with_retry(payload, context="chat")
        self._record_usage(data)
        return data["message"]["content"]

    async def chat_structured(
        self, messages: list[dict], schema: type[BaseModel], **kwargs
    ):
        """Return a validated instance of `schema`.

        Retries on validation failures (with corrective feedback appended to the
        conversation) and on transport failures (with backoff). Raises
        RuntimeError once retries are exhausted, so a transient timeout never
        silently ends the investigation but a persistent failure surfaces.
        """
        schema_prompt = build_schema_prompt(schema)
        messages_with_schema = inject_schema_prompt(messages, schema_prompt)
        payload = self._build_payload(
            messages_with_schema, kwargs.get("temperature"), json_mode=True
        )

        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                data = await self._post(payload)
                self._record_usage(data)
                content = data["message"]["content"]
                json_obj = orjson.loads(content)
                validated = schema.model_validate(json_obj)
                logger.info(
                    "ollama_structured_output_success",
                    schema=schema.__name__,
                    attempt=attempt + 1,
                )
                return validated

            except (orjson.JSONDecodeError, ValidationError) as e:
                last_error = e
                logger.warning(
                    "ollama_structured_output_invalid",
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
                    payload["messages"] = messages_with_schema

            except httpx.HTTPStatusError as e:
                last_error = e
                if not _is_retryable_status(e.response.status_code):
                    raise RuntimeError(
                        f"Ollama request failed with client error "
                        f"{e.response.status_code}: {e}"
                    )
                logger.warning(
                    "ollama_structured_transport_error",
                    schema=schema.__name__,
                    attempt=attempt + 1,
                    status=e.response.status_code,
                )
                await self._maybe_backoff(attempt)

            except httpx.TransportError as e:
                last_error = e
                logger.warning(
                    "ollama_structured_transport_error",
                    schema=schema.__name__,
                    attempt=attempt + 1,
                    error=str(e),
                )
                await self._maybe_backoff(attempt)

        raise RuntimeError(
            f"Failed to get valid structured output from {self._model_name} "
            f"after {self._max_retries} attempts: {last_error}"
        )

    def _build_payload(
        self, messages: list[dict], temperature: float | None, json_mode: bool
    ) -> dict:
        payload = {
            "model": self._model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": (
                    temperature if temperature is not None else self._temperature
                )
            },
        }
        if json_mode:
            payload["format"] = "json"
        return payload

    async def _post(self, payload: dict) -> dict:
        """Single POST to /api/chat. Raises on transport or HTTP error."""
        response = await self._client.post(f"{self._base_url}/api/chat", json=payload)
        response.raise_for_status()
        return response.json()

    async def _post_with_retry(self, payload: dict, context: str) -> dict:
        """POST with transport-only retry. Used by the text chat path."""
        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                return await self._post(payload)
            except httpx.HTTPStatusError as e:
                last_error = e
                if not _is_retryable_status(e.response.status_code):
                    raise RuntimeError(
                        f"Ollama {context} failed with client error "
                        f"{e.response.status_code}: {e}"
                    )
                await self._maybe_backoff(attempt)
            except httpx.TransportError as e:
                last_error = e
                await self._maybe_backoff(attempt)
        raise RuntimeError(
            f"Ollama {context} failed after {self._max_retries} attempts: {last_error}"
        )

    async def _maybe_backoff(self, attempt: int) -> None:
        """Sleep with exponential backoff unless this was the last attempt."""
        if attempt < self._max_retries - 1 and self._backoff_base_s > 0:
            await asyncio.sleep(self._backoff_base_s * (2**attempt))

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
