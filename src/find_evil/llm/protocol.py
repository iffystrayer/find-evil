"""LLM client protocol. Two surfaces: free prose (summary only) and structured.

The structured path validates against a Pydantic schema and retries on BOTH
validation failures and transport failures (timeouts, connection errors, HTTP
5xx) with backoff. The previous build retried validation but let a single Ollama
timeout end the whole investigation. Do not repeat that.

Providers implement this protocol in llm/providers/ (ollama, openai, anthropic).
into providers/, applying the transport-retry fix. Keep this protocol stable.
"""

from __future__ import annotations
from typing import Protocol, TypeVar
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMClient(Protocol):
    async def chat(self, messages: list[dict]) -> str: ...
    async def chat_structured(self, messages: list[dict], schema: type[T]) -> T: ...
