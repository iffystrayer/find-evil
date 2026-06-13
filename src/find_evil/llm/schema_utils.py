"""Shared JSON-schema prompt utilities for LLM providers.

OpenAI and Ollama both lack native ``response_format=BaseModel`` support across
all of our target models, so we coerce them by injecting an explicit JSON-schema
instruction into the system message. This module is the single source of truth
for that logic, shared by the OpenAI and Ollama providers.

Anthropic uses native tool-use and does not consume these utilities.
"""

from __future__ import annotations

from typing import Any

import orjson
from pydantic import BaseModel

__all__ = ["build_schema_prompt", "inject_schema_prompt"]


def build_schema_prompt(schema: type[BaseModel]) -> str:
    """Build a JSON-schema instruction prompt from a Pydantic model.

    The wording is deliberate: instructing models to omit markdown fences and
    explanatory text noticeably reduces parse-failure retries against weaker
    models like the smaller Ollama variants.

    Args:
        schema: Pydantic model class to derive the schema from.

    Returns:
        A system-message-ready string containing the JSON schema and formatting
        instructions.
    """
    schema_json: dict[str, Any] = schema.model_json_schema()
    return f"""You must respond with valid JSON matching this schema:

{orjson.dumps(schema_json, option=orjson.OPT_INDENT_2).decode()}

IMPORTANT:
- Respond ONLY with the JSON object
- Do NOT include markdown code fences (```json)
- Do NOT include any explanatory text
- Ensure all required fields are present
- Follow the exact field names and types"""


def inject_schema_prompt(
    messages: list[dict[str, str]],
    schema_prompt: str,
) -> list[dict[str, str]]:
    """Inject a schema prompt into a chat-completions message list.

    If the first message is already a system message, append to it (preserving
    prior system instructions). Otherwise prepend a new system message. The
    input list is never mutated.

    Args:
        messages: Original chat messages (each ``{"role": ..., "content": ...}``).
        schema_prompt: Output of :func:`build_schema_prompt`.

    Returns:
        A new list with the schema prompt merged in.
    """
    messages_copy = messages.copy()

    if messages_copy and messages_copy[0].get("role") == "system":
        messages_copy[0] = {
            **messages_copy[0],
            "content": f"{messages_copy[0]['content']}\n\n{schema_prompt}",
        }
    else:
        messages_copy.insert(0, {"role": "system", "content": schema_prompt})

    return messages_copy
