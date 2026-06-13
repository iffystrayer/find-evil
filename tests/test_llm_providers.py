"""LLM provider tests. Focus of the M1 gate.

The structured path must return a validated schema from a faked transport and
must RETRY (not abort) on a simulated transport timeout. The previous build
retried validation failures but let a single Ollama timeout end the whole
investigation. These tests pin the corrected behavior.

The transport is faked with small real classes, not unittest.mock objects, so
the assertions exercise the real retry control flow.
"""

from __future__ import annotations

import httpx
import orjson
import pytest
from pydantic import BaseModel

from find_evil.llm.providers.ollama import OllamaProvider


class _Selection(BaseModel):
    tool: str
    confidence: float


def _ollama_chat_response(content: str) -> httpx.Response:
    """Build a real httpx.Response shaped like the Ollama /api/chat reply."""
    return httpx.Response(
        status_code=200,
        json={"message": {"content": content}},
        request=httpx.Request("POST", "http://fake/api/chat"),
    )


class FakeTransport:
    """Programmable stand-in for httpx.AsyncClient.

    `script` is a list of either httpx.Response objects to return or Exception
    instances to raise, consumed in order on each `post` call. This is a real
    object with deterministic behavior, not a mock.
    """

    def __init__(self, script: list):
        self._script = list(script)
        self.calls = 0

    async def post(self, url: str, json: dict | None = None) -> httpx.Response:
        self.calls += 1
        if not self._script:
            raise AssertionError("FakeTransport called more times than scripted")
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def aclose(self) -> None:
        return None


def _provider(script: list) -> OllamaProvider:
    return OllamaProvider(
        base_url="http://fake:11434",
        model_name="test-model",
        max_retries=3,
        backoff_base_s=0.0,  # keep retries instant in tests
        client=FakeTransport(script),
    )


async def test_chat_structured_returns_validated_schema():
    content = orjson.dumps({"tool": "volatility", "confidence": 0.9}).decode()
    provider = _provider([_ollama_chat_response(content)])

    result = await provider.chat_structured(
        [{"role": "user", "content": "pick a tool"}], _Selection
    )

    assert isinstance(result, _Selection)
    assert result.tool == "volatility"
    assert result.confidence == 0.9


async def test_chat_structured_retries_on_timeout_then_succeeds():
    """A single transport timeout must NOT end the investigation."""
    content = orjson.dumps({"tool": "tsk", "confidence": 0.5}).decode()
    transport = FakeTransport(
        [httpx.ReadTimeout("simulated timeout"), _ollama_chat_response(content)]
    )
    provider = OllamaProvider(
        base_url="http://fake:11434",
        model_name="test-model",
        max_retries=3,
        backoff_base_s=0.0,
        client=transport,
    )

    result = await provider.chat_structured(
        [{"role": "user", "content": "pick a tool"}], _Selection
    )

    assert result.tool == "tsk"
    assert transport.calls == 2  # retried, did not abort


async def test_chat_structured_retries_on_connect_error_then_succeeds():
    content = orjson.dumps({"tool": "grep", "confidence": 0.7}).decode()
    transport = FakeTransport(
        [httpx.ConnectError("connection refused"), _ollama_chat_response(content)]
    )
    provider = OllamaProvider(
        base_url="http://fake:11434",
        model_name="test-model",
        max_retries=3,
        backoff_base_s=0.0,
        client=transport,
    )

    result = await provider.chat_structured(
        [{"role": "user", "content": "go"}], _Selection
    )
    assert result.tool == "grep"
    assert transport.calls == 2


async def test_chat_structured_retries_on_http_5xx_then_succeeds():
    content = orjson.dumps({"tool": "strings", "confidence": 0.4}).decode()
    err = httpx.Response(
        status_code=503,
        request=httpx.Request("POST", "http://fake/api/chat"),
    )
    transport = FakeTransport([err, _ollama_chat_response(content)])
    provider = OllamaProvider(
        base_url="http://fake:11434",
        model_name="test-model",
        max_retries=3,
        backoff_base_s=0.0,
        client=transport,
    )

    result = await provider.chat_structured(
        [{"role": "user", "content": "go"}], _Selection
    )
    assert result.tool == "strings"
    assert transport.calls == 2


async def test_chat_structured_retries_on_http_429_then_succeeds():
    """Rate limiting is transient. A 429 must be retried, not treated as fatal."""
    content = orjson.dumps({"tool": "fls", "confidence": 0.3}).decode()
    err = httpx.Response(
        status_code=429,
        request=httpx.Request("POST", "http://fake/api/chat"),
    )
    transport = FakeTransport([err, _ollama_chat_response(content)])
    provider = OllamaProvider(
        base_url="http://fake:11434",
        model_name="test-model",
        max_retries=3,
        backoff_base_s=0.0,
        client=transport,
    )

    result = await provider.chat_structured(
        [{"role": "user", "content": "go"}], _Selection
    )
    assert result.tool == "fls"
    assert transport.calls == 2


async def test_chat_structured_retries_on_validation_failure_then_succeeds():
    bad = orjson.dumps({"tool": "vol"}).decode()  # missing required confidence
    good = orjson.dumps({"tool": "vol", "confidence": 0.6}).decode()
    transport = FakeTransport([_ollama_chat_response(bad), _ollama_chat_response(good)])
    provider = OllamaProvider(
        base_url="http://fake:11434",
        model_name="test-model",
        max_retries=3,
        backoff_base_s=0.0,
        client=transport,
    )

    result = await provider.chat_structured(
        [{"role": "user", "content": "go"}], _Selection
    )
    assert result.confidence == 0.6
    assert transport.calls == 2


async def test_chat_structured_aborts_after_exhausting_retries():
    transport = FakeTransport(
        [httpx.ReadTimeout("t1"), httpx.ReadTimeout("t2"), httpx.ReadTimeout("t3")]
    )
    provider = OllamaProvider(
        base_url="http://fake:11434",
        model_name="test-model",
        max_retries=3,
        backoff_base_s=0.0,
        client=transport,
    )

    with pytest.raises(RuntimeError):
        await provider.chat_structured([{"role": "user", "content": "go"}], _Selection)
    assert transport.calls == 3


async def test_http_4xx_is_not_retried():
    """Client errors are fatal. Retrying a 400 wastes budget."""
    err = httpx.Response(
        status_code=400,
        request=httpx.Request("POST", "http://fake/api/chat"),
    )
    transport = FakeTransport([err])
    provider = OllamaProvider(
        base_url="http://fake:11434",
        model_name="test-model",
        max_retries=3,
        backoff_base_s=0.0,
        client=transport,
    )

    with pytest.raises(RuntimeError):
        await provider.chat_structured([{"role": "user", "content": "go"}], _Selection)
    assert transport.calls == 1


async def test_chat_returns_text():
    transport = FakeTransport([_ollama_chat_response("a plain answer")])
    provider = OllamaProvider(
        base_url="http://fake:11434",
        model_name="test-model",
        backoff_base_s=0.0,
        client=transport,
    )

    text = await provider.chat([{"role": "user", "content": "hi"}])
    assert text == "a plain answer"


def test_factory_builds_ollama_from_settings():
    from find_evil.config.settings import Settings
    from find_evil.llm.factory import create_llm_provider

    settings = Settings(llm_provider="ollama", llm_model="test-model")
    provider = create_llm_provider(settings)
    assert isinstance(provider, OllamaProvider)
    assert provider.get_model_name() == "test-model"


def test_factory_rejects_openai_without_key():
    from find_evil.config.settings import Settings
    from find_evil.llm.factory import create_llm_provider

    settings = Settings(llm_provider="openai", openai_api_key=None)
    with pytest.raises(ValueError):
        create_llm_provider(settings)
