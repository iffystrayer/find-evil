"""Token accounting (follow-up to M5).

The Ollama provider accumulates prompt and completion token counts from each
response, and the ledger stores the token cost of each tool-test iteration on
the execution row so the execution log can report per-call token usage.
"""

from __future__ import annotations

import httpx
import orjson
from pydantic import BaseModel

from find_evil.engine.schemas import ExecResult
from find_evil.ledger.store import Ledger
from find_evil.llm.providers.ollama import OllamaProvider


class _Sel(BaseModel):
    tool: str


def _resp(content: str, prompt: int, completion: int) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "message": {"content": content},
            "prompt_eval_count": prompt,
            "eval_count": completion,
        },
        request=httpx.Request("POST", "http://f/api/chat"),
    )


class _FakeTransport:
    def __init__(self, script):
        self._script = list(script)

    async def post(self, url, json=None):
        return self._script.pop(0)

    async def aclose(self):
        return None


def _provider(script):
    return OllamaProvider(
        "http://f", model_name="m", backoff_base_s=0.0, client=_FakeTransport(script)
    )


async def test_token_usage_accumulates_across_calls():
    c1 = orjson.dumps({"tool": "a"}).decode()
    c2 = orjson.dumps({"tool": "b"}).decode()
    p = _provider([_resp(c1, 10, 5), _resp(c2, 7, 3)])
    await p.chat_structured([{"role": "user", "content": "x"}], _Sel)
    await p.chat_structured([{"role": "user", "content": "y"}], _Sel)
    u = p.token_usage()
    assert u["prompt"] == 17
    assert u["completion"] == 8
    assert u["total"] == 25
    assert u["calls"] == 2


async def test_chat_text_also_counts_tokens():
    p = _provider([_resp("plain answer", 4, 6)])
    await p.chat([{"role": "user", "content": "x"}])
    assert p.token_usage()["total"] == 10
    assert p.token_usage()["calls"] == 1


def test_ledger_stores_and_updates_execution_tokens(tmp_path):
    ledger = Ledger(str(tmp_path / "t.db"))
    run_id = "r1"
    ledger.start_run(run_id, "i", "g", "m", {})
    ex = ExecResult(
        execution_id="e1",
        tool="strings",
        command="strings -n 6 /x",
        exit_code=0,
        stdout="o",
        stdout_sha256="s",
        duration_s=0.1,
        status="ok",
    )
    ledger.add_execution(run_id, ex, stdout_path="/x.txt")
    ledger.update_execution_tokens("e1", 42)
    rows = ledger.executions(run_id)
    assert rows[0]["tokens"] == 42
