import os
import pytest
from find_evil.config.settings import Settings


@pytest.fixture
def settings(tmp_path):
    fx = os.path.join(os.getcwd(), "fixtures", "sample_case")
    return Settings(
        executor="mock",
        fixtures_dir=fx,
        db_path=str(tmp_path / "test.db"),
        evidence_allowlist=[fx],
        workspace_dir=str(tmp_path / "workspace"),
        max_steps=3,
        max_wall_seconds=30,
        # Point the lazily-built provider at a dead endpoint and disable retry
        # backoff so any test that does NOT inject an LLM degrades fast and
        # deterministically instead of reaching a live Ollama on the host.
        ollama_base_url="http://127.0.0.1:1",
        llm_max_retries=1,
    )
