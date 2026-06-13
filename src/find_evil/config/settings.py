"""Runtime configuration. Values load from environment or a .env file.

List-typed fields accept comma-separated env values (EVIDENCE_ALLOWLIST=a,b),
not JSON. The NoDecode annotation plus the CSV validator make shell .env files
ergonomic and avoid the pydantic-settings JSON-decode trap.
"""

from __future__ import annotations
from typing import Annotated, Any
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # LLM
    llm_provider: str = "ollama"  # ollama | openai | anthropic
    llm_model: str = "deepseek-v3.1"
    llm_temperature: float = 0.1
    llm_max_retries: int = 3
    ollama_base_url: str = "http://localhost:11434"
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None

    # SIFT Workstation (LAN). Used by SSHExecutor for the live run.
    sift_host: str = "127.0.0.1"
    sift_port: int = 22
    sift_user: str = "sansforensics"
    sift_ssh_key_path: str | None = None
    sift_password: str | None = None  # password auth (key auth preferred)
    sift_known_hosts_path: str | None = None  # None -> ~/.ssh/known_hosts
    sift_strict_host_key: bool = True

    # Evidence + workspace (paths AS SEEN ON THE SIFT VM for live runs)
    evidence_allowlist: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["/mnt/evidence/", "/cases/"]
    )
    workspace_dir: str = "/tmp/find-evil"

    # Trust layer
    critique_enabled: bool = True  # one cheap LLM review per grounded finding

    # Execution
    executor: str = "mock"  # mock | ssh | local
    default_timeout_s: int = 120
    max_timeout_s: int = 1800

    # Budget
    max_steps: int = 12
    max_wall_seconds: int = 1800
    max_tokens: int = 400000

    # Ledger
    db_path: str = "./find_evil_runs.db"
    fixtures_dir: str = "./fixtures/sample_case"

    @field_validator("evidence_allowlist", mode="before")
    @classmethod
    def _split_csv(cls, v: Any) -> Any:
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
