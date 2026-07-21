"""Application configuration, loaded from environment / .env via pydantic-settings.

All tunable behaviour (thresholds, model, provider keys, database URL) lives here so the
service can be reconfigured without code changes.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repository root (two levels up from this file: app/config.py -> app -> repo root).
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Typed application settings.

    Values are read from environment variables (case-insensitive) and, for local dev,
    from a `.env` file at the repository root. Secrets never have defaults.
    """

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Service ---
    app_name: str = "prompt-injection-detector"
    environment: str = "development"

    # --- LLM classifier (primary: OpenAI) ---
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"

    # --- LLM classifier (fallback: OpenRouter) ---
    openrouter_api_key: str = ""
    openrouter_model: str = "openrouter/free"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    # Master switch for the classifier layer. When False the service is heuristics-only.
    classifier_enabled: bool = True
    classifier_timeout_s: float = 8.0

    # --- Detection thresholds (heuristic score in [0, 1]) ---
    # >= high  -> malicious, skip the LLM.  <= low -> benign, skip the LLM.
    # In between -> ambiguous band, invoke the LLM classifier (cascade).
    heuristic_high_threshold: float = 0.80
    heuristic_low_threshold: float = 0.20

    # Final-score -> label thresholds.
    malicious_threshold: float = 0.70
    suspicious_threshold: float = 0.40

    # Weight given to the classifier score when blending with the heuristic score.
    classifier_weight: float = 0.65

    # --- Rules ---
    rules_path: str = str(BASE_DIR / "config" / "rules.yaml")

    # --- Database / logging ---
    database_url: str = Field(
        default="postgresql+psycopg://postgres:postgres@localhost:5432/pid",
    )
    logging_enabled: bool = True
    # How much of the raw input to persist (truncated for privacy). 0 = store nothing.
    input_preview_chars: int = 500

    @property
    def classifier_available(self) -> bool:
        """True when the classifier layer is enabled and at least one provider key exists."""
        return self.classifier_enabled and bool(
            self.openai_api_key or self.openrouter_api_key
        )


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (single source of truth for the process)."""
    return Settings()
