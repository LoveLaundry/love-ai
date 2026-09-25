import json
from typing import List

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Placeholder shipped in .env.example. Copying it verbatim must not silently
# become the production encryption key.
PLACEHOLDER_MASTER_KEY = "CHANGE-ME-IN-PRODUCTION-love-laundry-2026"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mongo_uri: str = Field(
        default="mongodb://localhost:27017",
        validation_alias=AliasChoices("MONGO_URI", "DATABASE_URL"),
    )
    mongo_db_name: str = "laundry_management"

    # Optional explicit main-DB overrides (mirrors laundry-management config)
    mongodb_main_uri: str | None = Field(default=None, validation_alias=AliasChoices("MONGODB_MAIN_URI"))
    mongodb_main_db: str | None = Field(default=None, validation_alias=AliasChoices("MONGODB_MAIN_DB"))

    master_key: str = Field(validation_alias=AliasChoices("MASTER_KEY"))
    # Raw string on purpose: pydantic-settings would try to parse a List[str]
    # field as JSON and crash on plain / comma-separated / empty values.
    # Parsing happens in ai_api_keys_raw (comma-separated or JSON accepted).
    api_keys: str = Field(default="", validation_alias=AliasChoices("LOVE_AI_API_KEYS"))
    jwt_secret: str | None = None
    signature_ttl_seconds: int = 300

    cors: str = Field(
        default='["http://localhost:5173","http://localhost:3000","https://lovelaundry-manager.vercel.app"]',
        validation_alias=AliasChoices("CORS_ORIGINS"),
    )
    rate_limit_per_minute: int = 120

    @field_validator("master_key")
    @classmethod
    def _reject_placeholder_master_key(cls, value: str) -> str:
        """Refuse blank or placeholder keys instead of deriving weak crypto."""
        if not value or not value.strip():
            raise ValueError("MASTER_KEY must not be empty")
        if value.strip() == PLACEHOLDER_MASTER_KEY:
            raise ValueError(
                "MASTER_KEY is still the .env.example placeholder. "
                "Generate a unique secret, e.g. `python -c \"import secrets;"
                " print(secrets.token_urlsafe(32))\"`."
            )
        return value

    @property
    def ai_api_keys_raw(self) -> List[str]:
        """Return the configured plaintext API keys (never exposed in responses)."""
        keys = self.api_keys.strip()
        if not keys:
            return []
        try:
            parsed = json.loads(keys)
            if isinstance(parsed, list):
                return [str(k).strip() for k in parsed if str(k).strip()]
        except (ValueError, TypeError):
            pass
        return [k.strip() for k in keys.split(",") if k.strip()]

    @property
    def cors_origins(self) -> List[str]:
        """Parsed CORS origins — accepts JSON array or comma-separated values."""
        raw = self.cors.strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(o) for o in parsed]
        except (ValueError, TypeError):
            pass
        return [o.strip() for o in raw.split(",") if o.strip()]

    def resolve_main_uri(self) -> str:
        return self.mongodb_main_uri or self.mongo_uri

    def resolve_main_db(self) -> str:
        return self.mongodb_main_db or self.mongo_db_name


settings = Settings()