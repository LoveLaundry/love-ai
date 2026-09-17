import os
from typing import List

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    master_key: str = "CHANGE-ME-IN-PRODUCTION-love-laundry-2026"
    love_ai_api_keys: List[str] = Field(default_factory=lambda: ["dev-key-change-me"])
    jwt_secret: str | None = None
    signature_ttl_seconds: int = 300

    cors_origins: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://localhost:3000",
            "https://lovelaundry-manager.vercel.app",
        ]
    )
    rate_limit_per_minute: int = 120

    @property
    def ai_api_keys_raw(self) -> List[str]:
        """Return the configured plaintext API keys (never exposed in responses)."""
        keys = os.getenv("LOVE_AI_API_KEYS") or ""
        if keys.strip():
            return [k.strip() for k in keys.split(",") if k.strip()]
        return self.love_ai_api_keys

    def resolve_main_uri(self) -> str:
        return self.mongodb_main_uri or self.mongo_uri

    def resolve_main_db(self) -> str:
        return self.mongodb_main_db or self.mongo_db_name


settings = Settings()