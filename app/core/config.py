from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parents[2]  # project root (app/core/config.py → up 2)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # CORE
    app_name: str = "Phishing Detection API"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    # DATABASE
    database_url: str

    # CORS origins — comma-separated string (e.g. "https://a.com,https://b.com")
    cors_origins: str = "*"

    # Request timeout for feature extraction network calls (seconds)
    request_timeout: int = 30

    # ML Artifacts — version-stamped directory under artifact_dir
    artifact_dir: Path = BASE_DIR / "app" / "artifacts"
    model_version: str = "v1"

    # Predictions below this threshold are labelled "uncertain"
    confidence_threshold: float = 0.7

    # Logging
    log_level: str = "INFO"


settings = Settings()
