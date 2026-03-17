from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parents[3]  # project root


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "Phishing Detection API"
    app_version: str = "1.0.0"
    debug: bool = False

    # Model path relative to project root
    model_path: Path = BASE_DIR / "backend" / "app" / "models" / "svm_model.pkl"

    # CORS origins for the Streamlit frontend
    cors_origins: list[str] = ["http://localhost:8501", "http://127.0.0.1:8501"]

    # Request timeout for feature extraction network calls (seconds)
    request_timeout: int = 10


settings = Settings()
