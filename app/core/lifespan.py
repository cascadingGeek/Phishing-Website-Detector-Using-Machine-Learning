"""
Application lifespan — loads ML artifacts once and initialises the DB pool.

Stores model, scaler, and metadata in app.state so controllers can access them
without importing global singletons.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import csv

import joblib
import structlog
from fastapi import FastAPI

from app.core.config import settings
from app.core.exceptions import ArtifactLoadError
from app.database.engine import engine

logger = structlog.get_logger(__name__)

_BLOCKLIST_CSV = Path(__file__).parents[2] / "ml" / "datasets" / "phishing_site_urls.csv"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Startup: artifacts must load before the server accepts requests
    _load_artifacts(app)

    # Verify the DB connection pool can reach the database (5s timeout)
    try:
        async def _ping() -> None:
            async with engine.begin() as conn:
                await conn.run_sync(lambda _: None)

        await asyncio.wait_for(_ping(), timeout=15.0)
        logger.info("database.pool_ready")
    except asyncio.TimeoutError:
        logger.warning("database.unreachable", error="connection timed out after 15s")
    except Exception as exc:
        logger.warning("database.unreachable", error=str(exc))

    logger.info("app.startup_complete")
    yield

    # Shutdown: return all pooled connections
    await engine.dispose()
    logger.info("app.shutdown_complete")


def _load_artifacts(app: FastAPI) -> None:
    """Load model, scaler, and metadata from disk; validate; store in app.state."""
    artifact_dir: Path = settings.artifact_dir / settings.model_version

    model_path = artifact_dir / "model.joblib"
    scaler_path = artifact_dir / "scaler.joblib"
    metadata_path = artifact_dir / "metadata.json"

    # Fail fast if any artifact file is missing
    for path in (model_path, scaler_path, metadata_path):
        if not path.exists():
            raise ArtifactLoadError(f"Required artifact not found: {path}")

    try:
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        metadata: dict = json.loads(metadata_path.read_text())
    except Exception as exc:
        raise ArtifactLoadError(f"Failed to deserialise artifacts: {exc}") from exc

    # feature_list must be non-empty — empty means training hasn't run yet
    feature_list: list[str] = metadata.get("feature_list", [])
    if not feature_list:
        raise RuntimeError(
            "metadata.json has an empty feature_list — "
            "run training/train.py then update artifacts/v1/metadata.json"
        )

    # When the model exposes n_features_in_ (sklearn >= 1.0), verify it matches
    if hasattr(model, "n_features_in_") and model.n_features_in_ is not None:
        if model.n_features_in_ != len(feature_list):
            raise RuntimeError(
                f"Feature count mismatch: metadata lists {len(feature_list)} features "
                f"but model expects {model.n_features_in_} — "
                "retrain or update metadata.json"
            )

    app.state.model = model
    app.state.scaler = scaler
    app.state.metadata = metadata
    app.state.phishing_blocklist = _load_blocklist()

    logger.info(
        "artifacts.loaded",
        version=metadata.get("model_version", "?"),
        features=len(feature_list),
        kernel=metadata.get("kernel", "?"),
    )


def _load_blocklist() -> frozenset[str]:
    """Load known-phishing URLs from the Kaggle CSV into a frozenset for O(1) lookup.

    The CSV has no protocol prefix (e.g. "www.example.com/path"), so we strip
    http:// / https:// from incoming URLs before checking.  Both www and non-www
    variants are stored so either form matches.
    """
    if not _BLOCKLIST_CSV.exists():
        logger.warning("blocklist.not_found", path=str(_BLOCKLIST_CSV))
        return frozenset()

    urls: set[str] = set()
    with _BLOCKLIST_CSV.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            label = (row.get("Label") or "").strip().lower()
            if label == "bad":
                raw = (row.get("URL") or "").strip()
                if raw:
                    urls.add(raw)
                    # Store without leading www. so we can match both variants
                    if raw.startswith("www."):
                        urls.add(raw[4:])

    result = frozenset(urls)
    logger.info("blocklist.loaded", count=len(result), path=str(_BLOCKLIST_CSV))
    return result
