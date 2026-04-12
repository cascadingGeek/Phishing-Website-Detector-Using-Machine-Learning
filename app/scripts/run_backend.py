"""
Entry point for the phishing detection API server.

Handles one-time artifact migration (pkl → joblib) then starts uvicorn.

Usage:
    uv run python -m app.scripts.run_backend
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import uvicorn

from app.core.config import settings
from app.services.feature_extractor import FEATURE_LIST

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

_LEGACY_PKL = (
    settings.artifact_dir.parent / "models" / "svm_model.pkl"
)
_ARTIFACT_DIR: Path = settings.artifact_dir / settings.model_version


def _ensure_artifacts() -> None:
    """Create artifacts/v1/ directory and migrate legacy pkl if present."""
    _ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    _ensure_model()
    _ensure_scaler()
    _ensure_metadata()


def _ensure_model() -> None:
    model_path = _ARTIFACT_DIR / "model.joblib"
    if model_path.exists():
        return

    model = None
    if _LEGACY_PKL.exists():
        # Attempt joblib load first, then pickle as fallback
        try:
            model = joblib.load(_LEGACY_PKL)
            if not hasattr(model, "predict"):
                raise ValueError("not a sklearn estimator")
            logger.info("Converted svm_model.pkl → model.joblib")
        except Exception as e1:
            try:
                import pickle
                with open(_LEGACY_PKL, "rb") as fh:
                    model = pickle.load(fh)
                if not hasattr(model, "predict"):
                    raise ValueError("not a sklearn estimator")
                logger.info("Converted svm_model.pkl (pickle) → model.joblib")
            except Exception as e2:
                logger.warning("Cannot load svm_model.pkl (%s / %s); creating placeholder", e1, e2)
                model = None

        if _LEGACY_PKL.exists():
            _LEGACY_PKL.unlink()
            logger.info("Deleted legacy %s", _LEGACY_PKL)

    if model is None:
        # PLACEHOLDER — run training/train.py to replace
        from sklearn.svm import SVC
        model = SVC(kernel="rbf", probability=True)
        model.fit(np.zeros((2, len(FEATURE_LIST))), [0, 1])
        logger.warning("Created placeholder model — predictions are meaningless until retrained")

    joblib.dump(model, model_path)


def _ensure_scaler() -> None:
    scaler_path = _ARTIFACT_DIR / "scaler.joblib"
    if scaler_path.exists():
        return

    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    scaler.fit(np.zeros((2, len(FEATURE_LIST))))  # fit on dummy data so transform() works
    joblib.dump(scaler, scaler_path)
    logger.warning("Created placeholder scaler — refit using training data before production use")


def _ensure_metadata() -> None:
    metadata_path = _ARTIFACT_DIR / "metadata.json"
    if metadata_path.exists():
        return

    metadata = {
        "model_version": settings.model_version,
        "training_date": "YYYY-MM-DD",
        "feature_list": FEATURE_LIST,
        "feature_order": FEATURE_LIST,
        "scaler_type": "StandardScaler",
        "kernel": "rbf",
        "class_mapping": {"0": "legitimate", "1": "phishing"},
        "notes": "placeholder — replace after first training run",
    }
    metadata_path.write_text(json.dumps(metadata, indent=2))
    logger.info("Created metadata.json")


if __name__ == "__main__":
    _ensure_artifacts()
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
    )
