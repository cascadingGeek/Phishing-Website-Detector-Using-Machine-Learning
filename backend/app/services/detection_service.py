"""
Detection Service — loads the trained SVM model once and runs inference.
"""
from __future__ import annotations

import math
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from backend.app.services.feature_extractor import FEATURE_COLUMNS, extract_features
from backend.app.schemas.response import DetectionResponse, FeatureVector


class DetectionService:
    """Singleton-friendly service that wraps the SVM model."""

    def __init__(self, model_path: Path) -> None:
        # Try joblib first (new models), fall back to pickle (legacy models)
        try:
            self._model = joblib.load(model_path)
        except Exception:
            import pickle
            with open(model_path, "rb") as f:
                self._model = pickle.load(f)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def detect(self, url: str) -> DetectionResponse:
        vector, rank = extract_features(url)

        df = pd.DataFrame([vector], columns=FEATURE_COLUMNS)
        raw_prediction: int = int(self._model.predict(df)[0])

        confidence = self._confidence(df)
        prediction = "legitimate" if raw_prediction == 1 else "phishing"

        feature_dict = dict(zip(FEATURE_COLUMNS, vector))

        return DetectionResponse(
            url=url,
            prediction=prediction,
            confidence=round(confidence, 4),
            global_rank=rank,
            features=FeatureVector(**feature_dict),
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _confidence(self, df: pd.DataFrame) -> float:
        """
        Convert SVM decision function score to a [0, 1] confidence value
        using a sigmoid transform.  Works even when probability=False.
        """
        try:
            score = float(self._model.decision_function(df)[0])
            return 1.0 / (1.0 + math.exp(-score))
        except Exception:
            # Fallback: use predict_proba if available (model trained with probability=True)
            try:
                proba = self._model.predict_proba(df)[0]
                return float(np.max(proba))
            except Exception:
                return 0.5
