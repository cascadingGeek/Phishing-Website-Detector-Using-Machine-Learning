"""
Detection service — stateless ML inference.

Knows about: feature_extractor, core config/exceptions, numpy.
Does NOT know about: HTTP, Pydantic schemas, database, or global model singletons.
All ML artifacts are received via app_state (loaded once in lifespan.py).
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
import pandas as pd

from app.core.config import settings
from app.core.exceptions import FeatureExtractionError
from app.services import feature_extractor


@dataclass
class DetectionResult:
    """Plain dataclass — schemas/response.py maps this to the HTTP shape."""

    label: str           # "phishing" | "legitimate" | "uncertain"
    confidence: float    # sigmoid-scaled SVM decision score in [0, 1]
    features_used: dict[str, float]
    model_version: str


def _normalise_for_blocklist(url: str) -> str:
    """Strip protocol prefix so the URL matches the blocklist CSV format."""
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            return url[len(prefix):]
    return url


def predict(url: str, app_state) -> DetectionResult:
    """Run end-to-end inference for *url* using artifacts stored in *app_state*.

    app_state must expose: .model, .scaler, .metadata, .phishing_blocklist (set by lifespan.py).
    """
    # --- Blocklist check: instant hit for known phishing URLs ---
    blocklist: frozenset[str] = getattr(app_state, "phishing_blocklist", frozenset())
    if blocklist:
        normalised = _normalise_for_blocklist(url)
        # Try exact match, then without leading www.
        if normalised in blocklist or normalised.removeprefix("www.") in blocklist:
            return DetectionResult(
                label="phishing",
                confidence=1.0,
                features_used={name: 1.0 for name in feature_extractor.FEATURE_LIST},
                model_version=app_state.metadata.get("model_version", "unknown"),
            )

    # --- Feature extraction (single source of truth in feature_extractor) ---
    features = feature_extractor.extract(url)

    if not feature_extractor.validate_feature_vector(features):
        raise FeatureExtractionError(f"Invalid feature vector extracted for: {url}")

    # --- Validate feature order against metadata before transforming ---
    feature_order: list[str] = app_state.metadata.get(
        "feature_order", feature_extractor.FEATURE_LIST
    )
    feature_vector = pd.DataFrame(
        [[features[name] for name in feature_order]], columns=feature_order
    )

    # --- Scale then predict (scaler must run before model.predict) ---
    scaled = app_state.scaler.transform(feature_vector)
    raw_label: int = int(app_state.model.predict(scaled)[0])

    # --- Map integer class index to human-readable label ---
    class_mapping: dict[str, str] = app_state.metadata.get(
        "class_mapping", {"0": "legitimate", "1": "phishing"}
    )
    label = class_mapping.get(str(raw_label), "unknown")

    # --- Confidence: sigmoid of SVM decision_function score ---
    confidence = _sigmoid_confidence(scaled, app_state.model)

    # --- Apply uncertainty threshold from config ---
    if confidence < settings.confidence_threshold:
        label = "uncertain"

    return DetectionResult(
        label=label,
        confidence=round(confidence, 4),
        features_used=features,
        model_version=app_state.metadata.get("model_version", "unknown"),
    )


def _sigmoid_confidence(scaled: np.ndarray, model) -> float:
    """Return confidence in [0, 1] for the predicted class.

    Uses predict_proba (available when model was trained with probability=True)
    which gives max(P(class_-1), P(class_1)) — always > 0.5 and symmetric for
    both phishing and legitimate predictions.

    Falls back to abs-sigmoid of decision_function, then 0.5.
    """
    try:
        proba = model.predict_proba(scaled)[0]
        return float(np.max(proba))
    except Exception:
        pass
    try:
        score = float(model.decision_function(scaled)[0])
        # Use abs so confidence is high for both strongly phishing AND strongly
        # legitimate predictions — not just for the positive (class 1) direction.
        return 1.0 / (1.0 + math.exp(-abs(score)))
    except Exception:
        return 0.5
