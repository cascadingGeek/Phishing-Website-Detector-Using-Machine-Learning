"""
Prediction and feedback controllers.

Knows about: services, schemas.
Does NOT know about: HTTP request/response objects, database models, ML artifacts directly.
Artifacts are accessed via app_state passed from the route layer.
"""
from __future__ import annotations

import time

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.request import DetectionRequest, FeedbackRequest
from app.schemas.response import DetectionResponse, FeedbackResponse
from app.services import detection_service, feedback_service


_FEATURE_LABELS: dict[float, str] = {
    1.0: "suspicious",
    0.0: "neutral",
    -1.0: "safe",
}


def _humanise_features(features: dict[str, float]) -> dict[str, str]:
    """Convert raw numeric feature values to user-readable labels.

    After negation in feature_extractor.extract():
      1.0  → phishing indicator  → "suspicious"
      0.0  → uncertain/neutral   → "neutral"
     -1.0  → legitimate          → "safe"
    """
    return {name: _FEATURE_LABELS.get(val, "neutral") for name, val in features.items()}


def handle_predict(request: DetectionRequest, app_state) -> DetectionResponse:
    """Call the detection service and map the result to the HTTP response shape."""
    start = time.perf_counter()
    result = detection_service.predict(request.url, app_state)
    latency_ms = (time.perf_counter() - start) * 1000

    return DetectionResponse(
        url=request.url,
        label=result.label,
        confidence=result.confidence,
        features_used=_humanise_features(result.features_used),
        model_version=result.model_version,
        latency_ms=round(latency_ms, 2),
    )


async def handle_feedback(
    request: FeedbackRequest,
    db: AsyncSession,
) -> FeedbackResponse:
    """Persist user feedback and return a confirmation response."""
    record = await feedback_service.submit_feedback(
        url=str(request.url),
        predicted_label=request.predicted_label,
        reported_label=request.reported_label,
        confidence=request.confidence,
        db=db,
    )
    return FeedbackResponse(
        received=True,
        feedback_id=record.id,
        message="Feedback recorded. Thank you!",
    )
