"""
v1 API routes — detection, feedback, and health.

Knows about: schemas, controllers, get_db (for dependency injection).
Does NOT know about: services, database models, or ML artifacts.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.controllers.v1.predict import handle_feedback, handle_predict
from app.database import get_db
from app.schemas.request import DetectionRequest, FeedbackRequest
from app.schemas.response import DetectionResponse, FeedbackResponse

router = APIRouter(prefix="/api/v1", tags=["detection"])


@router.post(
    "/detect",
    response_model=DetectionResponse,
    summary="Analyse a URL for phishing indicators",
)
def detect(payload: DetectionRequest, request: Request) -> DetectionResponse:
    # Sync route — FastAPI runs it in a thread pool to avoid blocking the event loop
    return handle_predict(payload, request.app.state)


@router.post(
    "/feedback",
    response_model=FeedbackResponse,
    summary="Submit a correction for a previous prediction",
)
async def feedback(
    payload: FeedbackRequest,
    db: AsyncSession = Depends(get_db),
) -> FeedbackResponse:
    return await handle_feedback(payload, db)


@router.get("/health", summary="Health check — includes artifact and model status")
def health(request: Request) -> dict:
    metadata: dict = getattr(request.app.state, "metadata", {})
    return {
        "status": "ok",
        "model_version": metadata.get("model_version", "unknown"),
        "artifact_loaded": hasattr(request.app.state, "model"),
    }
