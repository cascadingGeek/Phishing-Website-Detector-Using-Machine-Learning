from typing import Literal
from uuid import UUID

from pydantic import BaseModel


class DetectionResponse(BaseModel):
    url: str
    label: Literal["phishing", "legitimate", "uncertain"]
    confidence: float        # 0.0 – 1.0 (sigmoid of SVM decision score)
    features_used: dict[str, str]  # flat dict keyed by feature name → "safe" | "neutral" | "suspicious"
    model_version: str
    latency_ms: float


class FeedbackResponse(BaseModel):
    received: bool
    feedback_id: UUID
    message: str


class ErrorResponse(BaseModel):
    detail: str
