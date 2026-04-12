"""Core package — configuration, exceptions, logging, and app lifespan."""

from app.core.config import settings
from app.core.exceptions import (
    ArtifactLoadError,
    FeatureExtractionError,
    FeedbackError,
    PhishingDetectorError,
)
from app.core.lifespan import lifespan

__all__ = [
    "settings",
    "lifespan",
    "PhishingDetectorError",
    "ArtifactLoadError",
    "FeatureExtractionError",
    "FeedbackError",
]
