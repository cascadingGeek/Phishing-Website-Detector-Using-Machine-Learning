"""Application-level exceptions — no imports from other app layers."""


class PhishingDetectorError(Exception):
    """Base exception for all application errors."""


class ArtifactLoadError(PhishingDetectorError):
    """Raised when ML artifacts cannot be found, loaded, or validated."""


class FeatureExtractionError(PhishingDetectorError):
    """Raised when feature extraction produces an invalid vector."""


class FeedbackError(PhishingDetectorError):
    """Raised when a feedback submission fails."""
