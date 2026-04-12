from typing import Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator


class DetectionRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def normalise_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        return v


class FeedbackRequest(BaseModel):
    url: HttpUrl
    predicted_label: Literal["phishing", "legitimate", "uncertain"]
    reported_label: Literal["phishing", "legitimate"]
    confidence: float = Field(ge=0.0, le=1.0)
