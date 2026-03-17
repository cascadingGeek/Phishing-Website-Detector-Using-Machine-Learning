from pydantic import BaseModel, HttpUrl, field_validator


class DetectionRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def normalise_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        return v
