from fastapi import APIRouter, Depends, HTTPException, Request, status

from backend.app.schemas.request import DetectionRequest
from backend.app.schemas.response import DetectionResponse
from backend.app.services.detection_service import DetectionService

router = APIRouter(prefix="/api/v1", tags=["detection"])


def _get_service(request: Request) -> DetectionService:
    return request.app.state.detection_service


@router.post(
    "/detect",
    response_model=DetectionResponse,
    summary="Analyse a URL for phishing indicators",
)
def detect(
    payload: DetectionRequest,
    service: DetectionService = Depends(_get_service),
) -> DetectionResponse:
    try:
        return service.detect(payload.url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Detection failed: {exc}",
        ) from exc


@router.get("/health", summary="Health check")
def health() -> dict[str, str]:
    return {"status": "ok"}
