"""Export the v1 router for inclusion in main.py."""

from app.routes.v1.predict import router

__all__ = ["router"]
