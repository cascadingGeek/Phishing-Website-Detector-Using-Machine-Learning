"""Export all v1 controller functions."""

from app.controllers.v1.predict import handle_feedback, handle_predict

__all__ = ["handle_predict", "handle_feedback"]
