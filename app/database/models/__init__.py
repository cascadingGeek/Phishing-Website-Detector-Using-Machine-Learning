"""Export all ORM models so Alembic's env.py can discover them via Base.metadata."""

from app.database.models.feedback import FeedbackQueue
from app.database.models.url import LabeledURL

__all__ = ["LabeledURL", "FeedbackQueue"]
