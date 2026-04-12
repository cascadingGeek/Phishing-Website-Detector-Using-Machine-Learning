"""
Feedback service — the only place that writes to the feedback_queue table.

Knows about: database models, sqlalchemy session.
Does NOT know about: HTTP, schemas, ML artifacts.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models.feedback import FeedbackQueue


async def submit_feedback(
    url: str,
    predicted_label: str,
    reported_label: str,
    confidence: float,
    db: AsyncSession,
) -> FeedbackQueue:
    """Insert one feedback row and return the persisted record."""
    record = FeedbackQueue(
        url=url,
        predicted_label=predicted_label,
        reported_label=reported_label,
        confidence=confidence,
        # prediction_id left null until a prediction-log table is added
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record
