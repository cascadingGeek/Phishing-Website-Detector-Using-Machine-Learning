"""ORM model for the labeled_urls table.

Stores URLs with ground-truth labels for model training/retraining.
No imports from services, schemas, or routes.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.engine import Base


class LabelEnum(str, enum.Enum):
    phishing = "phishing"
    legitimate = "legitimate"
    unknown = "unknown"


class LabeledURL(Base):
    __tablename__ = "labeled_urls"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[LabelEnum] = mapped_column(
        Enum(LabelEnum, name="label_enum"),
        default=LabelEnum.unknown,
        nullable=False,
    )
    # Where this label came from (e.g. "phishtank", "alexa", "user_report")
    source: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Feature vector captured at labelling time — used for offline analysis
    features_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
