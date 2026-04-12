"""initial schema

Revision ID: 4609fac29b6d
Revises:
Create Date: 2026-03-31 07:52:40.337792

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '4609fac29b6d'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create labeled_urls and feedback_queue tables."""
    op.create_table(
        "labeled_urls",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column(
            "label",
            sa.Enum("phishing", "legitimate", "unknown", name="label_enum"),
            nullable=False,
            server_default="unknown",
        ),
        sa.Column("source", sa.Text, nullable=True),
        sa.Column("features_json", postgresql.JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )

    op.create_table(
        "feedback_queue",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("predicted_label", sa.Text, nullable=False),
        sa.Column("reported_label", sa.Text, nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("prediction_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reviewed", sa.Boolean, nullable=False, server_default="false"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    """Drop feedback_queue and labeled_urls tables."""
    op.drop_table("feedback_queue")
    op.drop_table("labeled_urls")
    op.execute("DROP TYPE IF EXISTS label_enum")
