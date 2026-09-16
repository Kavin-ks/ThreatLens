from typing import Optional
from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class AiAnalysis(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "ai_analyses"

    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("findings.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    model_used: Mapped[str] = mapped_column(String(100), default="claude-haiku-4-5-20251001")

    technical_explanation: Mapped[Optional[str]] = mapped_column(Text)
    impact_assessment: Mapped[Optional[str]] = mapped_column(Text)
    false_positive_likelihood: Mapped[Optional[str]] = mapped_column(String(20))
    false_positive_reasoning: Mapped[Optional[str]] = mapped_column(Text)
    remediation_recommendation: Mapped[Optional[str]] = mapped_column(Text)
    analyst_summary: Mapped[Optional[str]] = mapped_column(Text)
    raw_response_json: Mapped[Optional[str]] = mapped_column(Text)

    finding: Mapped["Finding"] = relationship("Finding", back_populates="ai_analysis")
