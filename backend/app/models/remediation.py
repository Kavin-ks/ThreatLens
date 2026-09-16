import enum
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Text, ForeignKey, Enum as SAEnum, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class RetestStatus(str, enum.Enum):
    PENDING = "pending"
    PASSED = "passed"       # Vulnerability confirmed fixed
    FAILED = "failed"       # Vulnerability still present
    INCONCLUSIVE = "inconclusive"


class RemediationRecord(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "remediation_records"

    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    applied_by: Mapped[Optional[str]] = mapped_column(String(255))
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Git diff of the fix, if available
    patch_diff: Mapped[Optional[str]] = mapped_column(Text)

    retest_status: Mapped[str] = mapped_column(
        SAEnum(RetestStatus), default=RetestStatus.PENDING, nullable=False
    )
    retest_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    retest_notes: Mapped[Optional[str]] = mapped_column(Text)
    retest_scan_run_id: Mapped[Optional[str]] = mapped_column(String(36))

    finding: Mapped["Finding"] = relationship("Finding", back_populates="remediation_records")
