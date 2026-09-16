import enum
from typing import Optional, List
from sqlalchemy import String, Text, Integer, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanRun(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scan_runs"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        SAEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False
    )
    # JSON: {"scanners": ["secrets.hardcoded", ...], "target_path": "...", "options": {...}}
    scanner_config: Mapped[Optional[str]] = mapped_column(Text)
    # JSON: {"total": 0, "confirmed": 0, "by_severity": {...}, "duration_s": 0}
    summary: Mapped[Optional[str]] = mapped_column(Text)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255))

    project: Mapped["Project"] = relationship("Project", back_populates="scan_runs")
    scanner_results: Mapped[List["ScannerResult"]] = relationship(
        "ScannerResult", back_populates="scan_run", cascade="all, delete-orphan"
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="scan_run", cascade="all, delete-orphan"
    )


class ScannerResult(UUIDMixin, TimestampMixin, Base):
    """Per-scanner output record within a scan run."""

    __tablename__ = "scanner_results"

    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scanner_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    raw_finding_count: Mapped[int] = mapped_column(Integer, default=0)
    confirmed_finding_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    scan_run: Mapped["ScanRun"] = relationship("ScanRun", back_populates="scanner_results")
