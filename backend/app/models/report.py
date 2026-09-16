import enum
from typing import Optional
from sqlalchemy import String, Text, LargeBinary, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class ReportFormat(str, enum.Enum):
    PDF = "pdf"
    HTML = "html"


class SecurityReport(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "security_reports"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True
    )
    format: Mapped[str] = mapped_column(
        SAEnum(ReportFormat), default=ReportFormat.PDF, nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    generated_by: Mapped[Optional[str]] = mapped_column(String(255))
    report_data: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text)

    project: Mapped["Project"] = relationship("Project")
    scan_run: Mapped[Optional["ScanRun"]] = relationship("ScanRun")
