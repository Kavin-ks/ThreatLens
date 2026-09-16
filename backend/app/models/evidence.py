import enum
from typing import Optional
from sqlalchemy import String, Text, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class EvidenceType(str, enum.Enum):
    CODE_SNIPPET = "code_snippet"
    REQUEST_RESPONSE = "request_response"
    CONFIG_VALUE = "config_value"
    DEPENDENCY_RECORD = "dependency_record"
    REGEX_MATCH = "regex_match"
    SCREENSHOT = "screenshot"
    LOG_ENTRY = "log_entry"
    OTHER = "other"


class Evidence(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "evidence"

    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_type: Mapped[str] = mapped_column(SAEnum(EvidenceType), nullable=False)

    # For inline evidence (code snippets, config values, request/response pairs < 64KB)
    content: Mapped[Optional[str]] = mapped_column(Text)

    # For larger files (screenshots, large dumps) — path relative to evidence_store root
    file_path: Mapped[Optional[str]] = mapped_column(String(1024))

    # JSON metadata: {"file": "...", "start_line": 42, "end_line": 50, "language": "python"}
    metadata_json: Mapped[Optional[str]] = mapped_column(Text)

    title: Mapped[Optional[str]] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text)

    finding: Mapped["Finding"] = relationship("Finding", back_populates="evidence")
