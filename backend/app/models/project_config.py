from typing import Optional
from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class ProjectConfig(UUIDMixin, TimestampMixin, Base):
    """Per-project scanner settings and authorized targets."""

    __tablename__ = "project_configs"

    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    # JSON array of scanner IDs that are enabled; null means all enabled
    enabled_scanners_json: Mapped[Optional[str]] = mapped_column(Text)
    # JSON array of authorized target URLs/paths for dynamic scanning
    authorized_targets_json: Mapped[Optional[str]] = mapped_column(Text)

    project: Mapped["Project"] = relationship("Project", back_populates="scanner_config")
