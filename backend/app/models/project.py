import enum
from typing import Optional, List
from sqlalchemy import String, Text, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class ProjectStatus(str, enum.Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class Project(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    target_path: Mapped[Optional[str]] = mapped_column(String(1024))
    target_url: Mapped[Optional[str]] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(
        SAEnum(ProjectStatus), default=ProjectStatus.ACTIVE, nullable=False
    )
    # JSON blob: {"languages": [...], "frameworks": [...], "detected_at": "..."}
    stack_info: Mapped[Optional[str]] = mapped_column(Text)

    scan_runs: Mapped[List["ScanRun"]] = relationship(
        "ScanRun", back_populates="project", cascade="all, delete-orphan", lazy="select"
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="project", cascade="all, delete-orphan", lazy="select"
    )
