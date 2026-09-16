import enum
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import String, Text, Integer, Float, ForeignKey, Enum as SAEnum, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class SecurityCategory(str, enum.Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INJECTION = "injection"
    XSS = "xss"
    API_SECURITY = "api_security"
    DEPENDENCIES = "dependencies"
    SECRETS = "secrets"
    CONFIGURATION = "configuration"
    SESSION = "session"
    CRYPTOGRAPHY = "cryptography"
    HEADERS = "headers"
    DATA_EXPOSURE = "data_exposure"
    SSRF = "ssrf"
    SECURE_COMMUNICATION = "secure_communication"
    RATE_LIMITING = "rate_limiting"
    PRIVACY = "privacy"
    OTHER = "other"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class FindingStatus(str, enum.Enum):
    DETECTED = "DETECTED"
    VALIDATING = "VALIDATING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    REMEDIATION = "REMEDIATION"
    RETESTING = "RETESTING"
    RESOLVED = "RESOLVED"


class Finding(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scanner_id: Mapped[str] = mapped_column(String(255), nullable=False)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(SAEnum(SecurityCategory), nullable=False)
    severity: Mapped[str] = mapped_column(SAEnum(Severity), nullable=False)
    confidence: Mapped[str] = mapped_column(SAEnum(Confidence), nullable=False)
    status: Mapped[str] = mapped_column(
        SAEnum(FindingStatus), default=FindingStatus.DETECTED, nullable=False, index=True
    )

    # Location
    affected_component: Mapped[Optional[str]] = mapped_column(String(512))
    affected_file: Mapped[Optional[str]] = mapped_column(String(1024))
    affected_line: Mapped[Optional[int]] = mapped_column(Integer)
    affected_endpoint: Mapped[Optional[str]] = mapped_column(String(2048))

    # Classification
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50))
    owasp_category: Mapped[Optional[str]] = mapped_column(String(100))
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(255))
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)

    # Impact and remediation
    impact: Mapped[Optional[str]] = mapped_column(Text)
    remediation: Mapped[Optional[str]] = mapped_column(Text)

    # Fingerprint to de-duplicate findings across scan runs
    fingerprint: Mapped[Optional[str]] = mapped_column(String(64), index=True)

    project: Mapped["Project"] = relationship("Project", back_populates="findings")
    scan_run: Mapped["ScanRun"] = relationship("ScanRun", back_populates="findings")
    evidence: Mapped[List["Evidence"]] = relationship(
        "Evidence", back_populates="finding", cascade="all, delete-orphan"
    )
    history: Mapped[List["FindingHistory"]] = relationship(
        "FindingHistory", back_populates="finding", cascade="all, delete-orphan"
    )
    remediation_records: Mapped[List["RemediationRecord"]] = relationship(
        "RemediationRecord", back_populates="finding", cascade="all, delete-orphan"
    )
    ai_analysis: Mapped[Optional["AiAnalysis"]] = relationship(
        "AiAnalysis", back_populates="finding", cascade="all, delete-orphan", uselist=False
    )


class FindingHistory(UUIDMixin, Base):
    """Audit trail for every finding status transition."""

    __tablename__ = "finding_history"

    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    from_status: Mapped[Optional[str]] = mapped_column(SAEnum(FindingStatus))
    to_status: Mapped[str] = mapped_column(SAEnum(FindingStatus), nullable=False)
    changed_by: Mapped[str] = mapped_column(String(255), default="system")
    note: Mapped[Optional[str]] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    finding: Mapped["Finding"] = relationship("Finding", back_populates="history")
