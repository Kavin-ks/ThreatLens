"""
Data classes for scanner inputs and outputs.
These are pure data structures — no database imports.
"""
import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any


class StackType(str, enum.Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    NODEJS = "nodejs"
    JAVA = "java"
    GO = "go"
    RUBY = "ruby"
    PHP = "php"
    DOTNET = "dotnet"
    RUST = "rust"
    UNKNOWN = "unknown"


class SecurityCategory(str, enum.Enum):
    """Mirror of app.models.finding.SecurityCategory for scanner-layer use."""
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


@dataclass
class StackProfile:
    """Technology stack detected for a scan target."""
    languages: List[StackType] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    package_managers: List[str] = field(default_factory=list)
    has_api: bool = False
    has_frontend: bool = False
    raw_indicators: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanTarget:
    """Describes what a scanner is operating against."""
    project_id: str
    target_path: Optional[Path] = None
    target_url: Optional[str] = None
    stack_profile: Optional[StackProfile] = None
    # Additional metadata passed from the scan config
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RawFinding:
    """
    A finding emitted by a scanner before validation and evidence collection.
    All findings start as RawFindings; confirmed ones are persisted as Finding ORM objects.
    """
    scanner_id: str
    title: str
    description: str
    category: SecurityCategory
    severity: Severity
    confidence: Confidence

    # Location
    affected_component: Optional[str] = None
    affected_file: Optional[str] = None
    affected_line: Optional[int] = None
    affected_endpoint: Optional[str] = None

    # Classification hints
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

    # Impact and remediation (can be overridden by scanner)
    impact: Optional[str] = None
    remediation: Optional[str] = None

    # Raw evidence data to be structured by evidence collector
    evidence_data: Optional[Dict[str, Any]] = None

    # Arbitrary scanner metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Result of a scanner's validate() method for a given RawFinding."""
    is_valid: bool
    confidence: Confidence
    notes: str = ""
    # If False, the finding is marked FALSE_POSITIVE and archived
