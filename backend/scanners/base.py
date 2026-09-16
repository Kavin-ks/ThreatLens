"""
BaseScanner — the abstract interface every ThreatLens scanner must implement.

Adding a new scanner:
1. Create a Python file in scanners/<category>/
2. Subclass BaseScanner and set the class-level metadata attributes
3. Implement can_scan(), scan(), and optionally validate() and collect_evidence()
4. Decorate with @scanner_registry.register

Example:
    from scanners.base import BaseScanner
    from scanners.registry import scanner_registry
    from scanners.models import ScanTarget, RawFinding, ValidationResult, SecurityCategory, Severity, Confidence

    @scanner_registry.register
    class HardcodedPasswordScanner(BaseScanner):
        scanner_id = "secrets.hardcoded_password"
        name = "Hardcoded Password Detector"
        description = "Detects plaintext passwords embedded in source code."
        category = SecurityCategory.SECRETS
        supported_stacks = []  # empty = all stacks

        def can_scan(self, target: ScanTarget) -> bool:
            return target.target_path is not None

        def scan(self, target: ScanTarget) -> list[RawFinding]:
            ...
"""
from abc import ABC, abstractmethod
from typing import ClassVar, Dict, Any, List, Optional
from scanners.models import (
    ScanTarget,
    RawFinding,
    ValidationResult,
    SecurityCategory,
    StackType,
    Severity,
    Confidence,
)


class BaseScanner(ABC):
    # --- Required class-level metadata ---

    #: Unique dot-separated identifier, e.g. "secrets.hardcoded_api_key"
    scanner_id: ClassVar[str]

    #: Human-readable name shown in the UI
    name: ClassVar[str]

    #: One-sentence description of what this scanner detects
    description: ClassVar[str]

    #: Primary security category
    category: ClassVar[SecurityCategory]

    # --- Optional class-level metadata ---

    #: Stack types this scanner is relevant for. Empty list = all stacks.
    supported_stacks: ClassVar[List[StackType]] = []

    #: Whether this scanner requires a running application (dynamic) or only source (static)
    requires_running_app: ClassVar[bool] = False

    #: CWE IDs this scanner can detect (for reference)
    cwe_ids: ClassVar[List[str]] = []

    # -------------------------------------------------------------------------
    # Required methods
    # -------------------------------------------------------------------------

    @abstractmethod
    def can_scan(self, target: ScanTarget) -> bool:
        """
        Return True if this scanner can operate on the given target.
        Should be cheap — no I/O. Check target_path presence, stack type, etc.
        """

    @abstractmethod
    def scan(self, target: ScanTarget) -> List[RawFinding]:
        """
        Run the scan and return a list of raw (unvalidated) findings.
        Must not raise — catch and log internal errors, return partial results.
        """

    # -------------------------------------------------------------------------
    # Optional methods — provide useful defaults
    # -------------------------------------------------------------------------

    def validate(self, finding: RawFinding, target: ScanTarget) -> ValidationResult:
        """
        Attempt to confirm or reject a raw finding.
        Default: trust the scanner's confidence as-is.
        Override to add context-specific validation logic.
        """
        return ValidationResult(
            is_valid=finding.confidence != Confidence.FALSE_POSITIVE,
            confidence=finding.confidence,
            notes="No additional validation performed.",
        )

    def collect_evidence(self, finding: RawFinding, target: ScanTarget) -> Dict[str, Any]:
        """
        Collect structured evidence for a confirmed finding.
        Returns a dict that will be serialized into an Evidence DB record.
        Default: return the evidence_data already attached to the RawFinding.
        """
        return finding.evidence_data or {}

    # -------------------------------------------------------------------------
    # Utility helpers available to all scanners
    # -------------------------------------------------------------------------

    def _read_file_lines(self, path, start: int, end: int) -> Optional[str]:
        """Safely read a slice of a file for code snippet evidence."""
        try:
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()
            return "".join(lines[max(0, start - 1): end])
        except OSError:
            return None

    def __repr__(self) -> str:
        return f"<Scanner id={self.scanner_id!r} category={self.category!r}>"
