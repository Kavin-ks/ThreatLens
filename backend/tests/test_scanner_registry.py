"""Tests for the scanner framework — registry, base interface, and stack detector."""
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from scanners.registry import ScannerRegistry
from scanners.base import BaseScanner
from scanners.models import (
    ScanTarget, RawFinding, ValidationResult,
    SecurityCategory, Severity, Confidence, StackType,
)
from scanners.stack_detector import StackDetector


# --- Helpers ---

class _ConcreteScanner(BaseScanner):
    scanner_id = "test.example_scanner"
    name = "Example Scanner"
    description = "A test scanner that always returns one finding."
    category = SecurityCategory.CONFIGURATION
    supported_stacks = [StackType.PYTHON]

    def can_scan(self, target: ScanTarget) -> bool:
        return target.target_path is not None

    def scan(self, target: ScanTarget) -> list:
        return [
            RawFinding(
                scanner_id=self.scanner_id,
                title="Test Finding",
                description="A test vulnerability for unit testing.",
                category=SecurityCategory.CONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.POSSIBLE,
                affected_file="test.py",
                affected_line=1,
            )
        ]


# --- Registry tests ---

class TestScannerRegistry:
    def test_register_and_retrieve(self):
        registry = ScannerRegistry()
        registry.register(_ConcreteScanner)
        scanner = registry.get("test.example_scanner")
        assert scanner is not None
        assert scanner.scanner_id == "test.example_scanner"

    def test_register_decorator(self):
        registry = ScannerRegistry()

        @registry.register
        class _Decorated(BaseScanner):
            scanner_id = "test.decorated"
            name = "Decorated Scanner"
            description = "Registered via decorator."
            category = SecurityCategory.SECRETS

            def can_scan(self, target):
                return True

            def scan(self, target):
                return []

        assert registry.get("test.decorated") is not None

    def test_register_missing_attribute_raises(self):
        registry = ScannerRegistry()

        class _BadScanner(BaseScanner):
            # Missing scanner_id, name, description, category
            def can_scan(self, target):
                return True
            def scan(self, target):
                return []

        with pytest.raises(TypeError):
            registry.register(_BadScanner)

    def test_all_returns_registered(self):
        registry = ScannerRegistry()
        registry.register(_ConcreteScanner)
        assert len(registry.all()) >= 1

    def test_for_target_filters_correctly(self):
        registry = ScannerRegistry()
        registry.register(_ConcreteScanner)

        target_with_path = ScanTarget(project_id="p1", target_path=Path("/tmp"))
        target_no_path = ScanTarget(project_id="p2")

        assert any(s.scanner_id == "test.example_scanner" for s in registry.for_target(target_with_path))
        assert not any(s.scanner_id == "test.example_scanner" for s in registry.for_target(target_no_path))

    def test_summary(self):
        registry = ScannerRegistry()
        registry.register(_ConcreteScanner)
        summary = registry.summary()
        assert isinstance(summary, list)
        assert any(s["scanner_id"] == "test.example_scanner" for s in summary)


# --- BaseScanner tests ---

class TestBaseScanner:
    def test_scan_returns_findings(self):
        scanner = _ConcreteScanner()
        target = ScanTarget(project_id="p1", target_path=Path("/tmp"))
        findings = scanner.scan(target)
        assert len(findings) == 1
        assert findings[0].scanner_id == "test.example_scanner"

    def test_validate_default_trusts_confidence(self):
        scanner = _ConcreteScanner()
        target = ScanTarget(project_id="p1", target_path=Path("/tmp"))
        finding = RawFinding(
            scanner_id="test.example_scanner",
            title="T",
            description="D",
            category=SecurityCategory.CONFIGURATION,
            severity=Severity.LOW,
            confidence=Confidence.LIKELY,
        )
        result = scanner.validate(finding, target)
        assert result.is_valid is True
        assert result.confidence == Confidence.LIKELY

    def test_collect_evidence_returns_evidence_data(self):
        scanner = _ConcreteScanner()
        target = ScanTarget(project_id="p1", target_path=Path("/tmp"))
        finding = RawFinding(
            scanner_id="test.example_scanner",
            title="T",
            description="D",
            category=SecurityCategory.CONFIGURATION,
            severity=Severity.LOW,
            confidence=Confidence.LIKELY,
            evidence_data={"type": "code_snippet", "content": "password = 'secret'"},
        )
        evidence = scanner.collect_evidence(finding, target)
        assert evidence["content"] == "password = 'secret'"


# --- StackDetector tests ---

class TestStackDetector:
    def test_empty_directory(self, tmp_path):
        detector = StackDetector()
        profile = detector.detect(tmp_path)
        assert profile.languages == []

    def test_detects_python(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("fastapi\n")
        detector = StackDetector()
        profile = detector.detect(tmp_path)
        assert StackType.PYTHON in profile.languages

    def test_detects_node(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "test", "dependencies": {}}')
        detector = StackDetector()
        profile = detector.detect(tmp_path)
        assert StackType.NODEJS in profile.languages

    def test_nonexistent_path(self):
        detector = StackDetector()
        profile = detector.detect(Path("/nonexistent/path/xyz"))
        assert profile.languages == []
