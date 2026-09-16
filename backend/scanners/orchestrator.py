"""
ScanOrchestrator — coordinates scanner execution for a scan run.

Responsibilities:
  1. Run stack detection on the target
  2. Select applicable scanners (all or the specified subset)
  3. Execute each scanner, catch failures gracefully
  4. Validate findings and collect evidence
  5. Persist findings to the database
  6. Return a summary dict
"""
import hashlib
import json
import logging
import time
from typing import Optional, List, Dict, Any

from sqlalchemy.orm import Session

from scanners.models import ScanTarget
from scanners.registry import scanner_registry
from scanners.stack_detector import StackDetector

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self, db: Session):
        self.db = db
        self.stack_detector = StackDetector()
        # Ensure all scanners are loaded
        scanner_registry.autodiscover()

    def run(
        self,
        scan_run,  # ScanRun ORM object (avoids circular import)
        target: ScanTarget,
        scanner_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        from app.models.scan import ScannerResult, ScanStatus
        from app.models.finding import Finding, FindingStatus, FindingHistory

        # 1. Stack detection
        if target.target_path and target.stack_profile is None:
            target.stack_profile = self.stack_detector.detect(target.target_path)
            # Persist stack info on the project
            project = self.db.get(
                __import__("app.models.project", fromlist=["Project"]).Project,
                target.project_id,
            )
            if project:
                project.stack_info = json.dumps({
                    "languages": [l.value for l in target.stack_profile.languages],
                    "frameworks": target.stack_profile.frameworks,
                    "package_managers": target.stack_profile.package_managers,
                })
                self.db.commit()

        # 2. Select scanners
        if scanner_ids:
            scanners = scanner_registry.by_ids(scanner_ids)
        else:
            scanners = scanner_registry.for_target(target)

        logger.info("Running %d scanner(s) for scan_run=%s", len(scanners), scan_run.id)

        total_raw = 0
        total_confirmed = 0
        by_severity: Dict[str, int] = {}

        for scanner in scanners:
            scanner_result = ScannerResult(
                scan_run_id=scan_run.id,
                scanner_id=scanner.scanner_id,
                status="running",
            )
            self.db.add(scanner_result)
            self.db.commit()

            t0 = time.monotonic()
            raw_findings = []
            error = None

            try:
                raw_findings = scanner.scan(target)
            except Exception as exc:
                error = str(exc)
                logger.exception("Scanner %s raised: %s", scanner.scanner_id, exc)

            duration_ms = int((time.monotonic() - t0) * 1000)

            confirmed_count = 0
            for raw in raw_findings:
                # Validate
                try:
                    validation = scanner.validate(raw, target)
                except Exception as exc:
                    logger.warning("validate() raised for %s: %s", scanner.scanner_id, exc)
                    from scanners.models import ValidationResult, Confidence as SC
                    validation = ValidationResult(is_valid=True, confidence=raw.confidence)

                if not validation.is_valid:
                    raw.confidence = "FALSE_POSITIVE"

                # Persist finding
                finding = Finding(
                    project_id=target.project_id,
                    scan_run_id=scan_run.id,
                    scanner_id=raw.scanner_id,
                    title=raw.title,
                    description=raw.description,
                    category=raw.category,
                    severity=raw.severity,
                    confidence=validation.confidence,
                    status=FindingStatus.DETECTED,
                    affected_component=raw.affected_component,
                    affected_file=raw.affected_file,
                    affected_line=raw.affected_line,
                    affected_endpoint=raw.affected_endpoint,
                    cwe_id=raw.cwe_id,
                    owasp_category=raw.owasp_category,
                    impact=raw.impact,
                    remediation=raw.remediation,
                    fingerprint=_fingerprint(raw),
                )
                self.db.add(finding)
                self.db.flush()  # get the finding.id

                # History entry
                self.db.add(FindingHistory(
                    finding_id=finding.id,
                    from_status=None,
                    to_status=FindingStatus.DETECTED,
                    changed_by="scanner",
                    note=f"Detected by {scanner.scanner_id}",
                ))

                # Evidence
                try:
                    evidence_data = scanner.collect_evidence(raw, target)
                    if evidence_data:
                        self._persist_evidence(finding.id, raw, evidence_data)
                except Exception as exc:
                    logger.warning("collect_evidence() raised for %s: %s", scanner.scanner_id, exc)

                if validation.is_valid:
                    confirmed_count += 1
                    sev = raw.severity if isinstance(raw.severity, str) else raw.severity.value
                    by_severity[sev] = by_severity.get(sev, 0) + 1

            total_raw += len(raw_findings)
            total_confirmed += confirmed_count

            scanner_result.status = "completed" if not error else "failed"
            scanner_result.raw_finding_count = len(raw_findings)
            scanner_result.confirmed_finding_count = confirmed_count
            scanner_result.duration_ms = duration_ms
            scanner_result.error_message = error
            self.db.commit()

        summary = {
            "total_raw": total_raw,
            "total_confirmed": total_confirmed,
            "by_severity": by_severity,
            "scanner_count": len(scanners),
        }
        logger.info("Scan run %s complete: %s", scan_run.id, summary)
        return summary

    def _persist_evidence(self, finding_id: str, raw, evidence_data: dict):
        from app.models.evidence import Evidence, EvidenceType
        evidence = Evidence(
            finding_id=finding_id,
            evidence_type=evidence_data.get("type", EvidenceType.OTHER),
            content=evidence_data.get("content"),
            metadata_json=json.dumps(evidence_data.get("metadata", {})),
            title=evidence_data.get("title"),
            description=evidence_data.get("description"),
        )
        self.db.add(evidence)


def _fingerprint(raw) -> str:
    """Generate a stable fingerprint to de-duplicate findings."""
    key = f"{raw.scanner_id}:{raw.affected_file}:{raw.affected_line}:{raw.title}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]
