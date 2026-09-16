"""
RetestService — re-runs a specific scanner for a finding and updates the remediation record.

Only runs against local, authorized targets (enforced via scanner.can_scan()).
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select

from scanners.registry import scanner_registry
from scanners.models import ScanTarget

logger = logging.getLogger(__name__)


def _fingerprint(raw) -> str:
    key = f"{raw.scanner_id}:{raw.affected_file}:{raw.affected_line}:{raw.title}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def run_retest(
    db: Session,
    finding_id: str,
    remediation_id: str,
    notes: str = "",
) -> str:
    """
    Re-run the scanner that produced the finding.
    Returns the retest_status: 'passed' | 'failed' | 'inconclusive'.
    """
    from app.models.finding import Finding, FindingHistory, FindingStatus
    from app.models.remediation import RemediationRecord, RetestStatus
    from app.models.project import Project

    finding = db.execute(
        select(Finding).where(Finding.id == finding_id)
    ).scalar_one_or_none()
    if not finding:
        raise ValueError(f"Finding {finding_id} not found")

    rec = db.execute(
        select(RemediationRecord).where(RemediationRecord.id == remediation_id)
    ).scalar_one_or_none()
    if not rec:
        raise ValueError(f"RemediationRecord {remediation_id} not found")

    project = db.get(Project, finding.project_id)
    if not project:
        raise ValueError("Project not found")

    scanner_registry.autodiscover()
    scanner = scanner_registry.get(finding.scanner_id)
    if not scanner:
        rec.retest_status = RetestStatus.INCONCLUSIVE
        rec.retest_notes = (
            f"Scanner '{finding.scanner_id}' is no longer registered; cannot retest. {notes}"
        ).strip()
        rec.retest_at = datetime.now(timezone.utc)
        db.commit()
        return "inconclusive"

    config = {}
    if project.stack_info:
        try:
            config = json.loads(project.stack_info)
        except Exception:
            pass

    target = ScanTarget(
        project_id=project.id,
        target_path=Path(project.target_path) if project.target_path else None,
        target_url=project.target_url,
    )

    if not scanner.can_scan(target):
        rec.retest_status = RetestStatus.INCONCLUSIVE
        rec.retest_notes = (
            f"Scanner cannot run against this target (target not applicable or not local). {notes}"
        ).strip()
        rec.retest_at = datetime.now(timezone.utc)
        db.commit()
        return "inconclusive"

    try:
        raw_findings = scanner.scan(target)
    except Exception as exc:
        logger.exception("Retest scan raised for finding %s: %s", finding_id, exc)
        rec.retest_status = RetestStatus.INCONCLUSIVE
        rec.retest_notes = f"Scanner error during retest: {exc}. {notes}".strip()
        rec.retest_at = datetime.now(timezone.utc)
        db.commit()
        return "inconclusive"

    # Check if the same fingerprint reappears
    original_fp = finding.fingerprint
    retest_fps = {_fingerprint(r) for r in raw_findings}

    if original_fp and original_fp in retest_fps:
        retest_status = RetestStatus.FAILED
        status_label = "failed"
        history_note = f"Retest FAILED — vulnerability still present. {notes}".strip()
    else:
        retest_status = RetestStatus.PASSED
        status_label = "passed"
        history_note = f"Retest PASSED — vulnerability no longer detected. {notes}".strip()

    rec.retest_status = retest_status
    rec.retest_notes = history_note
    rec.retest_at = datetime.now(timezone.utc)
    db.commit()

    # Auto-resolve the finding if retest passed
    if retest_status == RetestStatus.PASSED:
        from app.models.finding import FindingHistory, FindingStatus
        old_status = finding.status
        finding.status = FindingStatus.RESOLVED
        db.add(FindingHistory(
            finding_id=finding.id,
            from_status=old_status,
            to_status=FindingStatus.RESOLVED,
            changed_by="retest",
            note=history_note,
        ))
        db.commit()

    return status_label
