"""
Dependency vulnerability scanners.

PythonDependencyScanner  — runs pip-audit against requirements files.
NodeDependencyScanner    — runs npm audit against package-lock.json.

Both scanners gracefully return an INFO finding when their required external
tool is not available, rather than failing silently.
"""
import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from scanners.base import BaseScanner
from scanners.registry import scanner_registry
from scanners.models import (
    ScanTarget,
    RawFinding,
    SecurityCategory,
    Severity,
    Confidence,
)

_OWASP_CAT = "A06:2021 – Vulnerable and Outdated Components"


def _cvss_to_severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _npm_severity_to_tl(npm_sev: str) -> Severity:
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }.get(npm_sev.lower(), Severity.MEDIUM)


# ---------------------------------------------------------------------------
# Python scanner
# ---------------------------------------------------------------------------

@scanner_registry.register
class PythonDependencyScanner(BaseScanner):
    scanner_id = "dependencies.python_packages"
    name = "Python Dependency Vulnerability Scanner"
    description = (
        "Audits Python dependencies against known CVE/GHSA databases using pip-audit. "
        "Requires requirements.txt, Pipfile, or pyproject.toml in the target directory."
    )
    category = SecurityCategory.DEPENDENCIES
    supported_stacks = []
    cwe_ids = ["CWE-1035", "CWE-937"]

    def can_scan(self, target: ScanTarget) -> bool:
        if target.target_path is None:
            return False
        return self._find_requirements(target.target_path) is not None

    def scan(self, target: ScanTarget) -> List[RawFinding]:
        req_file = self._find_requirements(target.target_path)
        if req_file is None:
            return []

        if not shutil.which("pip-audit"):
            return [RawFinding(
                scanner_id=self.scanner_id,
                title="pip-audit not installed — Python dependency scan skipped",
                description=(
                    "pip-audit is not available in PATH. Install it with "
                    "`pip install pip-audit` to enable Python dependency scanning."
                ),
                category=SecurityCategory.DEPENDENCIES,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                affected_file=str(req_file.relative_to(target.target_path)),
                remediation="pip install pip-audit",
            )]

        return self._run_pip_audit(req_file, target.target_path)

    def _run_pip_audit(self, req_file: Path, root: Path) -> List[RawFinding]:
        try:
            result = subprocess.run(
                [
                    "pip-audit",
                    "--requirement", str(req_file),
                    "--format", "json",
                    "--no-progress-spinner",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            # pip-audit exits 1 when vulnerabilities are found — that's fine
            raw = result.stdout.strip() or result.stderr.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            return [RawFinding(
                scanner_id=self.scanner_id,
                title="pip-audit execution failed",
                description=f"pip-audit could not complete: {exc}",
                category=SecurityCategory.DEPENDENCIES,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
            )]

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: List[RawFinding] = []
        # pip-audit JSON: {"dependencies": [{name, version, vulns: [{id, description, fix_versions, aliases}]}]}
        deps = data.get("dependencies", []) if isinstance(data, dict) else data
        for dep in deps:
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "Unknown")
                desc = vuln.get("description", "No description available.")
                fix_versions = vuln.get("fix_versions", [])
                pkg = dep.get("name", "unknown")
                ver = dep.get("version", "unknown")

                findings.append(RawFinding(
                    scanner_id=self.scanner_id,
                    title=f"Vulnerable Dependency: {pkg} {ver} ({vuln_id})",
                    description=(
                        f"Python package `{pkg}` version `{ver}` has a known vulnerability: {desc}"
                    ),
                    category=SecurityCategory.DEPENDENCIES,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    affected_file=str(req_file.relative_to(root)),
                    affected_component=f"{pkg} {ver}",
                    cwe_id="CWE-1035",
                    owasp_category=_OWASP_CAT,
                    impact=(
                        f"The vulnerability {vuln_id} in `{pkg}` may allow an attacker "
                        "to exploit the affected functionality."
                    ),
                    remediation=(
                        f"Upgrade `{pkg}` to "
                        f"{', '.join(fix_versions) if fix_versions else 'the latest patched version'}. "
                        "Run `pip install --upgrade <package>` and commit updated requirements."
                    ),
                    evidence_data={
                        "type": "dependency_record",
                        "title": f"Vulnerability record: {pkg} {vuln_id}",
                        "content": json.dumps(
                            {
                                "package": pkg,
                                "version": ver,
                                "vulnerability_id": vuln_id,
                                "description": desc,
                                "fix_versions": fix_versions,
                            },
                            indent=2,
                        ),
                        "metadata": {"package": pkg, "version": ver, "vuln_id": vuln_id},
                    },
                ))
        return findings

    def _find_requirements(self, root: Path) -> Optional[Path]:
        for name in ("requirements.txt", "requirements-dev.txt", "Pipfile", "pyproject.toml"):
            p = root / name
            if p.exists():
                return p
        req_dir = root / "requirements"
        if req_dir.is_dir():
            for f in sorted(req_dir.glob("*.txt")):
                return f
        return None


# ---------------------------------------------------------------------------
# Node.js scanner
# ---------------------------------------------------------------------------

@scanner_registry.register
class NodeDependencyScanner(BaseScanner):
    scanner_id = "dependencies.node_packages"
    name = "Node.js Dependency Vulnerability Scanner"
    description = (
        "Audits Node.js dependencies against npm's vulnerability database using npm audit. "
        "Requires package-lock.json or package.json in the target directory."
    )
    category = SecurityCategory.DEPENDENCIES
    supported_stacks = []
    cwe_ids = ["CWE-1035", "CWE-937"]

    def can_scan(self, target: ScanTarget) -> bool:
        if target.target_path is None:
            return False
        return (
            (target.target_path / "package-lock.json").exists()
            or (target.target_path / "package.json").exists()
        )

    def scan(self, target: ScanTarget) -> List[RawFinding]:
        if not shutil.which("npm"):
            return [RawFinding(
                scanner_id=self.scanner_id,
                title="npm not available — Node.js dependency scan skipped",
                description="npm is not installed or not in PATH.",
                category=SecurityCategory.DEPENDENCIES,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
            )]

        return self._run_npm_audit(target.target_path)

    def _run_npm_audit(self, root: Path) -> List[RawFinding]:
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(root),
            )
            raw = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            return [RawFinding(
                scanner_id=self.scanner_id,
                title="npm audit execution failed",
                description=f"npm audit could not complete: {exc}",
                category=SecurityCategory.DEPENDENCIES,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
            )]

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: List[RawFinding] = []
        for pkg_name, info in data.get("vulnerabilities", {}).items():
            sev_str = info.get("severity", "moderate")
            severity = _npm_severity_to_tl(sev_str)

            via = info.get("via", [])
            cve_ids: List[str] = []
            titles: List[str] = []
            for v in via:
                if isinstance(v, dict):
                    raw_cwe = v.get("cwe", [])
                    cwe_list = raw_cwe if isinstance(raw_cwe, list) else [raw_cwe]
                    cve_ids.extend(str(c) for c in cwe_list if c)
                    if v.get("title"):
                        titles.append(v["title"])

            desc = "; ".join(titles) if titles else "Vulnerability in Node.js package"
            fix_available = info.get("fixAvailable", False)

            findings.append(RawFinding(
                scanner_id=self.scanner_id,
                title=f"Vulnerable Node.js Package: {pkg_name} ({sev_str})",
                description=f"npm package `{pkg_name}` has a known {sev_str} vulnerability: {desc}",
                category=SecurityCategory.DEPENDENCIES,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                affected_file="package.json",
                affected_component=pkg_name,
                cwe_id="CWE-1035",
                owasp_category=_OWASP_CAT,
                impact=(
                    f"The {sev_str} vulnerability in `{pkg_name}` may be exploitable "
                    "in the application's attack surface."
                ),
                remediation=(
                    "Run `npm audit fix` to automatically apply available patches. "
                    "For breaking fixes, use `npm audit fix --force` after reviewing changes."
                    if fix_available
                    else "No automatic fix is available. Check the npm advisory for manual remediation steps."
                ),
                evidence_data={
                    "type": "dependency_record",
                    "title": f"npm audit: {pkg_name}",
                    "content": json.dumps(
                        {
                            "package": pkg_name,
                            "severity": sev_str,
                            "description": desc,
                            "fix_available": fix_available,
                        },
                        indent=2,
                    ),
                    "metadata": {"package": pkg_name, "severity": sev_str},
                },
            ))
        return findings
