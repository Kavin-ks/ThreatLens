"""
ThreatLens PDF security report generator using fpdf2.
Generates a professional assessment report suitable for SIH demonstration.
"""
import io
import json
import textwrap
import unicodedata
from datetime import datetime, timezone
from typing import Optional

from fpdf import FPDF


def _safe(text: str) -> str:
    """Normalise and strip non-Latin-1 characters so fpdf2's built-in fonts accept the text."""
    if not text:
        return ""
    # NFKD decomposition maps many accented / special chars to base + combining
    normalised = unicodedata.normalize("NFKD", str(text))
    # Encode to latin-1, replacing anything that won't fit with '?'
    return normalised.encode("latin-1", errors="replace").decode("latin-1")

# --- colour palette -----------------------------------------------------------
DARK_BG   = (15, 20, 30)
SURFACE   = (26, 33, 48)
ACCENT    = (52, 130, 246)      # tl-blue
TEXT_PRI  = (220, 230, 240)
TEXT_MUT  = (120, 140, 165)

SEV_COLORS = {
    "CRITICAL": (220, 38, 38),
    "HIGH":     (234, 88, 12),
    "MEDIUM":   (202, 138, 4),
    "LOW":      (37, 99, 235),
    "INFO":     (100, 116, 139),
}
CONF_COLORS = {
    "CONFIRMED":      (239, 68, 68),
    "LIKELY":         (249, 115, 22),
    "POSSIBLE":       (234, 179, 8),
    "FALSE_POSITIVE": (100, 116, 139),
}

STATUS_LABELS = {
    "DETECTED":    "Detected",
    "VALIDATING":  "Validating",
    "CONFIRMED":   "Confirmed",
    "REJECTED":    "Rejected",
    "REMEDIATION": "In Remediation",
    "RETESTING":   "Retesting",
    "RESOLVED":    "Resolved",
}


class ThreatLensReport(FPDF):
    def __init__(self, project_name: str, target: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.project_name = project_name
        self.target = target
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(20, 20, 20)

    # -- helpers --------------------------------------------------------------

    def _bg(self, r, g, b):
        self.set_fill_color(r, g, b)

    def _text(self, r, g, b):
        self.set_text_color(r, g, b)

    def _draw_rect(self, x, y, w, h, r, g, b, *, border=False):
        self.set_fill_color(r, g, b)
        if border:
            self.set_draw_color(r, g, b)
        self.rect(x, y, w, h, "F")

    def _chip(self, x, y, label: str, bg, text_color=(255, 255, 255), width=30, height=5):
        """Draw a filled rounded-ish chip."""
        self._draw_rect(x, y, width, height, *bg)
        self.set_xy(x, y)
        self._text(*text_color)
        self.set_font("Helvetica", "B", 7)
        self.cell(width, height, label, align="C")

    # -- header / footer -------------------------------------------------------

    def header(self):
        if self.page_no() == 1:
            return
        self._draw_rect(0, 0, 210, 10, *DARK_BG)
        self._text(*TEXT_MUT)
        self.set_font("Helvetica", "", 7)
        self.set_xy(20, 3)
        self.cell(0, 4, f"ThreatLens Security Assessment  .  {self.project_name}", align="L")
        self.set_xy(-40, 3)
        self.cell(20, 4, f"Page {self.page_no()}", align="R")
        self.set_xy(20, 10)

    def footer(self):
        if self.page_no() == 1:
            return
        self._draw_rect(0, 285, 210, 12, *DARK_BG)
        self._text(*TEXT_MUT)
        self.set_font("Helvetica", "", 7)
        self.set_xy(20, 288)
        self.cell(0, 4, "CONFIDENTIAL - Authorized Assessment Only. ThreatLens v1.0", align="L")
        self.set_xy(-50, 288)
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.cell(30, 4, date_str, align="R")

    # -- section heading -------------------------------------------------------

    def section_heading(self, title: str, level: int = 1):
        self.ln(4)
        if level == 1:
            self._draw_rect(20, self.get_y(), 170, 8, *SURFACE)
            self._draw_rect(20, self.get_y(), 3, 8, *ACCENT)
            self._text(*TEXT_PRI)
            self.set_font("Helvetica", "B", 11)
            self.set_x(27)
            self.cell(163, 8, title.upper(), align="L")
            self.ln(10)
        else:
            self._text(*ACCENT)
            self.set_font("Helvetica", "B", 9)
            self.cell(0, 6, title, align="L")
            self.ln(7)

    # -- key-value row ---------------------------------------------------------

    def kv_row(self, key: str, value: str, muted_key=True):
        if muted_key:
            self._text(*TEXT_MUT)
        else:
            self._text(*TEXT_PRI)
        self.set_font("Helvetica", "", 8)
        self.cell(45, 5, _safe(key) + ":", align="L")
        self._text(*TEXT_PRI)
        self.set_font("Helvetica", "", 8)
        self.multi_cell(125, 5, _safe(str(value)))

    # -- body paragraph -------------------------------------------------------

    def body_para(self, text: str):
        self._text(*TEXT_PRI)
        self.set_font("Helvetica", "", 8)
        self.multi_cell(0, 5, _safe(str(text)))
        self.ln(2)

    # -- horizontal rule ------------------------------------------------------

    def hr(self):
        self._draw_rect(20, self.get_y(), 170, 0.3, *SURFACE)
        self.ln(3)

    # -- stat box grid --------------------------------------------------------

    def stat_grid(self, stats: list[tuple[str, str, tuple]]):
        """stats = [(label, value, color), ...]"""
        box_w = 30
        gap = 5
        x_start = 20
        y = self.get_y()
        for i, (label, value, color) in enumerate(stats):
            x = x_start + i * (box_w + gap)
            self._draw_rect(x, y, box_w, 18, *SURFACE)
            self._draw_rect(x, y, box_w, 2, *color)
            self._text(*color)
            self.set_font("Helvetica", "B", 14)
            self.set_xy(x, y + 3)
            self.cell(box_w, 8, str(value), align="C")
            self._text(*TEXT_MUT)
            self.set_font("Helvetica", "", 6.5)
            self.set_xy(x, y + 11)
            self.cell(box_w, 5, label.upper(), align="C")
        self.ln(24)


# --- main generation function --------------------------------------------------


def generate_pdf_report(
    project,
    findings,
    scan_run=None,
    title: Optional[str] = None,
) -> bytes:
    """
    Generate a PDF security assessment report.

    :param project: Project ORM object
    :param findings: list of Finding ORM objects (with evidence + remediation_records loaded)
    :param scan_run: optional ScanRun ORM object
    :param title: override report title
    :returns: PDF bytes
    """
    report_title = _safe(title or f"{project.name} - Security Assessment Report")
    target_display = _safe(project.target_url or project.target_path or "Not specified")

    pdf = ThreatLensReport(_safe(project.name), target_display)
    pdf.set_author("ThreatLens")
    pdf.set_title(_safe(report_title))

    # -- Cover page ------------------------------------------------------------
    pdf.add_page()
    # Full-page dark background
    pdf._draw_rect(0, 0, 210, 297, *DARK_BG)

    # Accent bar at top
    pdf._draw_rect(0, 0, 210, 3, *ACCENT)

    # Logo wordmark
    pdf._text(*ACCENT)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_xy(20, 40)
    pdf.cell(0, 10, "ThreatLens", align="L")
    pdf._text(*TEXT_MUT)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_xy(20, 52)
    pdf.cell(0, 6, "Security Assessment Platform", align="L")

    # Divider
    pdf._draw_rect(20, 62, 170, 0.5, *ACCENT)

    # Report title
    pdf._text(*TEXT_PRI)
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_xy(20, 72)
    pdf.multi_cell(170, 9, report_title)

    # Classification banner
    pdf._draw_rect(20, 105, 170, 10, 180, 30, 30)
    pdf._text(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_xy(20, 107)
    pdf.cell(170, 6, "CONFIDENTIAL - FOR AUTHORIZED RECIPIENTS ONLY", align="C")

    # Meta table
    pdf._draw_rect(20, 120, 170, 70, *SURFACE)
    date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")
    meta_rows = [
        ("Project",      project.name),
        ("Target",       target_display),
        ("Report Date",  date_str),
        ("Methodology",  "Static Analysis . Dynamic Testing . Manual Validation"),
        ("Prepared By",  "ThreatLens Automated Scanner v1.0"),
        ("Classification", "Confidential"),
    ]
    y = 124
    for key, val in meta_rows:
        pdf._text(*TEXT_MUT)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_xy(28, y)
        pdf.cell(40, 5, key + ":", align="L")
        pdf._text(*TEXT_PRI)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_xy(72, y)
        pdf.multi_cell(110, 5, val)
        y += 7

    # Bottom accent bar
    pdf._draw_rect(0, 294, 210, 3, *ACCENT)

    # -- Executive summary -----------------------------------------------------
    pdf.add_page()

    # Count findings by severity
    by_sev: dict[str, int] = {}
    for f in findings:
        s = f.severity if isinstance(f.severity, str) else f.severity.value
        by_sev[s] = by_sev.get(s, 0) + 1

    total = len(findings)
    critical = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)
    resolved = sum(1 for f in findings if (f.status if isinstance(f.status, str) else f.status.value) == "RESOLVED")
    open_count = total - resolved

    # Security posture
    if critical > 0:
        posture = "CRITICAL RISK"
        posture_color = SEV_COLORS["CRITICAL"]
    elif high > 0:
        posture = "HIGH RISK"
        posture_color = SEV_COLORS["HIGH"]
    elif by_sev.get("MEDIUM", 0) > 0:
        posture = "MEDIUM RISK"
        posture_color = SEV_COLORS["MEDIUM"]
    elif total > 0:
        posture = "LOW RISK"
        posture_color = SEV_COLORS["LOW"]
    else:
        posture = "SECURE"
        posture_color = (34, 197, 94)

    pdf.section_heading("1. Executive Summary")

    # Posture badge
    pdf._draw_rect(20, pdf.get_y() - 2, 170, 12, *SURFACE)
    pdf._draw_rect(20, pdf.get_y() - 2, 4, 12, *posture_color)
    pdf._text(*posture_color)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_x(28)
    pdf.cell(162, 8, f"Overall Security Posture: {posture}", align="L")
    pdf.ln(14)

    stats = [
        ("Total Findings", total,    ACCENT),
        ("Critical",       critical,  SEV_COLORS["CRITICAL"]),
        ("High",           high,      SEV_COLORS["HIGH"]),
        ("Medium",         by_sev.get("MEDIUM", 0), SEV_COLORS["MEDIUM"]),
        ("Low",            by_sev.get("LOW", 0),    SEV_COLORS["LOW"]),
    ]
    pdf.stat_grid(stats)

    pdf.body_para(
        f"This automated security assessment identified {total} potential security issue(s) "
        f"across {len(set(f.category for f in findings))} security category/categories. "
        f"Of these, {open_count} remain open and {resolved} have been resolved. "
        f"Critical and High severity findings should be addressed immediately."
    )

    pdf.kv_row("Assessment Date", date_str)
    pdf.kv_row("Target", target_display)
    if scan_run:
        pdf.kv_row("Scan Run ID", scan_run.id[:16] + "...")
        pdf.kv_row("Scan Status", scan_run.status)
    pdf.ln(4)

    # -- Severity breakdown table -----------------------------------------------
    pdf.section_heading("2. Severity Breakdown")
    headers = ["Severity", "Count", "% of Total", "Status"]
    col_w = [40, 25, 35, 70]
    # Header row
    pdf._draw_rect(20, pdf.get_y(), sum(col_w), 7, *SURFACE)
    pdf._text(*ACCENT)
    pdf.set_font("Helvetica", "B", 8)
    x = 20
    for h, w in zip(headers, col_w):
        pdf.set_xy(x, pdf.get_y())
        pdf.cell(w, 7, h, align="L")
        x += w
    pdf.ln(7)
    # Data rows
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_sev.get(sev, 0)
        pct = f"{count / total * 100:.0f}%" if total else "0%"
        recs = [f for f in findings if (f.severity if isinstance(f.severity, str) else f.severity.value) == sev]
        statuses = set(
            (f.status if isinstance(f.status, str) else f.status.value) for f in recs
        )
        status_str = ", ".join(sorted(statuses)) if statuses else "-"
        pdf._draw_rect(20, pdf.get_y(), sum(col_w), 0.3, *SURFACE)
        color = SEV_COLORS.get(sev, TEXT_MUT)
        pdf._text(*color)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_xy(20, pdf.get_y())
        pdf.cell(40, 6, sev, align="L")
        pdf._text(*TEXT_PRI)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(25, 6, str(count), align="L")
        pdf.cell(35, 6, pct, align="L")
        pdf.cell(70, 6, status_str, align="L")
        pdf.ln(6)
    pdf.ln(4)

    # -- Assessment scope -----------------------------------------------------
    pdf.section_heading("3. Assessment Scope & Target")
    pdf.kv_row("Project Name", project.name)
    if project.description:
        pdf.kv_row("Description", project.description)
    pdf.kv_row("Target", target_display)
    stack_info = {}
    if project.stack_info:
        try:
            stack_info = json.loads(project.stack_info)
        except Exception:
            pass
    if stack_info.get("languages"):
        pdf.kv_row("Languages Detected", ", ".join(stack_info["languages"]))
    if stack_info.get("frameworks"):
        pdf.kv_row("Frameworks", ", ".join(stack_info["frameworks"]))
    pdf.ln(4)

    # -- Methodology ----------------------------------------------------------
    pdf.section_heading("4. Methodology")
    pdf.body_para(
        "ThreatLens performs a multi-phase security assessment combining static source-code "
        "analysis, dynamic application testing against authorized local targets, and automated "
        "validation. All testing is conducted in a non-destructive manner against explicitly "
        "authorized targets only. No testing is performed against third-party infrastructure, "
        "production systems outside the defined scope, or without explicit authorization."
    )
    phases = [
        ("Static Analysis",    "Source code, configuration files, dependency manifests, and "
                               "secret patterns are scanned without executing the application."),
        ("Dynamic Testing",    "HTTP security headers, API endpoints, XSS reflection, and "
                               "injection vectors are tested against a local authorized instance."),
        ("Validation",         "Each finding is evaluated for confidence (CONFIRMED / LIKELY / "
                               "POSSIBLE / FALSE_POSITIVE) using scanner-specific validation logic."),
        ("Evidence Collection","Request/response pairs, code snippets, and configuration excerpts "
                               "are captured as structured evidence."),
        ("Remediation Tracking", "Findings progress through a defined lifecycle: DETECTED -> "
                               "CONFIRMED -> REMEDIATION -> RETESTING -> RESOLVED."),
    ]
    for phase, desc in phases:
        pdf._text(*ACCENT)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(50, 5, f"  {phase}:", align="L")
        pdf._text(*TEXT_PRI)
        pdf.set_font("Helvetica", "", 8)
        pdf.multi_cell(120, 5, desc)
        pdf.ln(1)
    pdf.ln(4)

    # -- Findings -------------------------------------------------------------
    pdf.section_heading("5. Findings")

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(
            f.severity if isinstance(f.severity, str) else f.severity.value, 5
        ),
    )

    if not sorted_findings:
        pdf.body_para("No security issues were detected during this assessment.")
    else:
        for idx, finding in enumerate(sorted_findings, start=1):
            sev = finding.severity if isinstance(finding.severity, str) else finding.severity.value
            conf = finding.confidence if isinstance(finding.confidence, str) else finding.confidence.value
            stat = finding.status if isinstance(finding.status, str) else finding.status.value

            sev_color = SEV_COLORS.get(sev, TEXT_MUT)
            conf_color = CONF_COLORS.get(conf, TEXT_MUT)

            # Finding header block
            y_before = pdf.get_y()
            pdf._draw_rect(20, y_before, 170, 10, *SURFACE)
            pdf._draw_rect(20, y_before, 4, 10, *sev_color)
            pdf._text(*TEXT_PRI)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_xy(27, y_before + 1)
            title_text = f"F{idx:02d}  {_safe(finding.title or '')}"
            pdf.cell(100, 5, title_text[:80], align="L")
            # Chips
            pdf._chip(132, y_before + 2.5, sev, sev_color, width=22, height=5)
            pdf._chip(158, y_before + 2.5, conf[:4], conf_color, width=18, height=5)
            pdf._chip(180, y_before + 2.5, STATUS_LABELS.get(stat, stat)[:8], SURFACE, TEXT_MUT, width=22, height=5)
            pdf.ln(12)

            # Finding detail
            if finding.cwe_id:
                pdf.kv_row("CWE", finding.cwe_id)
            if finding.owasp_category:
                pdf.kv_row("OWASP", finding.owasp_category)
            location = (
                finding.affected_endpoint
                or (f"{finding.affected_file}:{finding.affected_line}" if finding.affected_file else None)
                or finding.affected_component
            )
            if location:
                pdf.kv_row("Location", location)

            pdf.section_heading("Description", level=2)
            pdf.body_para(finding.description or "-")

            if finding.impact:
                pdf.section_heading("Impact", level=2)
                pdf.body_para(finding.impact)

            if finding.remediation:
                pdf.section_heading("Remediation", level=2)
                pdf.body_para(finding.remediation)

            # Evidence
            if hasattr(finding, "evidence") and finding.evidence:
                pdf.section_heading("Evidence", level=2)
                for ev in finding.evidence:
                    ev_type = ev.evidence_type if isinstance(ev.evidence_type, str) else ev.evidence_type.value
                    pdf._text(*TEXT_MUT)
                    pdf.set_font("Helvetica", "B", 7)
                    pdf.cell(0, 4, _safe(f"[{ev_type.upper()}]  {ev.title or ''}"), align="L")
                    pdf.ln(4)
                    if ev.content:
                        # Show first 400 chars of evidence content in monospaced style
                        content_preview = _safe(ev.content[:400])
                        if len(ev.content) > 400:
                            content_preview += "\n... (truncated)"
                        pdf._draw_rect(20, pdf.get_y(), 170, 4, *SURFACE)
                        pdf.set_y(pdf.get_y() + 1)
                        pdf._text(*TEXT_MUT)
                        pdf.set_font("Courier", "", 6.5)
                        # Wrap lines
                        for line in content_preview.split("\n")[:8]:
                            pdf.set_x(23)
                            pdf.cell(164, 3.5, _safe(line[:120]), align="L")
                            pdf.ln(3.5)
                    pdf.ln(2)

            # Remediation records / retest status
            if hasattr(finding, "remediation_records") and finding.remediation_records:
                pdf.section_heading("Remediation & Retest", level=2)
                for rec in finding.remediation_records:
                    rs = rec.retest_status if isinstance(rec.retest_status, str) else rec.retest_status.value
                    rs_color = {
                        "pending": TEXT_MUT,
                        "passed":  (34, 197, 94),
                        "failed":  SEV_COLORS["CRITICAL"],
                        "inconclusive": SEV_COLORS["MEDIUM"],
                    }.get(rs, TEXT_MUT)
                    pdf.kv_row("Remediation", rec.description)
                    if rec.applied_by:
                        pdf.kv_row("Applied By", rec.applied_by)
                    pdf._text(*rs_color)
                    pdf.set_font("Helvetica", "B", 8)
                    pdf.cell(45, 5, "Retest Status:")
                    pdf.cell(0, 5, rs.upper())
                    pdf.ln(5)
                    if rec.retest_notes:
                        pdf.kv_row("Retest Notes", rec.retest_notes)

            pdf.hr()

    # -- Security posture conclusion --------------------------------------------
    pdf.section_heading("6. Security Posture & Conclusion")

    pdf._draw_rect(20, pdf.get_y() - 2, 170, 14, *SURFACE)
    pdf._draw_rect(20, pdf.get_y() - 2, 4, 14, *posture_color)
    pdf._text(*posture_color)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_x(28)
    pdf.cell(0, 7, f"Rating: {posture}", align="L")
    pdf.ln(8)
    pdf._text(*TEXT_MUT)
    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_x(28)
    pdf.cell(0, 5, "Assessment conducted by ThreatLens Automated Security Platform")
    pdf.ln(8)

    conclusion_parts = []
    if critical > 0:
        conclusion_parts.append(
            f"{critical} CRITICAL finding(s) require immediate attention before deployment or production use."
        )
    if high > 0:
        conclusion_parts.append(
            f"{high} HIGH severity finding(s) pose significant risk and should be remediated promptly."
        )
    if resolved > 0:
        conclusion_parts.append(
            f"{resolved} finding(s) have been verified as resolved through retesting."
        )
    if not conclusion_parts:
        conclusion_parts = ["No significant security issues were detected. Maintain regular assessments."]

    pdf.body_para(" ".join(conclusion_parts))
    pdf.body_para(
        "NOTE: This report was generated by ThreatLens automated scanning. "
        "Results should be reviewed by a qualified security professional before "
        "making security decisions. Automated tools cannot detect every vulnerability type."
    )

    # Footer
    pdf._draw_rect(20, pdf.get_y() + 5, 170, 0.5, *ACCENT)
    pdf.ln(8)
    pdf._text(*TEXT_MUT)
    pdf.set_font("Helvetica", "", 7)
    pdf.cell(0, 4, "ThreatLens  .  Authorized Security Assessment Platform  .  Confidential", align="C")

    return bytes(pdf.output())
