"""
AI-assisted triage service.

Security constraints (Phase 7):
- Only sends non-sensitive finding metadata — title, description, category, severity,
  affected_component, affected_file, affected_endpoint, cwe_id, owasp_category.
- Never sends: evidence content, project target_url/path, raw scanner output, secret values.
- Findings from the 'secrets' scanner or category are always skipped.
- Requires ENABLE_AI_TRIAGE=true and ANTHROPIC_API_KEY in the environment.
- AI output is clearly labelled; it never auto-confirms a finding.
"""
import json
import os
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.finding import Finding
from app.models.ai_analysis import AiAnalysis


_SKIP_SCANNERS = {"secrets_scanner", "secret_scanner"}
_SKIP_CATEGORIES = {"secrets"}


def _is_sensitive(finding: Finding) -> bool:
    return (
        finding.scanner_id in _SKIP_SCANNERS
        or str(finding.category).lower() in _SKIP_CATEGORIES
    )


def _build_prompt(finding: Finding) -> str:
    lines = [
        "You are a security analyst assistant. Analyze this security finding and provide structured triage.",
        "",
        f"Title: {finding.title}",
        f"Category: {finding.category}",
        f"Severity: {finding.severity}",
        f"Confidence: {finding.confidence}",
        f"Description: {finding.description}",
    ]
    if finding.affected_component:
        lines.append(f"Affected Component: {finding.affected_component}")
    if finding.affected_file:
        lines.append(f"Affected File: {finding.affected_file}")
    if finding.affected_line:
        lines.append(f"Affected Line: {finding.affected_line}")
    if finding.affected_endpoint:
        lines.append(f"Affected Endpoint: {finding.affected_endpoint}")
    if finding.cwe_id:
        lines.append(f"CWE: {finding.cwe_id}")
    if finding.owasp_category:
        lines.append(f"OWASP Category: {finding.owasp_category}")

    lines += [
        "",
        "Respond with a JSON object containing exactly these keys:",
        "  technical_explanation: string (2-4 sentences, technical detail about this finding type)",
        "  impact_assessment: string (1-3 sentences on potential business/security impact)",
        "  false_positive_likelihood: one of 'low', 'medium', 'high'",
        "  false_positive_reasoning: string (1-2 sentences explaining the likelihood)",
        "  remediation_recommendation: string (2-4 sentences of concrete remediation advice)",
        "  analyst_summary: string (1-2 sentences, high-level summary for a non-technical audience)",
        "",
        "Output only the JSON object, no markdown fences or extra text.",
    ]
    return "\n".join(lines)


def run_ai_triage(db: Session, finding: Finding) -> AiAnalysis:
    """
    Run AI triage on a finding and persist the result.
    Raises RuntimeError if AI triage is disabled or the API key is missing.
    Raises ValueError if the finding is sensitive (secrets category/scanner).
    """
    if not settings.ENABLE_AI_TRIAGE:
        raise RuntimeError("AI triage is disabled (ENABLE_AI_TRIAGE=false)")

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")

    if _is_sensitive(finding):
        raise ValueError(
            f"Skipping AI triage for sensitive finding (scanner={finding.scanner_id}, "
            f"category={finding.category})"
        )

    try:
        import anthropic  # type: ignore
    except ImportError:
        raise RuntimeError("anthropic package is not installed. Run: pip install anthropic")

    client = anthropic.Anthropic(api_key=api_key)
    prompt = _build_prompt(finding)

    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    raw_text = message.content[0].text.strip()

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {}

    # Upsert: one AiAnalysis per finding
    existing = db.get(AiAnalysis, finding.id) if hasattr(finding, "ai_analysis") else None
    # Query directly by finding_id to handle upsert
    from sqlalchemy import select as sa_select
    existing = db.execute(
        sa_select(AiAnalysis).where(AiAnalysis.finding_id == finding.id)
    ).scalar_one_or_none()

    if existing:
        analysis = existing
    else:
        analysis = AiAnalysis(finding_id=finding.id)
        db.add(analysis)

    analysis.model_used = "claude-haiku-4-5-20251001"
    analysis.technical_explanation = parsed.get("technical_explanation")
    analysis.impact_assessment = parsed.get("impact_assessment")
    analysis.false_positive_likelihood = parsed.get("false_positive_likelihood")
    analysis.false_positive_reasoning = parsed.get("false_positive_reasoning")
    analysis.remediation_recommendation = parsed.get("remediation_recommendation")
    analysis.analyst_summary = parsed.get("analyst_summary")
    analysis.raw_response_json = raw_text

    db.commit()
    db.refresh(analysis)
    return analysis
