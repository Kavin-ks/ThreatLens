"""
Pure-Python CVSS v3.1 base-score calculator.
Reference: https://www.first.org/cvss/v3.1/specification-document
"""
import math
from typing import Tuple, Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED   = {"N": 0.85, "L": 0.50, "H": 0.08}
_UI  = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0,  "L": 0.22, "H": 0.56}


def _roundup(val: float) -> float:
    """Round up to nearest 0.1 (CVSS-mandated rounding)."""
    return math.ceil(val * 10) / 10


def _parse_vector(vector: str) -> dict:
    """Parse 'CVSS:3.1/AV:N/AC:L/...' into a dict."""
    parts = vector.replace("CVSS:3.1/", "").split("/")
    return {k: v for part in parts if ":" in part for k, v in [part.split(":", 1)]}


def calculate_cvss31(vector: str) -> Tuple[float, str]:
    """
    Calculate CVSS v3.1 base score from a vector string.
    Returns (score, severity_label).  Raises ValueError on malformed input.
    """
    m = _parse_vector(vector)
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - m.keys()
    if missing:
        raise ValueError(f"Missing CVSS metrics: {missing}")

    av  = _AV.get(m["AV"])
    ac  = _AC.get(m["AC"])
    scope_changed = m["S"] == "C"
    pr  = (_PR_CHANGED if scope_changed else _PR_UNCHANGED).get(m["PR"])
    ui  = _UI.get(m["UI"])
    c   = _CIA.get(m["C"])
    i   = _CIA.get(m["I"])
    a   = _CIA.get(m["A"])

    if any(x is None for x in (av, ac, pr, ui, c, i, a)):
        raise ValueError(f"Invalid metric values in CVSS vector: {vector}")

    iss = 1 - (1 - c) * (1 - i) * (1 - a)

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        score = _roundup(min(impact + exploitability, 10.0))

    return score, score_to_severity(score)


def score_to_severity(score: float) -> str:
    if score == 0.0:
        return "NONE"
    elif score < 4.0:
        return "LOW"
    elif score < 7.0:
        return "MEDIUM"
    elif score < 9.0:
        return "HIGH"
    return "CRITICAL"


def default_vector_for_severity(severity: str) -> Optional[str]:
    """Return a conservative default CVSS vector for a finding severity."""
    return {
        "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "HIGH":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "MEDIUM":   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "LOW":      "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
        "INFO":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    }.get(severity.upper())
