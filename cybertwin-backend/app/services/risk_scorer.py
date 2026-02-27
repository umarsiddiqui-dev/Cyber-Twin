"""
Risk Scoring Service
Computes a composite 0–10 risk score for each incident.

Formula:
    risk_score = (severity_base × 0.50)
               + (mitre_confidence × 10 × 0.30)
               + (source_reliability × 10 × 0.20)

Clamped to [0.0, 10.0] and rounded to 2 decimal places.

REPLACEMENT POINT (Phase 4+):
  Replace this formula with an ML model trained on confirmed incidents.
  The function signature must remain identical.
"""

from app.services.mitre_service import MitreMatch

# ── Severity → base score ────────────────────────────────────────────────────
_SEVERITY_BASE: dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH":      7.5,
    "MEDIUM":    5.0,
    "LOW":       2.5,
    "INFO":      0.5,
}

# ── Source reliability weight ─────────────────────────────────────────────────
_SOURCE_RELIABILITY: dict[str, float] = {
    "snort":      0.90,   # Signature-based IDS — high signal
    "ossec":      0.85,   # Host-based — high signal
    "firewall":   0.75,   # Firewall deny — moderate signal
    "simulator":  0.60,   # Generated — lower weight in scoring
    "manual":     0.50,
    "unknown":    0.40,
}


def score(
    severity: str,
    source: str = "unknown",
    mitre_match: MitreMatch | None = None,
) -> float:
    """
    Compute a composite risk score for an incident.

    Args:
        severity:    Severity string (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        source:      Alert source (snort/ossec/simulator/…)
        mitre_match: Optional MITRE match from mitre_service.classify()

    Returns:
        Risk score in [0.0, 10.0]
    """
    sev_base       = _SEVERITY_BASE.get(severity.upper(), 1.0)
    source_weight  = _SOURCE_RELIABILITY.get(source.lower(), 0.40)
    mitre_conf     = mitre_match.confidence if mitre_match else 0.0

    raw = (
        sev_base * 0.50
        + mitre_conf * 10.0 * 0.30
        + source_weight * 10.0 * 0.20
    )
    return round(min(max(raw, 0.0), 10.0), 2)


def score_label(score_val: float) -> str:
    """Map a numeric score to a human-readable label."""
    if score_val >= 8.5: return "CRITICAL"
    if score_val >= 6.5: return "HIGH"
    if score_val >= 4.0: return "MEDIUM"
    if score_val >= 2.0: return "LOW"
    return "INFO"
