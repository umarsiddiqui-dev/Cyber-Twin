"""
ml_service.py – Phase 6
CyberTwin Backend Service

Wraps the CyberTwinAgent for FastAPI integration.
Loaded at startup via the lifespan hook in main.py.

Provides:
  - classify_flow(flow: dict, src_ip: str) → dict  (for /api/ml/classify)
  - enrich_label(label: str, src_ip: str)  → dict  (for action generator integration)
  - is_model_ready()                        → bool
"""

import logging
from typing import Optional

from ml_pipeline.cybertwin_core import agent, ThreatAnalysis

log = logging.getLogger(__name__)


def startup():
    """Call during FastAPI lifespan startup to load model + knowledge base."""
    try:
        agent.startup()
        log.info("[MLService] Agent loaded successfully.")
    except Exception as e:
        log.error(f"[MLService] Failed to load agent: {e}")


def is_model_ready() -> bool:
    return agent._models.is_available() and agent._models._loaded


def classify_flow(flow: dict, src_ip: str = "0.0.0.0") -> dict:
    """
    Classify a dict of CICFlowMeter network features.

    Args:
        flow:   Dict mapping feature name → float value
        src_ip: Source IP of the flow (used for defense commands)

    Returns:
        {
          "label":           str,    # e.g. "BruteForce-SSH"
          "confidence":      float,  # 0.0 – 1.0
          "risk_level":      str,    # CRITICAL / HIGH / MEDIUM / LOW / BENIGN
          "explanation":     str,
          "mitre_techniques": [...],
          "related_cves":    [...],
          "defense_linux":   str,
          "defense_windows": str,
          "defense_desc":    str,
          "src_ip":          str,
        }
    """
    try:
        analysis: ThreatAnalysis = agent.analyze(flow, src_ip)
        return _serialise(analysis)
    except Exception as e:
        log.error(f"[MLService] classify_flow error: {e}")
        return {
            "label": "Error",
            "confidence": 0.0,
            "risk_level": "UNKNOWN",
            "explanation": f"ML classification error: {e}",
            "mitre_techniques": [],
            "related_cves": [],
            "defense_linux": "",
            "defense_windows": "",
            "defense_desc": "",
            "src_ip": src_ip,
        }


def enrich_label(label: str, src_ip: str = "0.0.0.0") -> dict:
    """
    Enrich a pre-detected label with MITRE/CVE knowledge.
    Called by action_generator.py to enhance proposals.
    """
    try:
        analysis: ThreatAnalysis = agent.enrich(label, src_ip)
        return _serialise(analysis)
    except Exception as e:
        log.error(f"[MLService] enrich_label error: {e}")
        return {}


def _serialise(a: ThreatAnalysis) -> dict:
    return {
        "label":            a.threat_label,
        "confidence":       a.confidence,
        "risk_level":       a.risk_level,
        "explanation":      a.explanation,
        "mitre_techniques": a.mitre_techniques,
        "related_cves":     a.related_cves,
        "defense_linux":    a.defense_linux,
        "defense_windows":  a.defense_windows,
        "defense_desc":     a.defense_desc,
        "src_ip":           a.src_ip,
    }
