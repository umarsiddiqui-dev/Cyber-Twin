"""
MITRE ATT&CK Service – Phase 2 Updated (STIX 2.0 Support)
Classifies raw log text and incident titles against the MITRE ATT&CK dataset.

Load strategy (in priority order):
  1. STIX 2.0 bundle — uses mitreattack-python MitreAttackData if
     enterprise-attack.json is present in app/data/. Most up-to-date.
  2. Local JSON keyword store — always available, no external deps.
     Used as fallback when the STIX bundle is absent or the import fails.

REPLACEMENT POINT (Phase 3+):
  To download the live STIX feed automatically:
  - Add a startup task that fetches the canonical bundle from:
    https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json
  - Save to app/data/enterprise-attack.json
  - The service will pick it up on next restart.
"""

import json
import re
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Data paths ────────────────────────────────────────────────────────────────
_DATA_DIR = Path(__file__).parent.parent / "data"
_LOCAL_JSON_PATH = _DATA_DIR / "mitre_techniques.json"
_STIX_BUNDLE_PATH = _DATA_DIR / "enterprise-attack.json"


# ── Result type ───────────────────────────────────────────────────────────────

@dataclass
class MitreMatch:
    technique_id: str       # e.g. "T1595"
    technique_name: str     # e.g. "Active Scanning"
    tactic: str             # e.g. "Reconnaissance"
    description: str
    confidence: float       # 0.0 – 1.0


# ── STIX loader ───────────────────────────────────────────────────────────────

def _load_techniques_stix() -> list[dict]:
    """
    Load techniques from a local STIX 2.0 enterprise-attack bundle.
    Converts each STIX attack-pattern object into the same keyword-dict format
    used by the local JSON store so the classify() function is unchanged.

    Returns an empty list (falling back to local JSON) if:
    - The STIX file is absent.
    - mitreattack-python is not installed.
    - Any parsing error occurs.
    """
    if not _STIX_BUNDLE_PATH.exists():
        logger.debug("[MITRE] STIX bundle not found — using local JSON dataset")
        return []

    try:
        from mitreattack.stix20 import MitreAttackData
        ma = MitreAttackData(str(_STIX_BUNDLE_PATH))
        techniques = ma.get_techniques(remove_revoked_deprecated=True)

        result: list[dict] = []
        for t in techniques:
            name: str = t.get("name", "")
            description: str = t.get("description", "")

            # Derive tactic from the kill_chain_phases list
            phases = t.get("kill_chain_phases", [])
            tactic = phases[0]["phase_name"].replace("-", " ").title() if phases else "Unknown"

            # Derive technique ID (e.g. "T1595")
            ext_refs = t.get("external_references", [])
            tid = next(
                (r.get("external_id", "") for r in ext_refs if r.get("source_name") == "mitre-attack"),
                "",
            )
            if not tid:
                continue

            # Build keyword list from name + first sentence of description
            name_words = re.findall(r"\b[a-z]{3,}\b", name.lower())
            desc_first = (description.split(".")[0] if description else "")
            desc_words = re.findall(r"\b[a-z]{4,}\b", desc_first.lower())[:10]
            keywords = list(dict.fromkeys(name_words + desc_words))  # deduplicate, preserve order

            result.append({
                "id": tid,
                "name": name,
                "tactic": tactic,
                "description": description[:300],
                "keywords": keywords,
            })

        logger.info(f"[MITRE] Loaded {len(result)} techniques from STIX bundle")
        return result

    except ImportError:
        logger.warning("[MITRE] mitreattack-python not installed — falling back to local JSON")
        return []
    except Exception as e:
        logger.error(f"[MITRE] STIX load failed: {e} — falling back to local JSON")
        return []


def _load_techniques_local() -> list[dict]:
    """Load from the bundled local JSON keyword store (always available)."""
    try:
        with open(_LOCAL_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.info(f"[MITRE] Loaded {len(data)} techniques from local JSON dataset")
        return data
    except Exception as e:
        logger.error(f"[MITRE] Failed to load local techniques: {e}")
        return []


def _load_techniques() -> list[dict]:
    """
    Load with priority: STIX bundle → local JSON fallback.
    """
    stix = _load_techniques_stix()
    if stix:
        return stix
    return _load_techniques_local()


_TECHNIQUES: list[dict] = _load_techniques()


# ── Core classifier ───────────────────────────────────────────────────────────

def classify(text: str) -> MitreMatch | None:
    """
    Score each ATT&CK technique against the input text using keyword overlap.
    Returns the highest-confidence match, or None if nothing scores above threshold.
    """
    if not text or not _TECHNIQUES:
        return None

    lower = text.lower()
    best_score = 0.0
    best_match: dict | None = None

    for technique in _TECHNIQUES:
        keywords: list[str] = technique.get("keywords", [])
        if not keywords:
            continue

        hits = sum(1 for kw in keywords if re.search(rf"\b{re.escape(kw)}\b", lower))
        if hits == 0:
            continue

        score = min(hits / max(len(keywords) * 0.4, 1), 1.0)
        if score > best_score:
            best_score = score
            best_match = technique

    if best_match and best_score >= 0.15:
        return MitreMatch(
            technique_id=best_match["id"],
            technique_name=best_match["name"],
            tactic=best_match["tactic"],
            description=best_match.get("description", ""),
            confidence=round(best_score, 3),
        )
    return None


def get_technique_by_id(technique_id: str) -> dict | None:
    """Retrieve full technique data by T-code (e.g. 'T1595')."""
    for t in _TECHNIQUES:
        if t["id"].upper() == technique_id.upper():
            return t
    return None


def list_all_techniques() -> list[dict]:
    """Return the full loaded ATT&CK dataset."""
    return _TECHNIQUES


def format_mitre_context(match: MitreMatch) -> str:
    """Build a concise ATT&CK context string for AI system prompts."""
    return (
        f"MITRE ATT&CK Match: [{match.technique_id}] {match.technique_name} "
        f"(Tactic: {match.tactic}, Confidence: {match.confidence:.0%})\n"
        f"Description: {match.description}"
    )
