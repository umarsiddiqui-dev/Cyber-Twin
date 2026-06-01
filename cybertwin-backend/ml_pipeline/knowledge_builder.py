"""
knowledge_builder.py – Phase 6
CyberTwin ML Pipeline

Parses two knowledge sources:
  1. MITRE ATT&CK STIX bundle  → mitre_index.json
  2. NVD CVE feed              → cve_index.json

Both are saved to app/data/ for fast runtime lookups.
This script is run ONCE; the outputs are committed to the repo.

Usage:
  python ml_pipeline/knowledge_builder.py
"""

import json, logging, re
from pathlib import Path
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("knowledge_builder")

# ── Source paths ───────────────────────────────────────────────────────────────
BASE    = Path("C:/Users/Abiha Afzal/Documents/FINALYP/fyp dataset")
STIX    = BASE / "cti-master/cti-master/enterprise-attack/enterprise-attack.json"
NVD     = BASE / "nvdcve-2.0-modified.json/nvdcve-2.0-modified.json"

# ── Output paths ───────────────────────────────────────────────────────────────
OUT_DIR = Path(__file__).parent.parent / "app" / "data"
OUT_DIR.mkdir(parents=True, exist_ok=True)
MITRE_OUT = OUT_DIR / "mitre_index.json"
CVE_OUT   = OUT_DIR / "cve_index.json"


# ═══════════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK STIX Parser
# ═══════════════════════════════════════════════════════════════════════════════

def parse_mitre(stix_path: Path) -> dict:
    """
    Parse the ATT&CK STIX bundle and build a lookup dict:
      {
        "T1059":  {
          "id": "T1059",
          "name": "Command and Scripting Interpreter",
          "tactic": ["Execution"],
          "description": "...",
          "detection": "...",
          "platforms": ["Windows","Linux","macOS"],
          "kill_chain": ["execution"],
          "url": "https://attack.mitre.org/techniques/T1059/"
        }, ...
      }
    Also builds a keyword → technique ID reverse index for fast matching.
    """
    log.info(f"Parsing MITRE ATT&CK STIX: {stix_path}")
    with open(stix_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])
    log.info(f"  STIX objects: {len(objects):,}")

    techniques = {}
    keyword_index: dict[str, list[str]] = defaultdict(list)  # keyword → [tech_id]

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            continue

        # Extract technique ID
        ext_refs = obj.get("external_references", [])
        mitre_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
        if not mitre_ref:
            continue
        tech_id = mitre_ref.get("external_id", "")
        if not tech_id.startswith("T"):
            continue

        # Tactics from kill-chain
        kill_chain = obj.get("kill_chain_phases", [])
        tactics = [kp["phase_name"].replace("-", " ").title() for kp in kill_chain]

        # Platforms
        platforms = obj.get("x_mitre_platforms", [])

        # Detection guidance
        detection = obj.get("x_mitre_detection", "")

        entry = {
            "id":          tech_id,
            "name":        obj.get("name", ""),
            "tactic":      tactics,
            "description": obj.get("description", "")[:500],
            "detection":   detection[:300] if detection else "",
            "platforms":   platforms,
            "kill_chain":  [kp["phase_name"] for kp in kill_chain],
            "url":         mitre_ref.get("url", f"https://attack.mitre.org/techniques/{tech_id}/"),
        }
        techniques[tech_id] = entry

        # Build keyword index from name + description words
        text = (entry["name"] + " " + entry["description"]).lower()
        words = set(re.findall(r"\b[a-z]{4,}\b", text))
        for w in words:
            keyword_index[w].append(tech_id)

    # Clean up keyword index (remove very common words that match everything)
    stop_words = {"this", "that", "with", "from", "have", "used", "when",
                  "which", "also", "such", "more", "into", "they", "uses",
                  "using", "often", "these", "other", "been", "their"}
    keyword_index = {
        k: list(set(v))
        for k, v in keyword_index.items()
        if k not in stop_words and len(v) <= 20
    }

    result = {
        "techniques": techniques,
        "keyword_index": keyword_index,
        "count": len(techniques),
    }

    log.info(f"  Parsed {len(techniques)} techniques, {len(keyword_index):,} keywords")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  NVD CVE Parser
# ═══════════════════════════════════════════════════════════════════════════════

def parse_nvd(nvd_path: Path) -> dict:
    """
    Parse NVD CVE JSON 2.0 API feed and build:
      {
        "CVE-2021-44228": {
          "id": "CVE-2021-44228",
          "description": "...",
          "cvss_score": 10.0,
          "cvss_vector": "AV:N/AC:L/...",
          "severity": "CRITICAL",
          "published": "2021-12-10",
          "cwe": ["CWE-502"],
          "references": ["https://..."]
        }, ...
      }
    Also builds a keyword → CVE ID reverse index.
    """
    log.info(f"Parsing NVD CVE feed (2.0 format): {nvd_path}")
    with open(nvd_path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    # NVD 2.0 format: data["vulnerabilities"] is a list of {"cve": {...}}
    items = data.get("vulnerabilities", [])
    log.info(f"  CVE items: {len(items):,}")

    cves = {}
    keyword_index: dict[str, list[str]] = defaultdict(list)

    for item in items:
        cve_obj = item.get("cve", {})
        cve_id  = cve_obj.get("id", "")
        if not cve_id:
            continue

        # Description (English)
        descs = cve_obj.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        # CVSS — NVD 2.0 nests under metrics
        metrics = cve_obj.get("metrics", {})
        cvss_v31 = (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData", {})
        cvss_v30 = (metrics.get("cvssMetricV30") or [{}])[0].get("cvssData", {})
        cvss_v2  = (metrics.get("cvssMetricV2") or [{}])[0].get("cvssData", {})

        cvss_data = cvss_v31 or cvss_v30 or cvss_v2
        score    = cvss_data.get("baseScore", 0.0)
        vector   = cvss_data.get("vectorString", "")

        # Severity from primary metric
        sev_v31 = (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData", {}).get("baseSeverity", "")
        sev_v30 = (metrics.get("cvssMetricV30") or [{}])[0].get("cvssData", {}).get("baseSeverity", "")
        sev_v2  = (metrics.get("cvssMetricV2") or [{}])[0].get("baseSeverity", "")
        severity = (sev_v31 or sev_v30 or sev_v2 or "UNKNOWN").upper()

        # CWE
        weaknesses = cve_obj.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    cwes.append(val)

        # References
        refs = [r.get("url", "") for r in cve_obj.get("references", [])[:3]]

        published = cve_obj.get("published", "")[:10]

        entry = {
            "id":          cve_id,
            "description": desc[:400],
            "cvss_score":  float(score),
            "cvss_vector": vector,
            "severity":    severity,
            "published":   published,
            "cwe":         cwes,
            "references":  refs,
        }
        cves[cve_id] = entry

        # Keyword index from description
        words = set(re.findall(r"\b[a-z]{5,}\b", desc.lower()))
        for w in words:
            keyword_index[w].append(cve_id)

    # Trim large keyword buckets
    keyword_index = {
        k: v[:50]
        for k, v in keyword_index.items()
        if 1 < len(v) <= 100
    }

    result = {
        "cves": cves,
        "keyword_index": keyword_index,
        "count": len(cves),
    }
    log.info(f"  Parsed {len(cves):,} CVEs, {len(keyword_index):,} keywords")
    return result





# ═══════════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    log.info("═" * 60)
    log.info("CyberTwin – Knowledge Base Builder")
    log.info("═" * 60)

    # MITRE ATT&CK
    mitre_data = parse_mitre(STIX)
    with open(MITRE_OUT, "w", encoding="utf-8") as f:
        json.dump(mitre_data, f, indent=2, ensure_ascii=False)
    log.info(f"✅ MITRE index saved → {MITRE_OUT}")

    # NVD CVE
    cve_data = parse_nvd(NVD)
    with open(CVE_OUT, "w", encoding="utf-8") as f:
        json.dump(cve_data, f, indent=2, ensure_ascii=False)
    log.info(f"✅ CVE index saved   → {CVE_OUT}")

    log.info("Knowledge base build complete.")
    log.info(f"  Techniques : {mitre_data['count']}")
    log.info(f"  CVEs       : {cve_data['count']:,}")


if __name__ == "__main__":
    main()
