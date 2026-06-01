"""
cybertwin_core.py – Phase 6
CyberTwin – Main Agent Logic

End-to-end pipeline:
  1. Receive a network flow or log line
  2. Classify using trained ML model
  3. Enrich with MITRE ATT&CK + CVE knowledge
  4. Generate a defense command
  5. ⛔ HUMAN APPROVAL GATE — wait for SOC analyst to approve/reject
  6. Execute (simulation or real) only after approval

Can be used:
  - Standalone (python ml_pipeline/cybertwin_core.py --demo)
  - As a library imported by ml_service.py (FastAPI runtime)
"""

import json, logging, asyncio
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import joblib

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("cybertwin_core")

# ── Paths ──────────────────────────────────────────────────────────────────────
_BASE      = Path(__file__).parent.parent / "app"
_MODEL_DIR = _BASE / "models" / "trained"
_DATA_DIR  = _BASE / "data"


# ═══════════════════════════════════════════════════════════════════════════════
#  Singleton loader — models are loaded once at startup
# ═══════════════════════════════════════════════════════════════════════════════

class _ModelStore:
    _instance = None

    def __init__(self):
        self.model    = None
        self.le       = None
        self.scaler   = None
        self.features = []
        self._loaded  = False

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load(self):
        if self._loaded:
            return
        log.info("Loading ML model artefacts …")
        self.model    = joblib.load(_MODEL_DIR / "threat_model.pkl")
        self.le       = joblib.load(_MODEL_DIR / "label_encoder.pkl")
        self.scaler   = joblib.load(_MODEL_DIR / "feature_scaler.pkl")
        with open(_MODEL_DIR / "feature_names.json") as f:
            self.features = json.load(f)
        self._loaded = True
        log.info(f"  Model loaded. Classes: {list(self.le.classes_)}")

    def is_available(self) -> bool:
        return (_MODEL_DIR / "threat_model.pkl").exists()


class _KnowledgeStore:
    _instance = None

    def __init__(self):
        self.mitre = {}
        self.mitre_keywords = {}
        self.cves  = {}
        self.cve_keywords = {}
        self._loaded = False

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load(self):
        if self._loaded:
            return
        mitre_path = _DATA_DIR / "mitre_index.json"
        cve_path   = _DATA_DIR / "cve_index.json"

        if mitre_path.exists():
            with open(mitre_path, encoding="utf-8") as f:
                data = json.load(f)
            self.mitre          = data.get("techniques", {})
            self.mitre_keywords = data.get("keyword_index", {})
            log.info(f"  MITRE index: {len(self.mitre)} techniques")

        if cve_path.exists():
            with open(cve_path, encoding="utf-8") as f:
                data = json.load(f)
            self.cves         = data.get("cves", {})
            self.cve_keywords = data.get("keyword_index", {})
            log.info(f"  CVE index: {len(self.cves):,} CVEs")

        self._loaded = True


# ═══════════════════════════════════════════════════════════════════════════════
#  Defense command templates (User Approval required before execution)
# ═══════════════════════════════════════════════════════════════════════════════

# Maps ML label → (windows_cmd, linux_cmd, description)
DEFENSE_TEMPLATES: dict[str, dict] = {
    "Botnet": {
        "windows": 'netsh advfirewall firewall add rule name="CyberTwin-Botnet-Block" dir=out action=block remoteip={src_ip}',
        "linux":   "iptables -A OUTPUT -d {src_ip} -j DROP",
        "desc":    "Block outbound C2 communication to botnet controller",
        "risk":    "HIGH",
    },
    "BruteForce-SSH": {
        "windows": 'netsh advfirewall firewall add rule name="CyberTwin-SSH-Block" dir=in action=block remoteip={src_ip} protocol=TCP localport=22',
        "linux":   "iptables -A INPUT -s {src_ip} -p tcp --dport 22 -j DROP",
        "desc":    "Block SSH brute force source IP on port 22",
        "risk":    "MEDIUM",
    },
    "BruteForce-FTP": {
        "windows": 'netsh advfirewall firewall add rule name="CyberTwin-FTP-Block" dir=in action=block remoteip={src_ip} protocol=TCP localport=21',
        "linux":   "iptables -A INPUT -s {src_ip} -p tcp --dport 21 -j DROP",
        "desc":    "Block FTP brute force source IP on port 21",
        "risk":    "MEDIUM",
    },
    "BruteForce-Web": {
        "windows": 'netsh advfirewall firewall add rule name="CyberTwin-WebBrute-Block" dir=in action=block remoteip={src_ip} protocol=TCP localport=80',
        "linux":   "iptables -A INPUT -s {src_ip} -p tcp --dport 80 -j DROP",
        "desc":    "Block web brute force attacker",
        "risk":    "MEDIUM",
    },
    "BruteForce-XSS": {
        "windows": 'netsh advfirewall firewall add rule name="CyberTwin-XSS-Block" dir=in action=block remoteip={src_ip}',
        "linux":   "iptables -A INPUT -s {src_ip} -j DROP",
        "desc":    "Block XSS attack source — consider WAF rule update",
        "risk":    "MEDIUM",
    },
    "SQLInjection": {
        "windows": 'netsh advfirewall firewall add rule name="CyberTwin-SQLi-Block" dir=in action=block remoteip={src_ip}',
        "linux":   "iptables -A INPUT -s {src_ip} -j DROP && fail2ban-client set apache-badbots banip {src_ip}",
        "desc":    "Block SQL injection source IP and alert WAF",
        "risk":    "HIGH",
    },
    "DoS-GoldenEye": {
        "windows": 'netsh advfirewall firewall add rule name="CyberTwin-DoS-Block" dir=in action=block remoteip={src_ip} protocol=TCP',
        "linux":   "iptables -A INPUT -s {src_ip} -p tcp -m connlimit --connlimit-above 20 -j REJECT",
        "desc":    "Rate-limit / block DoS source IP",
        "risk":    "HIGH",
    },
    "DoS-Hulk":       {"windows": 'netsh advfirewall firewall add rule name="CyberTwin-DoS-Hulk" dir=in action=block remoteip={src_ip}', "linux": "iptables -A INPUT -s {src_ip} -j DROP", "desc": "Block DoS-Hulk source", "risk": "HIGH"},
    "DoS-SlowHTTP":   {"windows": 'netsh advfirewall firewall add rule name="CyberTwin-SlowHTTP" dir=in action=block remoteip={src_ip} protocol=TCP localport=80', "linux": "iptables -A INPUT -s {src_ip} -p tcp --dport 80 -j DROP", "desc": "Block SlowHTTP DoS source", "risk": "HIGH"},
    "DoS-Slowloris":  {"windows": 'netsh advfirewall firewall add rule name="CyberTwin-Slowloris" dir=in action=block remoteip={src_ip} protocol=TCP localport=80', "linux": "iptables -A INPUT -s {src_ip} -p tcp --dport 80 -j DROP", "desc": "Block Slowloris DoS source", "risk": "HIGH"},
    "DDoS-HOIC":      {"windows": 'netsh advfirewall firewall add rule name="CyberTwin-DDoS-HOIC" dir=in action=block remoteip={src_ip}', "linux": "iptables -A INPUT -s {src_ip} -j DROP", "desc": "Block DDoS HOIC source IP", "risk": "CRITICAL"},
    "DDoS-LOIC":      {"windows": 'netsh advfirewall firewall add rule name="CyberTwin-DDoS-LOIC" dir=in action=block remoteip={src_ip}', "linux": "iptables -A INPUT -s {src_ip} -j DROP", "desc": "Block DDoS LOIC source IP", "risk": "CRITICAL"},
    "DDoS-LOIC-UDP":  {"windows": 'netsh advfirewall firewall add rule name="CyberTwin-DDoS-UDP" dir=in action=block remoteip={src_ip} protocol=UDP', "linux": "iptables -A INPUT -s {src_ip} -p udp -j DROP", "desc": "Block DDoS UDP flood source", "risk": "CRITICAL"},
    "Infiltration":   {"windows": 'netsh advfirewall firewall add rule name="CyberTwin-Infiltration" dir=in action=block remoteip={src_ip}', "linux": "iptables -A INPUT -s {src_ip} -j DROP && iptables -A OUTPUT -d {src_ip} -j DROP", "desc": "Bidirectional block for infiltration attempt — CRITICAL: isolate host", "risk": "CRITICAL"},
    "Benign": None,   # No action needed
}


# ═══════════════════════════════════════════════════════════════════════════════
#  Core data types
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ThreatAnalysis:
    threat_label:   str
    confidence:     float
    risk_level:     str            # CRITICAL / HIGH / MEDIUM / LOW / BENIGN
    mitre_techniques: list[dict]   = field(default_factory=list)
    related_cves:     list[dict]   = field(default_factory=list)
    explanation:      str          = ""
    defense_windows:  str          = ""
    defense_linux:    str          = ""
    defense_desc:     str          = ""
    src_ip:           str          = "0.0.0.0"


# ═══════════════════════════════════════════════════════════════════════════════
#  Core Agent
# ═══════════════════════════════════════════════════════════════════════════════

class CyberTwinAgent:
    """
    Main CyberTwin agent.
    Instantiate once at application startup by calling CyberTwinAgent.startup().
    """

    def __init__(self):
        self._models = _ModelStore.get()
        self._kb     = _KnowledgeStore.get()

    def startup(self):
        """Load all artefacts. Call once at FastAPI lifespan start."""
        if self._models.is_available():
            self._models.load()
        else:
            log.warning("threat_model.pkl not found — ML classification disabled. Run model_trainer.py first.")
        self._kb.load()

    # ── 1. Classify a network flow ──────────────────────────────────────────

    def classify_flow(self, flow: dict) -> tuple[str, float]:
        """
        Classify a dict of CICFlowMeter features.
        Returns (label, confidence).
        Falls back to 'Unknown' if model not loaded.
        """
        if not self._models.is_available() or not self._models._loaded:
            return "Unknown", 0.0

        features = self._models.features
        try:
            vec = np.array([[float(flow.get(f, 0.0)) for f in features]], dtype=np.float32)
            vec = self._models.scaler.transform(vec)
            proba = self._models.model.predict_proba(vec)[0]
            idx   = int(np.argmax(proba))
            label = self._models.le.inverse_transform([idx])[0]
            conf  = float(proba[idx])
            return label, round(conf, 4)
        except Exception as e:
            log.error(f"classify_flow error: {e}")
            return "Unknown", 0.0

    # ── 2. Enrich with knowledge ────────────────────────────────────────────

    def _label_to_keywords(self, label: str) -> list[str]:
        """Map ML label to relevant MITRE/CVE search keywords."""
        mapping = {
            "Botnet":          ["botnet", "command", "control", "malware"],
            "BruteForce-SSH":  ["brute", "force", "ssh", "credential"],
            "BruteForce-FTP":  ["brute", "force", "ftp", "credential"],
            "BruteForce-Web":  ["brute", "force", "credential", "password"],
            "BruteForce-XSS":  ["cross", "site", "scripting", "injection"],
            "SQLInjection":    ["injection", "database", "exploit"],
            "DoS-GoldenEye":   ["denial", "service", "flood"],
            "DoS-Hulk":        ["denial", "service", "flood"],
            "DoS-SlowHTTP":    ["denial", "service", "slowloris"],
            "DoS-Slowloris":   ["denial", "service", "slowloris"],
            "DDoS-HOIC":       ["distributed", "denial", "flood"],
            "DDoS-LOIC":       ["distributed", "denial", "flood"],
            "DDoS-LOIC-UDP":   ["distributed", "denial", "flood", "udp"],
            "Infiltration":    ["infiltration", "lateral", "movement"],
        }
        return mapping.get(label, [label.lower()])

    def enrich(self, label: str, src_ip: str = "0.0.0.0") -> ThreatAnalysis:
        """
        Look up MITRE techniques and CVEs for the detected label.
        Generate defense commands and a human-readable explanation.
        """
        keywords = self._label_to_keywords(label)

        # ── MITRE lookup ──
        mitre_hits = {}
        for kw in keywords:
            for tech_id in self._kb.mitre_keywords.get(kw, [])[:5]:
                if tech_id not in mitre_hits:
                    mitre_hits[tech_id] = self._kb.mitre.get(tech_id, {})
        mitre_list = list(mitre_hits.values())[:5]

        # ── CVE lookup ──
        cve_hits = {}
        for kw in keywords:
            for cve_id in self._kb.cve_keywords.get(kw, [])[:3]:
                if cve_id not in cve_hits:
                    cve_hits[cve_id] = self._kb.cves.get(cve_id, {})
        # Sort by CVSS score
        cve_list = sorted(cve_hits.values(), key=lambda x: x.get("cvss_score", 0), reverse=True)[:3]

        # ── Defense commands ──
        template = DEFENSE_TEMPLATES.get(label)
        def_win = def_lin = def_desc = ""
        risk_level = "LOW"
        if template:
            def_win  = template["windows"].format(src_ip=src_ip)
            def_lin  = template["linux"].format(src_ip=src_ip)
            def_desc = template["desc"]
            risk_level = template["risk"]

        # ── Explanation ──
        tactic_names = []
        for t in mitre_list[:2]:
            tactic_names.extend(t.get("tactic", []))
        tactic_str = " / ".join(set(tactic_names)) if tactic_names else "Unknown"

        explanation = (
            f"🔴 Detected **{label}** attack (Risk: {risk_level}). "
            f"Matches MITRE ATT&CK tactics: {tactic_str}. "
            f"{def_desc}. "
            f"Top CVEs with CVSS ≥ {cve_list[0]['cvss_score'] if cve_list else 'N/A'}. "
            f"Recommend immediate isolation of {src_ip}."
        ) if label != "Benign" else "✅ Traffic classified as Benign — no action required."

        return ThreatAnalysis(
            threat_label=label,
            confidence=0.0,     # filled in by caller
            risk_level=risk_level if label != "Benign" else "BENIGN",
            mitre_techniques=mitre_list,
            related_cves=cve_list,
            explanation=explanation,
            defense_windows=def_win,
            defense_linux=def_lin,
            defense_desc=def_desc,
            src_ip=src_ip,
        )

    # ── 3. Full pipeline: classify + enrich ──────────────────────────────────

    def analyze(self, flow: dict, src_ip: str = "0.0.0.0") -> ThreatAnalysis:
        """
        Main entry point for live traffic analysis.
        Returns a fully enriched ThreatAnalysis ready for the dashboard.
        """
        label, confidence = self.classify_flow(flow)
        analysis = self.enrich(label, src_ip)
        analysis.confidence = confidence
        return analysis

    # ── 4. User Approval Gate ────────────────────────────────────────────────

    def propose_command(self, analysis: ThreatAnalysis, platform: str = "linux") -> dict:
        """
        Return a proposed defense command dict.
        The command is NOT executed here — it must go through
        the /api/actions/propose → approve workflow.
        """
        cmd = analysis.defense_linux if platform == "linux" else analysis.defense_windows
        return {
            "label":      analysis.threat_label,
            "risk":       analysis.risk_level,
            "src_ip":     analysis.src_ip,
            "command":    cmd,
            "desc":       analysis.defense_desc,
            "status":     "pending",     # ← awaiting SOC analyst approval
            "approved":   False,         # ← must be set to True via /api/actions/{id}/approve
            "simulated":  True,          # ← real execution disabled by default
        }


# ── Singleton instance for import ─────────────────────────────────────────────
agent = CyberTwinAgent()


# ═══════════════════════════════════════════════════════════════════════════════
#  Interactive demo (standalone usage)
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse, sys

    parser = argparse.ArgumentParser(description="CyberTwin CLI Demo")
    parser.add_argument("--demo", action="store_true", help="Run interactive demo")
    args = parser.parse_args()

    agent.startup()

    # Synthetic demo flow (would come from live capture in production)
    DEMO_FLOW = {
        "Destination Port": 22,
        "Flow Duration": 500000,
        "Total Fwd Packets": 100,
        "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 8000,
        "Fwd Packet Length Max": 100,
        "Fwd Packet Length Min": 20,
        "Fwd Packet Length Mean": 80.0,
        "Flow Bytes/s": 16000.0,
        "Flow Packets/s": 200.0,
    }
    SRC_IP = "45.33.32.156"

    print("\n" + "═" * 60)
    print("  CyberTwin – Threat Analysis Demo")
    print("═" * 60)
    print(f"\n  Analysing flow from {SRC_IP} …\n")

    if not agent._models.is_available():
        print("  ⚠️  Model not trained yet. Using demo label: BruteForce-SSH")
        analysis = agent.enrich("BruteForce-SSH", SRC_IP)
        analysis.confidence = 0.93
    else:
        analysis = agent.analyze(DEMO_FLOW, SRC_IP)

    print(f"  Threat Detected : {analysis.threat_label}")
    print(f"  Confidence      : {analysis.confidence:.1%}")
    print(f"  Risk Level      : {analysis.risk_level}")
    print(f"\n  Explanation:\n  {analysis.explanation}\n")

    if analysis.mitre_techniques:
        t = analysis.mitre_techniques[0]
        print(f"  MITRE           : [{t['id']}] {t['name']}")
        print(f"  Tactic          : {', '.join(t['tactic'])}")

    if analysis.related_cves:
        c = analysis.related_cves[0]
        print(f"  Top CVE         : {c['id']} (CVSS {c['cvss_score']} {c['severity']})")

    if analysis.risk_level not in ("BENIGN", "LOW"):
        proposal = agent.propose_command(analysis)
        print(f"\n  ⛔  PROPOSED DEFENSE COMMAND (awaiting SOC approval):")
        print(f"  {proposal['command']}")
        print(f"\n  ─── HUMAN APPROVAL GATE ─────────────────────────────────")
        user_input = input("  SOC Analyst: Approve this command? [yes/no]: ").strip().lower()
        if user_input == "yes":
            print("  ✅ Command APPROVED. Submitting to execution engine (simulation mode).")
            print("  → In production, this routes to POST /api/actions/{id}/approve")
        else:
            print("  ❌ Command REJECTED. Logging rejection reason for audit.")
    else:
        print("  ✅ Traffic is Benign. No action required.")

    print("\n" + "═" * 60 + "\n")
