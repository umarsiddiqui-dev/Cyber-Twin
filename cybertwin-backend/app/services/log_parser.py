"""
Log Parser Service
Converts raw Snort/OSSEC log text into a structured IncidentEvent dataclass.

Supports:
  - Snort fast-alert format
  - OSSEC alert format
  - Generic syslog / firewall lines
  - Simulator-generated events

REPLACEMENT POINT (Phase 3):
  After parsing, Phase 3 will pass the IncidentEvent through the MITRE ATT&CK
  classifier and risk scorer before it reaches the incident_service.
"""

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ── Structured event dataclass ────────────────────────────────────────────────

@dataclass
class IncidentEvent:
    source: str           # "snort" | "ossec" | "simulator" | "firewall"
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    raw_log: str
    src_ip: str | None = None
    dst_ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_broadcast_dict(self) -> dict:
        """Convert to JSON-serializable dict for WebSocket broadcast."""
        return {
            "type": "alert",
            "id": self.id,
            "source": self.source,
            "severity": self.severity,
            "title": self.title,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "port": self.port,
            "protocol": self.protocol,
            "raw_log": self.raw_log,
            "timestamp": self.timestamp.isoformat(),
        }


# ── Severity keyword maps ─────────────────────────────────────────────────────

_SNORT_PRIORITY_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}

_KEYWORD_SEVERITY = {
    "critical": "CRITICAL", "exploit": "CRITICAL", "shellcode": "CRITICAL",
    "rootkit": "CRITICAL", "ransomware": "CRITICAL",
    "attack": "HIGH", "brute": "HIGH", "scan": "MEDIUM",
    "probe": "MEDIUM", "dos": "HIGH", "ddos": "HIGH",
    "suspicious": "MEDIUM", "injection": "HIGH", "overflow": "HIGH",
    "recon": "LOW", "info": "INFO",
}

# ── Regex patterns ─────────────────────────────────────────────────────────────

_RE_SNORT_FAST = re.compile(
    r"\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(?P<title>.+?)\s+\[\*\*\]"
    r".*?Priority:\s*(?P<priority>\d)"
    r".*?(?P<src>[\d.]+)(?::(?P<sport>\d+))?\s+->\s+(?P<dst>[\d.]+)(?::(?P<dport>\d+))?",
    re.DOTALL,
)

_RE_OSSEC = re.compile(
    r"Rule:\s*\d+\s+\(level\s+(?P<level>\d+)\)\s+->\s+'(?P<title>[^']+)'"
    r"(?:.*?Src IP:\s*(?P<src>[\d.]+))?",
    re.DOTALL,
)

_RE_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
_RE_PORT = re.compile(r":(\d{2,5})")


def _ossec_level_to_severity(level: int) -> str:
    if level >= 12:  return "CRITICAL"
    if level >= 8:   return "HIGH"
    if level >= 5:   return "MEDIUM"
    if level >= 3:   return "LOW"
    return "INFO"


def _keywords_severity(text: str) -> str:
    lower = text.lower()
    for keyword, sev in _KEYWORD_SEVERITY.items():
        if keyword in lower:
            return sev
    return "INFO"


def _extract_ips(text: str):
    ips = _RE_IP.findall(text)
    return ips[0] if len(ips) > 0 else None, ips[1] if len(ips) > 1 else None


def _extract_port(text: str) -> int | None:
    m = _RE_PORT.search(text)
    if m:
        p = int(m.group(1))
        return p if p < 65536 else None
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def parse_log_line(raw: str, source_hint: str = "unknown") -> IncidentEvent:
    """
    Parse a single raw log line and return an IncidentEvent.
    Falls back to keyword-based severity if no pattern matches.
    """
    raw = raw.strip()

    # ── Snort fast alert ──
    m = _RE_SNORT_FAST.search(raw)
    if m:
        priority = int(m.group("priority"))
        src_ip = m.group("src")
        dst_ip = m.group("dst")
        dport = m.group("dport")
        return IncidentEvent(
            source="snort",
            severity=_SNORT_PRIORITY_MAP.get(priority, "INFO"),
            title=m.group("title").strip(),
            raw_log=raw,
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=int(dport) if dport else None,
        )

    # ── OSSEC alert ──
    m = _RE_OSSEC.search(raw)
    if m:
        level = int(m.group("level"))
        src_ip = m.group("src") if m.lastindex is not None and m.lastindex >= 3 and m.group("src") else None
        return IncidentEvent(
            source="ossec",
            severity=_ossec_level_to_severity(level),
            title=m.group("title").strip(),
            raw_log=raw,
            src_ip=src_ip,
        )

    # ── Generic / simulator fallback ──
    src_ip, dst_ip = _extract_ips(raw)
    port = _extract_port(raw)
    # Use first line as title
    title = raw.split("\n")[0][:120]
    severity = _keywords_severity(raw)

    return IncidentEvent(
        source=source_hint,
        severity=severity,
        title=title,
        raw_log=raw,
        src_ip=src_ip,
        dst_ip=dst_ip,
        port=port,
    )
