"""
Log Simulator Service – Track A
Generates realistic Snort/OSSEC-style alert log lines asynchronously.

Activated by default when LOG_FILE_PATH is not set in .env.
Emits an alert every LOG_SIMULATE_INTERVAL_MIN – LOG_SIMULATE_INTERVAL_MAX seconds.

The generated log lines follow actual Snort fast-alert and OSSEC formats
so the log_parser.py regex patterns exercise real code paths.
"""

import asyncio
import logging
import random
from datetime import datetime

logger = logging.getLogger(__name__)


# ── Sample Snort fast-alert lines (realistic format) ──────────────────────────
_SNORT_TEMPLATES = [
    '[**] [1:2001219:20] ET SCAN Potential SSH Scan OUTBOUND [**] [Classification: Attempted Information Leak] [Priority: 2] {{TCP}} {src} -> {dst}:{port}',
    '[**] [1:2010937:3] ET POLICY Suspicious inbound to MSSQL port 1433 [**] [Classification: Potentially Bad Traffic] [Priority: 3] {{TCP}} {src} -> {dst}:1433',
    '[**] [1:2001831:17] ET SCAN Nmap Scripting Engine User-Agent Detected [**] [Classification: Web Application Attack] [Priority: 1] {{TCP}} {src} -> {dst}:{port}',
    '[**] [1:2019284:4] ET WEB_SERVER PHP Easter Egg Information Disclosure [**] [Classification: Attempted Information Leak] [Priority: 2] {{TCP}} {src}:{port} -> {dst}:80',
    '[**] [1:2009358:5] ET EXPLOIT Possible CVE-2014-6271 Attempt Bash RCE via CGI [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {{TCP}} {src} -> {dst}:80',
    '[**] [1:2406697:3134] ET DOS Excessive Web Requests - Possible DDoS [**] [Classification: Denial of Service Attack] [Priority: 1] {{TCP}} {src}:{port} -> {dst}:443',
    '[**] [1:2013028:5] ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management [**] [Classification: Potentially Bad Traffic] [Priority: 3] {{TCP}} {src} -> {dst}:80',
    '[**] [1:2260002:1] ET MALWARE Win32.Ransomware.Sodinokibi CnC Beacon [**] [Classification: Malware Command and Control Activity Detected] [Priority: 1] {{TCP}} {src}:{port} -> {dst}:443',
    '[**] [1:2016922:3] ET SCAN Nmap OS Detection Probe [**] [Classification: Attempted Information Leak] [Priority: 3] {{TCP}} {src} -> {dst}:{port}',
    '[**] [1:2012799:2] ET POLICY HTTP Request to a *.onion proxy domain [**] [Classification: Potentially Bad Traffic] [Priority: 2] {{TCP}} {src}:{port} -> {dst}:80',
]

# ── Sample OSSEC alert lines (realistic format) ────────────────────────────────
_OSSEC_TEMPLATES = [
    'Rule: 5716 (level 10) -> \'SSHD brute force trying to get access to the system.\'\nAuthentication failed for user root from Src IP: {src}',
    'Rule: 31101 (level 7) -> \'Web server 500 error code (Internal Error).\'\nSrc IP: {src} - request to {dst}',
    'Rule: 1002 (level 2) -> \'Unknown problem somewhere in the system.\'\nUnknown entry: error from {src}',
    'Rule: 80792 (level 14) -> \'Multiple trojans, rootkits or suspicious files detected. System may be compromised.\'\nFiles changed: /tmp/payload.sh - Src IP: {src}',
    'Rule: 5501 (level 8) -> \'Login session opened.\'\nSession opened for user root by {src}',
    'Rule: 30105 (level 6) -> \'Web server client denied access to restricted resource.\'\nAttempted access to /admin from Src IP: {src}',
    'Rule: 100100 (level 12) -> \'SQL injection attempt detected in web request.\'\nPayload detected via WAF - Src IP: {src} -> Dst: {dst}:80',
    'Rule: 5552 (level 8) -> \'useradd or groupadd used: User added to the system.\'\nNew user created from Src IP: {src}',
]

# ── Attacker / victim IPs ─────────────────────────────────────────────────────
_ATTACKER_IPS = [
    "45.33.32.156", "192.241.173.241", "104.236.246.116",
    "178.62.62.190", "159.65.67.130", "138.197.0.113",
    "206.189.91.155", "167.99.150.222", "68.183.108.112",
    "10.0.0.55",  # internal suspicious host
]
_VICTIM_IPS = [
    "192.168.1.100", "192.168.1.101", "192.168.1.200",
    "10.0.0.1", "10.0.0.10",
]
_PORTS = [22, 80, 443, 3306, 5432, 8080, 8443, 4444, 1433, 6379, 9200]


def _make_snort_log() -> str:
    template = random.choice(_SNORT_TEMPLATES)
    return template.format(
        src=random.choice(_ATTACKER_IPS),
        dst=random.choice(_VICTIM_IPS),
        port=random.choice(_PORTS),
    )


def _make_ossec_log() -> str:
    template = random.choice(_OSSEC_TEMPLATES)
    return template.format(
        src=random.choice(_ATTACKER_IPS),
        dst=random.choice(_VICTIM_IPS),
    )


async def run_simulator(callback, interval_min: float = 4.0, interval_max: float = 10.0):
    """
    Continuously generates log events and passes each raw line to `callback`.
    Args:
        callback: async callable(raw_log: str, source_hint: str)
        interval_min / interval_max: random sleep range in seconds
    """
    logger.info("[Simulator] Log simulator started")
    while True:
        try:
            # 60% Snort, 40% OSSEC
            if random.random() < 0.6:
                raw = _make_snort_log()
                hint = "snort"
            else:
                raw = _make_ossec_log()
                hint = "ossec"

            logger.debug(f"[Simulator] Emitting: {raw[:80]}…")
            await callback(raw, hint)

            delay = random.uniform(interval_min, interval_max)
            await asyncio.sleep(delay)

        except asyncio.CancelledError:
            logger.info("[Simulator] Simulator task cancelled")
            break
        except Exception as e:
            logger.error(f"[Simulator] Unexpected error: {e}")
            await asyncio.sleep(5)
