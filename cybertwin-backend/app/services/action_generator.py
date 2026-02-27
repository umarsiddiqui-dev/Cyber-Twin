"""
Action Generator Service – Phase 4
Maps MITRE ATT&CK tactics + incident severity to structured remediation
action templates. Completely deterministic — no LLM calls, no free-form
command generation. This prevents prompt injection and ensures every
generated command can be reviewed against a strict allowlist.

REPLACEMENT POINT (Phase 5+):
  Extend _ACTION_TEMPLATES to cover more ATT&CK techniques.
  The function signatures must remain identical.
"""

import json
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ── Proposed action dataclass ─────────────────────────────────────────────────

@dataclass
class ProposedAction:
    action_type: str       # block_ip | kill_process | isolate_host | run_scan | add_firewall_rule
    command: str           # exact shell command (Windows-friendly by default)
    parameters: dict       # structured key/value params (ip, pid, etc.)
    reason: str            # human-readable justification for the analyst
    risk_level: str        # LOW | MEDIUM | HIGH (to colour-code in the UI)
    mitre_context: str     # e.g. "[T1110] Credential Access"


# ── Action templates (tactic → action list) ───────────────────────────────────
# Each template is a dict with callables/format strings that receive context.

def _block_ip(ip: str, reason: str, mitre: str) -> ProposedAction:
    return ProposedAction(
        action_type="block_ip",
        command=f'netsh advfirewall firewall add rule name="CyberTwin-Block-{ip}" dir=in action=block remoteip={ip}',
        parameters={"ip": ip, "direction": "inbound"},
        reason=f"Block inbound traffic from attacker IP {ip}. {reason}",
        risk_level="MEDIUM",
        mitre_context=mitre,
    )


def _add_firewall_rule(ip: str, port: int, reason: str, mitre: str) -> ProposedAction:
    return ProposedAction(
        action_type="add_firewall_rule",
        command=f'netsh advfirewall firewall add rule name="CyberTwin-Port-{port}" dir=in action=block remoteip={ip} localport={port} protocol=TCP',
        parameters={"ip": ip, "port": port, "protocol": "TCP"},
        reason=f"Block TCP port {port} from {ip}. {reason}",
        risk_level="MEDIUM",
        mitre_context=mitre,
    )


def _isolate_host(host_ip: str, reason: str, mitre: str) -> ProposedAction:
    return ProposedAction(
        action_type="isolate_host",
        command=f'netsh advfirewall firewall add rule name="CyberTwin-Isolate-{host_ip}" dir=in action=block remoteip=any localip={host_ip}',
        parameters={"host_ip": host_ip, "scope": "all_traffic"},
        reason=f"Network-isolate host {host_ip} pending investigation. {reason}",
        risk_level="HIGH",
        mitre_context=mitre,
    )


def _run_scan(target_ip: str, reason: str, mitre: str) -> ProposedAction:
    return ProposedAction(
        action_type="run_scan",
        command=f"nmap -sV -O --top-ports 1000 {target_ip}",
        parameters={"target": target_ip, "type": "service_os_scan"},
        reason=f"Run reconnaissance scan on {target_ip} to identify open services. {reason}",
        risk_level="LOW",
        mitre_context=mitre,
    )


# ── Tactic → action mapping ───────────────────────────────────────────────────
# Maps MITRE tactic names to a function that builds one or more ProposedActions.

_TACTIC_ACTIONS = {
    "Reconnaissance": lambda ctx: [
        _block_ip(ctx["src_ip"], "Attacker is actively scanning your network.", ctx["mitre"]),
        _run_scan(ctx["src_ip"], "Enumerate attacker's exposed services.", ctx["mitre"]),
    ],
    "Credential Access": lambda ctx: [
        _block_ip(ctx["src_ip"], "Stop ongoing brute-force credential attacks.", ctx["mitre"]),
        _add_firewall_rule(ctx["src_ip"], 22, "Block SSH access from attacker.", ctx["mitre"]),
    ],
    "Lateral Movement": lambda ctx: [
        _isolate_host(ctx["src_ip"], "Prevent lateral spread across network.", ctx["mitre"]),
        _block_ip(ctx["src_ip"], "Cut off command & control channel.", ctx["mitre"]),
    ],
    "Command and Control": lambda ctx: [
        _block_ip(ctx["src_ip"], "Sever the C2 communication channel.", ctx["mitre"]),
        _add_firewall_rule(ctx["src_ip"], 443, "Block HTTPS C2 beaconing.", ctx["mitre"]),
    ],
    "Exfiltration": lambda ctx: [
        _isolate_host(ctx["src_ip"], "Prevent further data exfiltration.", ctx["mitre"]),
        _block_ip(ctx["src_ip"], "Block attacker contact with exfiltration endpoint.", ctx["mitre"]),
    ],
    "Impact": lambda ctx: [
        _isolate_host(ctx["src_ip"], "Contain ransomware/DoS impact radius.", ctx["mitre"]),
        _block_ip(ctx["src_ip"], "Block attacker's DoS/ransomware traffic.", ctx["mitre"]),
    ],
    "Execution": lambda ctx: [
        _block_ip(ctx["src_ip"], "Block host executing malicious payloads.", ctx["mitre"]),
        _run_scan(ctx["src_ip"], "Enumerate attacker services and payload delivery infra.", ctx["mitre"]),
    ],
    "Defense Evasion": lambda ctx: [
        _run_scan(ctx["src_ip"], "Map attacker's evasion infrastructure.", ctx["mitre"]),
        _block_ip(ctx["src_ip"], "Block evasive attacker IP.", ctx["mitre"]),
    ],
}

# Generic fallback for unrecognised tactics
_DEFAULT_ACTIONS = lambda ctx: [
    _block_ip(ctx["src_ip"], "Generic block for unclassified threat.", ctx["mitre"]),
]


# ── Public API ────────────────────────────────────────────────────────────────

def generate_actions(
    src_ip: str,
    severity: str,
    mitre_tactic: str | None,
    mitre_id: str | None,
    mitre_technique: str | None,
) -> list[ProposedAction]:
    """
    Generate a list of structured remediation actions for an incident.

    Args:
        src_ip:           Source IP of the threat actor (used in commands).
        severity:         CRITICAL | HIGH | MEDIUM | LOW | INFO
        mitre_tactic:     ATT&CK tactic name (or None if not classified).
        mitre_id:         ATT&CK technique ID e.g. "T1110" (or None).
        mitre_technique:  ATT&CK technique name (or None).

    Returns:
        List of ProposedAction dataclasses.
    """
    # ── Skip low-value events ─────────────────────────────────────────────
    if severity in ("INFO", "LOW") and not mitre_tactic:
        logger.debug(f"[ActionGen] Skipping low-severity event ({severity}, no MITRE)")
        return []

    if not src_ip or src_ip in ("0.0.0.0", "localhost", "127.0.0.1"):
        logger.debug(f"[ActionGen] No usable src_ip ({src_ip!r}), skipping")
        return []

    mitre_ctx = f"[{mitre_id}] {mitre_technique}" if mitre_id else "Unknown technique"

    ctx = {
        "src_ip":   src_ip,
        "severity": severity,
        "mitre":    mitre_ctx,
    }

    factory = _TACTIC_ACTIONS.get(mitre_tactic, _DEFAULT_ACTIONS)
    actions = factory(ctx)

    # For CRITICAL incidents, always prepend an isolate action
    if severity == "CRITICAL" and actions and actions[0].action_type != "isolate_host":
        actions.insert(0, _isolate_host(src_ip, "CRITICAL severity — immediate isolation recommended.", mitre_ctx))

    logger.info(
        f"[ActionGen] Generated {len(actions)} action(s) for {src_ip} "
        f"| severity={severity} tactic={mitre_tactic}"
    )
    return actions
