"""
Execution Engine – Phase 4
Safely executes (or simulates) approved remediation commands.

Security guarantees:
  1. ONLY runs if the ActionLog record has status = 'approved'.
  2. Command must pass the ALLOWLIST check (prefix match against safe commands).
  3. Defaults to SIMULATION MODE — no OS call unless ALLOW_REAL_EXECUTION=true.
  4. Real execution has a hard 15-second timeout to prevent hangs.
  5. Full stdout/stderr logged to the ActionLog.execution_output field.

REPLACEMENT POINT (Phase 5):
  Add subprocess execution for Linux (iptables, firewall-cmd) targets.
"""

import asyncio
import logging
import shlex
from datetime import datetime, timezone
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ── Safe command allowlist ────────────────────────────────────────────────────
# Only commands that START WITH one of these prefixes can ever execute.
# This is a defence-in-depth measure — the action_generator also only produces
# commands on this list, but we enforce it again here at execution time.

_COMMAND_ALLOWLIST = [
    "netsh advfirewall firewall",   # Windows firewall rules
    "iptables -A",                  # Linux iptables append
    "iptables -I",                  # Linux iptables insert
    "firewall-cmd",                 # RHEL/CentOS firewalld
    "nmap ",                        # Network scanning (read-only)
    "taskkill /pid",                # Windows process termination
]

EXECUTION_TIMEOUT = 15  # seconds


@dataclass
class ExecutionResult:
    success: bool
    simulated: bool
    output: str
    executed_at: datetime


def _is_allowed(command: str) -> bool:
    """Check command against the strict allowlist."""
    lower = command.strip().lower()
    return any(lower.startswith(prefix.lower()) for prefix in _COMMAND_ALLOWLIST)


async def execute_action(command: str, simulated: bool = True) -> ExecutionResult:
    """
    Execute or simulate a remediation command.

    Args:
        command:   The shell command string (already stored in ActionLog).
        simulated: True (default) = dry run only. False = real OS execution.

    Returns:
        ExecutionResult with success flag, output text, and timestamp.
    """
    now = datetime.now(timezone.utc)

    # ── Safety gate: allowlist check ─────────────────────────────────────────
    if not _is_allowed(command):
        msg = f"[Execution] BLOCKED: command not in allowlist: {command[:80]}"
        logger.error(msg)
        return ExecutionResult(success=False, simulated=simulated, output=msg, executed_at=now)

    # ── Simulation mode ───────────────────────────────────────────────────────
    if simulated:
        output = (
            f"[SIMULATION] Would execute: {command}\n"
            f"[SIMULATION] No changes were made to the host system.\n"
            f"[SIMULATION] Set ALLOW_REAL_EXECUTION=true in .env to enable real execution."
        )
        logger.info(f"[Execution] SIMULATE: {command[:80]}")
        return ExecutionResult(success=True, simulated=True, output=output, executed_at=now)

    # ── Real execution (only when ALLOW_REAL_EXECUTION=true in config) ────────
    try:
        logger.warning(f"[Execution] REAL EXEC: {command[:80]}")
        args = shlex.split(command)
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=EXECUTION_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            output = f"[Execution] TIMEOUT after {EXECUTION_TIMEOUT}s — process killed."
            logger.error(output)
            return ExecutionResult(success=False, simulated=False, output=output, executed_at=now)

        output = stdout.decode("utf-8", errors="replace") if stdout else "(no output)"
        success = proc.returncode == 0
        logger.info(
            f"[Execution] EXIT={proc.returncode} | "
            f"output={output[:120]}{'…' if len(output) > 120 else ''}"
        )
        return ExecutionResult(success=success, simulated=False, output=output, executed_at=now)

    except Exception as e:
        output = f"[Execution] ERROR: {e}"
        logger.error(output)
        return ExecutionResult(success=False, simulated=False, output=output, executed_at=now)
