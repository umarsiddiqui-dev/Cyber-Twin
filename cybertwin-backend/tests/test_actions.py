"""
Phase 4 Tests – Action Generation & Approval Workflow
Tests the action_generator, execution_engine (simulation mode),
and the /api/actions endpoints via the FastAPI test client.
"""

import json
import pytest
from unittest.mock import patch, AsyncMock

from app.services.action_generator import generate_actions, ProposedAction
from app.services.execution_engine import execute_action, _is_allowed


# ── action_generator tests ────────────────────────────────────────────────────

class TestActionGenerator:

    def test_block_ip_generated_for_credential_access(self):
        """Brute-force tactic should propose block_ip action."""
        actions = generate_actions(
            src_ip="45.33.32.156",
            severity="HIGH",
            mitre_tactic="Credential Access",
            mitre_id="T1110",
            mitre_technique="Brute Force",
        )
        assert len(actions) >= 1
        types = [a.action_type for a in actions]
        assert "block_ip" in types

    def test_isolate_host_prepended_for_critical_severity(self):
        """CRITICAL severity should always have isolate_host first."""
        actions = generate_actions(
            src_ip="45.33.32.156",
            severity="CRITICAL",
            mitre_tactic="Credential Access",
            mitre_id="T1110",
            mitre_technique="Brute Force",
        )
        assert actions[0].action_type == "isolate_host"

    def test_no_actions_for_info_no_mitre(self):
        """INFO severity with no tactic should produce no actions (skip low-value events)."""
        actions = generate_actions(
            src_ip="10.0.0.1",
            severity="INFO",
            mitre_tactic=None,
            mitre_id=None,
            mitre_technique=None,
        )
        assert actions == []

    def test_block_ip_command_contains_src_ip(self):
        """Verify the generated block_ip command references the source IP."""
        actions = generate_actions(
            src_ip="192.168.1.99",
            severity="HIGH",
            mitre_tactic="Reconnaissance",
            mitre_id="T1595",
            mitre_technique="Active Scanning",
        )
        block = next((a for a in actions if a.action_type == "block_ip"), None)
        assert block is not None
        assert "192.168.1.99" in block.command

    def test_invalid_ip_produces_no_actions(self):
        """Localhost/zero IP should be skipped gracefully."""
        actions = generate_actions(
            src_ip="0.0.0.0",
            severity="HIGH",
            mitre_tactic="Impact",
            mitre_id="T1498",
            mitre_technique="Network Denial of Service",
        )
        assert actions == []

    def test_proposed_action_has_risk_level(self):
        """Every generated action must have a risk_level attribute."""
        actions = generate_actions(
            src_ip="45.33.32.156",
            severity="HIGH",
            mitre_tactic="Command and Control",
            mitre_id="T1071",
            mitre_technique="Application Layer Protocol",
        )
        for action in actions:
            assert action.risk_level in ("LOW", "MEDIUM", "HIGH")


# ── execution_engine tests ────────────────────────────────────────────────────

class TestExecutionEngine:

    @pytest.mark.asyncio
    async def test_simulation_mode_returns_simulated_true(self):
        """In simulation mode, no OS command runs and simulated=True is returned."""
        result = await execute_action(
            command="netsh advfirewall firewall add rule name=\"Test\" dir=in action=block remoteip=1.2.3.4",
            simulated=True,
        )
        assert result.simulated is True
        assert result.success is True
        assert "SIMULATION" in result.output

    @pytest.mark.asyncio
    async def test_blocked_command_returns_failure(self):
        """A command not in the allowlist must be blocked even in real mode."""
        result = await execute_action(
            command="rm -rf /etc/passwd",
            simulated=False,
        )
        assert result.success is False
        assert "BLOCKED" in result.output

    def test_allowlist_check_permits_netsh(self):
        """netsh advfirewall commands should pass the allowlist."""
        assert _is_allowed("netsh advfirewall firewall add rule name=Test dir=in action=block remoteip=1.2.3.4")

    def test_allowlist_check_blocks_rm(self):
        """rm -rf and other destructive commands must be blocked."""
        assert not _is_allowed("rm -rf /")
        assert not _is_allowed("del /f /q C:\\Windows\\System32")
        assert not _is_allowed("format c: /q")
