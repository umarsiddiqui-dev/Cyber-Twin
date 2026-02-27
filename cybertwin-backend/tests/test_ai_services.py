"""
Tests for Phase 3 AI services.
No real OpenAI key or database needed — all tests use offline / local data only.
"""

import pytest
from app.services.mitre_service import classify, get_technique_by_id, MitreMatch
from app.services import risk_scorer
from app.services import conversation_memory


class TestMitreClassifier:
    def test_ssh_brute_force_matches_brute_force_technique(self):
        result = classify("SSH brute force login attempts from 10.0.0.5")
        assert result is not None
        assert result.technique_id == "T1110"
        assert result.tactic == "Credential Access"

    def test_port_scan_matches_active_scanning(self):
        result = classify("Nmap port scan detected from 1.2.3.4")
        assert result is not None
        assert result.technique_id in ["T1595", "T1046"]

    def test_ransomware_matches_data_encrypted(self):
        result = classify("Ransomware beacon detected C2 activity")
        assert result is not None
        assert result.technique_id in ["T1486", "T1071"]

    def test_ddos_traffic_matches_network_dos(self):
        result = classify("DDoS HTTP flood attack detected excessive web requests")
        assert result is not None
        assert result.technique_id == "T1498"

    def test_unrelated_text_returns_none(self):
        result = classify("the weather is sunny and warm today")
        assert result is None

    def test_confidence_is_between_0_and_1(self):
        result = classify("brute force password spray attack")
        assert result is not None
        assert 0.0 <= result.confidence <= 1.0

    def test_get_technique_by_id(self):
        tech = get_technique_by_id("T1595")
        assert tech is not None
        assert tech["name"] == "Active Scanning"

    def test_get_nonexistent_technique_returns_none(self):
        tech = get_technique_by_id("T9999")
        assert tech is None


class TestRiskScorer:
    def test_critical_snort_with_mitre_is_high_score(self):
        mitre = MitreMatch("T1110", "Brute Force", "Credential Access", "", 0.8)
        score = risk_scorer.score("CRITICAL", "snort", mitre)
        assert score > 7.0

    def test_info_no_mitre_is_low_score(self):
        score = risk_scorer.score("INFO", "simulator", None)
        assert score < 3.0

    def test_score_is_clamped_between_0_and_10(self):
        mitre = MitreMatch("T1595", "Active Scanning", "Recon", "", 1.0)
        score = risk_scorer.score("CRITICAL", "snort", mitre)
        assert 0.0 <= score <= 10.0

    def test_score_label_critical(self):
        assert risk_scorer.score_label(9.0) == "CRITICAL"

    def test_score_label_low(self):
        assert risk_scorer.score_label(2.5) == "LOW"

    def test_unknown_severity_defaults_gracefully(self):
        score = risk_scorer.score("UNKNOWN", "snort", None)
        assert score >= 0.0


class TestConversationMemory:
    def test_add_and_retrieve_history(self):
        sid = "test-session-001"
        conversation_memory.add_turn(sid, "Hello", "Hi there!")
        history = conversation_memory.get_history(sid)
        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "Hello"
        assert history[1]["role"] == "assistant"
        conversation_memory.clear_session(sid)

    def test_history_capped_at_max_turns(self):
        sid = "test-session-cap"
        # Add 15 turns (30 messages) — should cap at 10 turns (20 messages)
        for i in range(15):
            conversation_memory.add_turn(sid, f"msg {i}", f"reply {i}")
        history = conversation_memory.get_history(sid)
        assert len(history) == 20  # 10 turns × 2 messages
        conversation_memory.clear_session(sid)

    def test_clear_session_removes_history(self):
        sid = "test-session-clear"
        conversation_memory.add_turn(sid, "test", "response")
        conversation_memory.clear_session(sid)
        history = conversation_memory.get_history(sid)
        assert len(history) == 0
