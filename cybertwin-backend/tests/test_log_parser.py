"""
Tests for the log parser service.
No database or external services needed – pure unit tests.
"""

import pytest
from app.services.log_parser import parse_log_line, IncidentEvent


class TestSnortParsing:
    def test_parses_snort_fast_alert(self):
        raw = (
            "[**] [1:2001219:20] ET SCAN Potential SSH Scan OUTBOUND [**] "
            "[Classification: Attempted Information Leak] [Priority: 2] "
            "{TCP} 45.33.32.156 -> 192.168.1.100:22"
        )
        event = parse_log_line(raw, "snort")
        assert event.source == "snort"
        assert event.severity == "HIGH"
        assert "SSH Scan" in event.title
        assert event.src_ip == "45.33.32.156"
        assert event.dst_ip == "192.168.1.100"
        assert event.port == 22

    def test_snort_priority_1_is_critical(self):
        raw = (
            "[**] [1:2009358:5] ET EXPLOIT Bash RCE [**] "
            "[Priority: 1] {TCP} 1.2.3.4 -> 192.168.0.1:80"
        )
        event = parse_log_line(raw, "snort")
        assert event.severity == "CRITICAL"

    def test_snort_priority_3_is_medium(self):
        raw = (
            "[**] [1:2016922:3] ET SCAN Nmap OS Detection [**] "
            "[Priority: 3] {TCP} 1.2.3.4 -> 192.168.0.1:1234"
        )
        event = parse_log_line(raw, "snort")
        assert event.severity == "MEDIUM"


class TestOSSECParsing:
    def test_parses_ossec_alert(self):
        raw = (
            "Rule: 5716 (level 10) -> 'SSHD brute force trying to get access to the system.'\n"
            "Authentication failed for user root from Src IP: 45.33.32.156"
        )
        event = parse_log_line(raw, "ossec")
        assert event.source == "ossec"
        assert event.severity == "HIGH"
        assert "brute force" in event.title.lower()

    def test_ossec_level_14_is_critical(self):
        raw = "Rule: 80792 (level 14) -> 'Multiple trojans detected.'"
        event = parse_log_line(raw, "ossec")
        assert event.severity == "CRITICAL"


class TestFallbackParsing:
    def test_keyword_brute_is_high(self):
        raw = "Brute force login attempt from 10.0.0.5 to SSH on port 22"
        event = parse_log_line(raw, "simulator")
        assert event.severity == "HIGH"

    def test_unknown_line_extracts_ip(self):
        raw = "Connection from 192.168.1.55 attempted to reach 10.0.0.1"
        event = parse_log_line(raw, "simulator")
        assert event.src_ip == "192.168.1.55"

    def test_event_has_unique_id(self):
        e1 = parse_log_line("Some log", "simulator")
        e2 = parse_log_line("Some log", "simulator")
        assert e1.id != e2.id

    def test_to_broadcast_dict_structure(self):
        event = parse_log_line("[**] [1:1:1] Test Alert [**] [Priority: 1] {TCP} 1.1.1.1 -> 2.2.2.2:80", "snort")
        d = event.to_broadcast_dict()
        assert d["type"] == "alert"
        assert "id" in d
        assert "severity" in d
        assert "timestamp" in d
