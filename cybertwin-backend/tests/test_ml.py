"""
Tests for Phase 6 ML Classification router and service.
Mocks the machine learning agent to avoid dependency on fully trained model files in tests.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import MagicMock, patch

from app.main import app


@pytest.fixture
def mock_agent():
    """Mocks the core CyberTwin ML agent across all modules."""
    # We patch the agent inside ml_pipeline and ml_service
    with patch("ml_pipeline.cybertwin_core.agent") as mock_core, \
         patch("app.services.ml_service.agent") as mock_service:
         
        for mock in [mock_core, mock_service]:
            # Default mock state: model is loaded
            mock._models = MagicMock()
            mock._models.is_available.return_value = True
            mock._models._loaded = True
            mock._models.le.classes_ = [
                "Benign", "Botnet", "BruteForce-FTP", "BruteForce-SSH",
                "BruteForce-Web", "BruteForce-XSS", "DDoS-HOIC", "DDoS-LOIC",
                "DDoS-LOIC-UDP", "DoS-GoldenEye", "DoS-Hulk", "DoS-SlowHTTP",
                "DoS-Slowloris", "Infiltration", "SQLInjection"
            ]
            mock._models.features = ["Feature1", "Feature2"]
            mock._kb = MagicMock()
            mock._kb._loaded = True
            
            # Mock analyze/enrich methods
            from ml_pipeline.cybertwin_core import ThreatAnalysis
            mock.analyze.return_value = ThreatAnalysis(
                threat_label="DDoS-HOIC",
                confidence=0.98,
                risk_level="CRITICAL",
                mitre_techniques=[{"id": "T1498", "name": "Network Denial of Service", "tactic": ["Impact"]}],
                related_cves=[{"id": "CVE-2026-9999", "description": "Mock DDoS CVE", "cvss_score": 9.8, "severity": "CRITICAL"}],
                explanation="Mock explanation of DDoS",
                defense_windows="netsh block",
                defense_linux="iptables block",
                defense_desc="Block DDoS traffic",
                src_ip="192.168.1.100"
            )
            mock.enrich.return_value = mock.analyze.return_value
            
        yield mock_service




@pytest.mark.asyncio
async def test_ml_classes_endpoint(mock_agent):
    """GET /api/ml/classes returns the list of all attack classes."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/ml/classes")
    
    assert response.status_code == 200
    data = response.json()
    assert "classes" in data
    assert "Benign" in data["classes"]
    assert "DDoS-HOIC" in data["classes"]
    assert data["model_loaded"] is True


@pytest.mark.asyncio
async def test_ml_status_endpoint(mock_agent):
    """GET /api/ml/status returns correct loaded status of model and knowledge base."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/ml/status")
        
    assert response.status_code == 200
    data = response.json()
    assert data["model_ready"] is True
    assert "classes" in data
    assert data["knowledge_loaded"] is True


@pytest.mark.asyncio
async def test_ml_classify_endpoint(mock_agent):
    """POST /api/ml/classify runs inference and returns enriched threat intelligence."""
    payload = {
        "flow": {
            "Feature1": 12.3,
            "Feature2": 4.56
        },
        "src_ip": "192.168.1.100"
    }
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/ml/classify", json=payload)
        
    assert response.status_code == 200
    data = response.json()
    assert data["label"] == "DDoS-HOIC"
    assert data["confidence"] == 0.98
    assert data["risk_level"] == "CRITICAL"
    assert len(data["mitre_techniques"]) > 0
    assert data["mitre_techniques"][0]["id"] == "T1498"
    assert data["src_ip"] == "192.168.1.100"
    assert data["defense_linux"] == "iptables block"
