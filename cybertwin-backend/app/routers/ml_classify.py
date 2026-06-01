"""
ml_classify.py – Phase 6
CyberTwin – ML Classification API Router

Endpoints:
  POST /api/ml/classify     — classify a live network flow
  GET  /api/ml/status       — check if model is loaded
  GET  /api/ml/classes      — list all attack classes the model knows
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services import ml_service

log = logging.getLogger(__name__)
router = APIRouter(tags=["ML Classification"])


# ── Request / Response Schemas ─────────────────────────────────────────────────

class FlowClassifyRequest(BaseModel):
    """
    A single CICFlowMeter network flow dict.
    Any subset of the 77 feature columns is accepted;
    missing features default to 0.
    """
    flow:   dict  = Field(..., description="CICFlowMeter feature dict")
    src_ip: str   = Field("0.0.0.0", description="Source IP of the flow")


class MitreTechnique(BaseModel):
    id:          str
    name:        str
    tactic:      list[str]
    description: str
    url:         str


class RelatedCVE(BaseModel):
    id:          str
    description: str
    cvss_score:  float
    severity:    str


class FlowClassifyResponse(BaseModel):
    label:             str
    confidence:        float
    risk_level:        str
    explanation:       str
    mitre_techniques:  list[dict]
    related_cves:      list[dict]
    defense_linux:     str
    defense_windows:   str
    defense_desc:      str
    src_ip:            str
    model_used:        str = "LightGBM+RF Ensemble"


class MLStatusResponse(BaseModel):
    model_ready:   bool
    model_name:    str
    classes:       list[str]
    knowledge_loaded: bool


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post(
    "/ml/classify",
    response_model=FlowClassifyResponse,
    summary="Classify a live network flow",
    description=(
        "Accepts a dict of CICFlowMeter network features and returns:\n"
        "- Threat label (Benign, BruteForce-SSH, DDoS-HOIC, etc.)\n"
        "- Confidence score\n"
        "- MITRE ATT&CK techniques\n"
        "- Related CVEs\n"
        "- Proposed defense command (awaiting SOC approval)\n\n"
        "**The defense command is NOT executed by this endpoint.** "
        "It must be approved via `POST /api/actions/{id}/approve`."
    ),
)
async def classify_flow(body: FlowClassifyRequest):
    """Classify a CICFlowMeter feature dict and return enriched threat intelligence."""
    result = ml_service.classify_flow(body.flow, body.src_ip)
    return FlowClassifyResponse(**result, model_used="LightGBM+RF Ensemble")


@router.get(
    "/ml/status",
    response_model=MLStatusResponse,
    summary="Get ML model status",
)
async def ml_status():
    """Check whether the trained model is loaded and ready for inference."""
    from ml_pipeline.cybertwin_core import agent
    model_store = agent._models
    kb_store    = agent._kb

    classes = []
    if model_store._loaded:
        classes = list(model_store.le.classes_)

    return MLStatusResponse(
        model_ready=ml_service.is_model_ready(),
        model_name="LightGBM + Random Forest Voting Ensemble (CSE-CIC-IDS2018)",
        classes=classes,
        knowledge_loaded=kb_store._loaded,
    )


@router.get(
    "/ml/classes",
    summary="List known attack classes",
)
async def ml_classes():
    """Return the list of all attack categories the model can classify."""
    from ml_pipeline.cybertwin_core import agent
    if not agent._models._loaded:
        return {
            "classes": [
                "Benign", "Botnet", "BruteForce-FTP", "BruteForce-SSH",
                "BruteForce-Web", "BruteForce-XSS", "DDoS-HOIC", "DDoS-LOIC",
                "DDoS-LOIC-UDP", "DoS-GoldenEye", "DoS-Hulk", "DoS-SlowHTTP",
                "DoS-Slowloris", "Infiltration", "SQLInjection",
            ],
            "model_loaded": False,
        }
    return {
        "classes": list(agent._models.le.classes_),
        "model_loaded": True,
    }
