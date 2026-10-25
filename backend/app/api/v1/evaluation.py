import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.database import get_db

router = APIRouter(prefix="/evaluation", tags=["Evaluation Metrics"])


class ClassMetric(BaseModel):
    model_config = ConfigDict(extra="ignore")
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    support: int = 0


class CalibrationMetrics(BaseModel):
    model_config = ConfigDict(extra="ignore")
    brier_score: float = 0.0
    expected_calibration_error: float = 0.0
    max_calibration_error: float = 0.0
    auc_roc: float = 0.0
    reliability_bins: Optional[List[Dict[str, Any]]] = None


class EvaluationSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    model_version: str
    overall_precision: float
    overall_recall: float
    overall_f1: float
    per_class_metrics: Dict[str, Any] = Field(default_factory=dict)
    calibration: CalibrationMetrics
    evaluation_timestamp: datetime
    schema_version: Optional[str] = None
    corpus_seed: Optional[int] = None
    per_detector_metrics: Optional[Dict[str, Any]] = None
    abstention_rate: Optional[float] = None
    alerts_per_analyst_day: Optional[Dict[str, float]] = None
    incident_consolidation_ratio: Optional[float] = None
    attribution: Optional[Dict[str, float]] = None
    detection_latency_seconds: Optional[Dict[str, float]] = None


def find_evaluation_results_path() -> Optional[Path]:
    repo_root = Path(__file__).resolve().parents[4]
    candidates = [
        repo_root / "data" / "evaluation" / "evaluation_results.json",
        Path.cwd() / "data" / "evaluation" / "evaluation_results.json",
        Path.cwd() / "backend" / "data" / "evaluation" / "evaluation_results.json",
        Path.cwd().parent / "data" / "evaluation" / "evaluation_results.json",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None


import logging
from fastapi import APIRouter, Depends, HTTPException, Query, status

logger = logging.getLogger(__name__)

@router.get("/summary", response_model=EvaluationSummaryResponse)
def get_evaluation_summary(
    tenant_id: Optional[str] = Query(None, description="Optional tenant ID"),
    db: Session = Depends(get_db),
):
    # Dynamic evaluation metrics from Developer A evaluation artifact (CR-03 / CR-08)
    eval_file = find_evaluation_results_path()
    if not eval_file:
        logger.error("Evaluation results file evaluation_results.json not found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evaluation results file evaluation_results.json not found. Run evaluation script first.",
        )

    try:
        with open(eval_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return EvaluationSummaryResponse.model_validate(data)
    except Exception as exc:
        logger.error("Failed to load or validate evaluation_results.json: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evaluation results validation failed: {str(exc)}",
        )

