"""Phase 8 Agentic SOC evaluation engine."""

from .contracts import (
    AgenticCaseEvaluation,
    AgenticEvaluationReport,
    AgenticEvaluationRun,
    EvaluationDataset,
    GroundTruth,
    SocResultSnapshot,
)
from .dataset import load_dataset
from .gates import evaluate_gates
from .pipeline_verify import verify_pipeline
from .readiness import compute_readiness
from .regression import check_regression
from .service import AgenticEvaluationService

__all__ = [
    "AgenticCaseEvaluation",
    "AgenticEvaluationReport",
    "AgenticEvaluationRun",
    "AgenticEvaluationService",
    "EvaluationDataset",
    "GroundTruth",
    "SocResultSnapshot",
    "check_regression",
    "evaluate_gates",
    "load_dataset",
    "compute_readiness",
    "verify_pipeline",
]
