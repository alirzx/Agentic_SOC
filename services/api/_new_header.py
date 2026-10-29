"""Unit tests for the Runbook automation layer (Phase v2).

Tests the condition evaluator (pure logic, no DB) and the rule executor
(mocked DB). The automation_rules table tests go in test_runbook_events.py
with the rest of the DB-gated integration suite.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.runbook.condition_eval import (
    ConditionError,
    _validate_field,
    evaluate_all,
    evaluate_condition,
    validate_conditions,
)
from app.services.runbook.gate import GateDecision
from app.services.runbook.thresholds import AutonomyDecision, make_thresholds
