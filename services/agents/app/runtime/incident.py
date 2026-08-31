"""Incident state machine (spec §28). Case remains the persisted operator object."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class IncidentState(str, Enum):
    NEW = "NEW"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    CORRELATING = "CORRELATING"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    DECISION = "DECISION"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    RESPONDING = "RESPONDING"
    VALIDATING = "VALIDATING"
    REPORTING = "REPORTING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


TRANSITIONS: dict[IncidentState, frozenset[IncidentState]] = {
    IncidentState.NEW: frozenset({IncidentState.TRIAGING}),
    IncidentState.TRIAGING: frozenset({IncidentState.INVESTIGATING, IncidentState.REPORTING}),
    IncidentState.INVESTIGATING: frozenset({IncidentState.CORRELATING, IncidentState.INVESTIGATING}),
    IncidentState.CORRELATING: frozenset({IncidentState.RISK_ASSESSMENT}),
    IncidentState.RISK_ASSESSMENT: frozenset({IncidentState.DECISION}),
    IncidentState.DECISION: frozenset(
        {
            IncidentState.WAITING_APPROVAL,
            IncidentState.RESPONDING,
            IncidentState.REPORTING,
        }
    ),
    IncidentState.WAITING_APPROVAL: frozenset(
        {IncidentState.RESPONDING, IncidentState.REPORTING, IncidentState.DECISION}
    ),
    IncidentState.RESPONDING: frozenset({IncidentState.VALIDATING}),
    IncidentState.VALIDATING: frozenset(
        {IncidentState.REPORTING, IncidentState.INVESTIGATING}
    ),
    IncidentState.REPORTING: frozenset({IncidentState.RESOLVED}),
    IncidentState.RESOLVED: frozenset({IncidentState.CLOSED}),
    IncidentState.CLOSED: frozenset(),
}

# Map existing aisoc_cases statuses onto the spec machine (lossy on purpose).
CASE_STATUS_TO_INCIDENT: dict[str, IncidentState] = {
    "new": IncidentState.NEW,
    "triaged": IncidentState.TRIAGING,
    "investigating": IncidentState.INVESTIGATING,
    "contained": IncidentState.RESPONDING,
    "resolved": IncidentState.RESOLVED,
    "closed": IncidentState.CLOSED,
}

INCIDENT_TO_CASE_STATUS: dict[IncidentState, str] = {
    IncidentState.NEW: "new",
    IncidentState.TRIAGING: "new",
    IncidentState.INVESTIGATING: "investigating",
    IncidentState.CORRELATING: "investigating",
    IncidentState.RISK_ASSESSMENT: "investigating",
    IncidentState.DECISION: "investigating",
    IncidentState.WAITING_APPROVAL: "investigating",
    IncidentState.RESPONDING: "contained",
    IncidentState.VALIDATING: "contained",
    IncidentState.REPORTING: "investigating",
    IncidentState.RESOLVED: "resolved",
    IncidentState.CLOSED: "closed",
}


class IllegalTransitionError(ValueError):
    pass


class TransitionRecord(BaseModel):
    from_state: IncidentState
    to_state: IncidentState
    reason: str = ""
    actor: str = "system"


class IncidentStateMachine:
    def __init__(self, state: IncidentState = IncidentState.NEW) -> None:
        self.state = state
        self.history: list[TransitionRecord] = []

    def can_transition(self, to_state: IncidentState) -> bool:
        return to_state in TRANSITIONS.get(self.state, frozenset())

    def transition(self, to_state: IncidentState, *, reason: str = "", actor: str = "system") -> IncidentState:
        if not self.can_transition(to_state):
            raise IllegalTransitionError(
                f"illegal transition {self.state.value} → {to_state.value}"
            )
        record = TransitionRecord(
            from_state=self.state, to_state=to_state, reason=reason, actor=actor
        )
        self.history.append(record)
        self.state = to_state
        return self.state

    def allowed(self) -> list[str]:
        return sorted(item.value for item in TRANSITIONS.get(self.state, frozenset()))
