"""Case correlation graph view state snapshots.

Analysts can save named snapshots of their correlation graph state
(camera position, focused/hidden nodes, collapsed clusters, etc.)
and restore them later for investigation.

Endpoints
---------
* ``GET  /cases/{case_id}/graph-views``           List saved graph views for a case.
* ``POST /cases/{case_id}/graph-views``          Create a new graph view snapshot.
* ``GET  /cases/{case_id}/graph-views/{view_id}`` Retrieve a specific view snapshot.
* ``PATCH /cases/{case_id}/graph-views/{view_id}`` Update a view snapshot.
* ``DELETE /cases/{case_id}/graph-views/{view_id}`` Delete a view snapshot.
"""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession
from app.models.case_graph_view import CaseGraphView

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["case-graph-views"])


class CaseGraphViewCreate(BaseModel):
    """Request to create a new case graph view snapshot."""

    name: str = Field(..., min_length=1, max_length=255, description="Display name for the view")
    view_state: dict = Field(
        default_factory=dict,
        description="Opaque JSON: {camera: {x, y, zoom}, focused_nodes: [], hidden_nodes: [], ...}",
    )


class CaseGraphViewUpdate(BaseModel):
    """Request to update an existing case graph view snapshot."""

    name: str | None = Field(None, min_length=1, max_length=255)
    view_state: dict | None = Field(None, description="Updated view state JSON")


class CaseGraphViewResponse(BaseModel):
    """Response: a case graph view snapshot."""

    id: UUID
    case_id: UUID
    name: str
    view_state: dict
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.get("/{case_id}/graph-views", response_model=list[CaseGraphViewResponse])
async def list_case_graph_views(
    case_id: UUID,
    db: DBSession,
    user: AuthUser,
) -> list[CaseGraphViewResponse]:
    """List all saved graph view snapshots for a case.

    Only snapshots created by the current user are returned.
    """
    stmt = (
        select(CaseGraphView)
        .where(
            CaseGraphView.case_id == case_id,
            CaseGraphView.tenant_id == user.tenant_id,
            CaseGraphView.user_id == user.user_id,
        )
        .order_by(CaseGraphView.updated_at.desc())
    )
    views = (await db.execute(stmt)).scalars().all()
    return [
        CaseGraphViewResponse(
            id=v.id,
            case_id=v.case_id,
            name=v.name,
            view_state=v.view_state,
            created_at=v.created_at.isoformat(),
            updated_at=v.updated_at.isoformat(),
        )
        for v in views
    ]


@router.post("/{case_id}/graph-views", response_model=CaseGraphViewResponse, status_code=status.HTTP_201_CREATED)
async def create_case_graph_view(
    case_id: UUID,
    payload: CaseGraphViewCreate,
    db: DBSession,
    user: AuthUser,
) -> CaseGraphViewResponse:
    """Create a new named snapshot of the case's correlation graph view state.

    The view_state is opaque JSON that typically includes:
    - camera: {x, y, zoom} for pan/zoom position
    - focused_nodes: [observation_id, ...] for highlighted observations
    - hidden_nodes: [observation_id, ...] for nodes excluded from view
    - collapsed_clusters: {cluster_id: true, ...} for collapsed groups

    Saving replaces any existing view with the same name for this user+case.
    """
    # Upsert: if a view with this name exists, update it; otherwise create new
    existing = (await db.execute(
        select(CaseGraphView).where(
            CaseGraphView.case_id == case_id,
            CaseGraphView.tenant_id == user.tenant_id,
            CaseGraphView.user_id == user.user_id,
            CaseGraphView.name == payload.name,
        )
    )).scalar_one_or_none()

    if existing:
        existing.view_state = payload.view_state
        await db.flush()
        view = existing
    else:
        view = CaseGraphView(
            case_id=case_id,
            tenant_id=user.tenant_id,
            user_id=user.user_id,
            name=payload.name,
            view_state=payload.view_state,
        )
        db.add(view)
        await db.flush()

    await db.commit()

    return CaseGraphViewResponse(
        id=view.id,
        case_id=view.case_id,
        name=view.name,
        view_state=view.view_state,
        created_at=view.created_at.isoformat(),
        updated_at=view.updated_at.isoformat(),
    )


@router.get("/{case_id}/graph-views/{view_id}", response_model=CaseGraphViewResponse)
async def get_case_graph_view(
    case_id: UUID,
    view_id: UUID,
    db: DBSession,
    user: AuthUser,
) -> CaseGraphViewResponse:
    """Retrieve a specific graph view snapshot."""
    view = (await db.execute(
        select(CaseGraphView).where(
            CaseGraphView.id == view_id,
            CaseGraphView.case_id == case_id,
            CaseGraphView.tenant_id == user.tenant_id,
            CaseGraphView.user_id == user.user_id,
        )
    )).scalar_one_or_none()

    if not view:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Graph view not found")

    return CaseGraphViewResponse(
        id=view.id,
        case_id=view.case_id,
        name=view.name,
        view_state=view.view_state,
        created_at=view.created_at.isoformat(),
        updated_at=view.updated_at.isoformat(),
    )


@router.patch("/{case_id}/graph-views/{view_id}", response_model=CaseGraphViewResponse)
async def update_case_graph_view(
    case_id: UUID,
    view_id: UUID,
    payload: CaseGraphViewUpdate,
    db: DBSession,
    user: AuthUser,
) -> CaseGraphViewResponse:
    """Update a graph view snapshot."""
    view = (await db.execute(
        select(CaseGraphView).where(
            CaseGraphView.id == view_id,
            CaseGraphView.case_id == case_id,
            CaseGraphView.tenant_id == user.tenant_id,
            CaseGraphView.user_id == user.user_id,
        )
    )).scalar_one_or_none()

    if not view:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Graph view not found")

    if payload.name is not None:
        view.name = payload.name
    if payload.view_state is not None:
        view.view_state = payload.view_state

    await db.commit()

    return CaseGraphViewResponse(
        id=view.id,
        case_id=view.case_id,
        name=view.name,
        view_state=view.view_state,
        created_at=view.created_at.isoformat(),
        updated_at=view.updated_at.isoformat(),
    )


@router.delete("/{case_id}/graph-views/{view_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case_graph_view(
    case_id: UUID,
    view_id: UUID,
    db: DBSession,
    user: AuthUser,
) -> None:
    """Delete a graph view snapshot."""
    view = (await db.execute(
        select(CaseGraphView).where(
            CaseGraphView.id == view_id,
            CaseGraphView.case_id == case_id,
            CaseGraphView.tenant_id == user.tenant_id,
            CaseGraphView.user_id == user.user_id,
        )
    )).scalar_one_or_none()

    if not view:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Graph view not found")

    await db.delete(view)
    await db.commit()
