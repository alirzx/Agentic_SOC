"""Remove an alert↔incident correlation without deleting either row."""

from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def unlink_alert_from_incident(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    alert_id: uuid.UUID,
) -> dict[str, Any]:
    """Clear fusion_incident_id on the alert and drop it from incident.alert_ids."""
    await db.execute(
        text(
            """
            UPDATE alerts
               SET fusion_incident_id = NULL,
                   updated_at = now()
             WHERE tenant_id = :tid
               AND id = :aid
               AND fusion_incident_id = :iid
            """
        ).bindparams(tid=tenant_id, aid=alert_id, iid=incident_id)
    )
    row = (
        await db.execute(
            text(
                """
                UPDATE fusion_incidents
                   SET alert_ids = ARRAY(
                         SELECT x FROM unnest(alert_ids) AS t(x)
                          WHERE x <> :aid
                       ),
                       alert_count = GREATEST(
                         0,
                         COALESCE(array_length(alert_ids, 1), 1) - 1
                       ),
                       membership_history = COALESCE(membership_history, '[]'::jsonb)
                         || CAST(:hist AS jsonb),
                       updated_at = now()
                 WHERE id = :iid AND tenant_id = :tid
             RETURNING id, alert_count
                """
            ).bindparams(
                tid=tenant_id,
                iid=incident_id,
                aid=alert_id,
                hist=json.dumps(
                    [
                        {
                            "action": "removed",
                            "alert_id": str(alert_id),
                        }
                    ]
                ),
            )
        )
    ).mappings().first()
    return {
        "unlinked": True,
        "incident_id": str(incident_id),
        "alert_id": str(alert_id),
        "incident_alert_count": int(row["alert_count"]) if row else None,
    }
