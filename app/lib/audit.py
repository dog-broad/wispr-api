from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.admin import AdminAuditLog

# Canonical action verbs. Kept as constants so call sites and any future
# filtering agree on the exact strings.
ACTION_INVITE_ISSUED = "invite.issued"
ACTION_SNIPPET_TAKEN_DOWN = "snippet.taken_down"
ACTION_REPORT_DISMISSED = "report.dismissed"
ACTION_THRESHOLD_UPDATED = "threshold.updated"
ACTION_PURGE_RUN = "purge.run"
ACTION_BACKUP_RUN = "backup.run"
ACTION_BROADCAST_SENT = "broadcast.sent"
ACTION_MASTER_KEY_ROTATED = "master_key.rotated"


async def record_action(
    session: AsyncSession,
    *,
    actor_id: uuid.UUID | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Append an admin action to the audit log within the caller's transaction.

    Adds the row to ``session`` but does not commit, so the audit entry lands
    atomically with the action it records (a rolled-back action leaves no
    phantom entry; a committed one is never missing its log). The caller commits.
    """
    session.add(
        AdminAuditLog(
            actor_user_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            payload=metadata or {},
        )
    )
