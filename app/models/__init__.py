from __future__ import annotations

# Re-export every ORM model so importing `app.models` registers them all on
# Base.metadata. Alembic's env.py imports this module to populate the
# autogenerate target_metadata.
from app.models.accounts import (
    EmailChangeRequest,
    Invite,
    MagicLinkPurpose,
    MagicLinkToken,
    PassphraseLockout,
    Session,
    User,
)
from app.models.admin import (
    AdminAlertPref,
    AdminAuditLog,
    AdminThreshold,
    KillSwitch,
    KillSwitchName,
)
from app.models.reports import Report, ReportReasonCategory, ReportResolution
from app.models.snippets import ContentType, ShareMode, Snippet

__all__ = [
    "AdminAlertPref",
    "AdminAuditLog",
    "AdminThreshold",
    "ContentType",
    "EmailChangeRequest",
    "Invite",
    "KillSwitch",
    "KillSwitchName",
    "MagicLinkPurpose",
    "MagicLinkToken",
    "PassphraseLockout",
    "Report",
    "ReportReasonCategory",
    "ReportResolution",
    "Session",
    "ShareMode",
    "Snippet",
    "User",
]
