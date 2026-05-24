from __future__ import annotations

# Re-export every ORM model so importing `app.models` registers them all on
# Base.metadata. Alembic's env.py imports this module to populate the
# autogenerate target_metadata.
from app.models.snippets import ContentType, ShareMode, Snippet

__all__ = ["ContentType", "ShareMode", "Snippet"]
