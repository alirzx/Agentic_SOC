from uuid import UUID

from sqlalchemy import text

from app.services.tkg.binding import Binding, BindingError
from app.services.tkg_evaluation.client import TkgConfig


async def workspace_config(db, workspace: UUID, settings):
    empty = TkgConfig(base_url="", email="", password="", kb_id="")
    if settings is None:
        from app.core.config import settings
    await db.execute(text("SELECT set_config('app.current_tenant_id', :workspace, true)"), {"workspace": str(workspace)})
    row = (
        (
            await db.execute(
                text("""SELECT * FROM workspace_tkg_bindings
        WHERE tenant_id=:workspace AND enabled AND evaluation"""),
                {"workspace": workspace},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return empty
    try:
        binding = Binding.from_row(row, workspace)
        return TkgConfig(
            base_url=binding.origin(),
            email="",
            password="",
            kb_id=str(binding.kb_id),
            tenant_id=binding.tkg_tenant,
            source_system=binding.source_system,
            source_instance=binding.source_instance,
            bearer_token=binding.credential("reader"),
            binding=binding,
            evaluation_identity=row["evaluation_identity"],
            allow_send=bool(settings.AISOC_TKG_ALLOW_SEND) and row["evaluation_identity"] == "security_alert",
        )
    except BindingError:
        return empty
