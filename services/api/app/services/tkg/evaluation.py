from uuid import UUID

from sqlalchemy import text

from app.services.tkg.binding import Binding, BindingError
from app.services.tkg_evaluation.client import TkgConfig


async def workspace_config(db, workspace: UUID, settings):
    empty = TkgConfig(base_url="",email="",password="",kb_id="")
    row = (await db.execute(text("""SELECT * FROM workspace_tkg_bindings
        WHERE tenant_id=:workspace AND enabled AND evaluation"""), {"workspace":workspace})).mappings().one_or_none()
    if row is None:
        return empty
    try:
        binding = Binding.from_row(row,workspace)
        return TkgConfig(base_url=binding.origin(),email="",password="",kb_id=str(binding.kb_id),
                         tenant_id=binding.tkg_tenant,source_system=binding.source_system,
                         source_instance=binding.source_instance,bearer_token=binding.credential("reader"),
                         binding=binding,allow_send=bool(settings.AISOC_TKG_ALLOW_SEND))
    except BindingError:
        return empty
