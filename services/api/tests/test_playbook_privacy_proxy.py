"""Static routing contract for authenticated NL playbook drafting."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_api_draft_proxy_signs_authenticated_tenant() -> None:
    source = (
        ROOT / "services/api/app/api/v1/endpoints/playbooks.py"
    ).read_text(encoding="utf-8")
    assert '@router.post("/draft-from-nl"' in source
    assert "user: AuthUser" in source
    assert "signed_tenant_headers(user.tenant_id)" in source
    assert '"/draft-from-nl"' in source


def test_web_routes_llm_draft_through_authenticated_core_api_first() -> None:
    config = (ROOT / "apps/web/next.config.js").read_text(encoding="utf-8")
    authenticated = "destination: `${API_HOST}/api/v1/playbooks/draft-from-nl`"
    generic = "source: '/api/v1/playbooks/:path*'"
    assert authenticated in config
    assert config.index(authenticated) < config.index(generic)


def test_browser_llm_surfaces_route_through_authenticated_api_proxy() -> None:
    config = (ROOT / "apps/web/next.config.js").read_text(encoding="utf-8")
    proxy = (
        ROOT / "services/api/app/api/v1/endpoints/agents_llm_proxy.py"
    ).read_text(encoding="utf-8")
    router = (ROOT / "services/api/app/api/v1/router.py").read_text(encoding="utf-8")

    assert "`${API_HOST}/api/v1/agent-llm/contextual/:path*`" in config
    assert "`${API_HOST}/api/v1/agent-llm/copilot/:path*`" in config
    assert "signed_tenant_headers(user.tenant_id)" in proxy
    assert '_SURFACES = frozenset({"contextual", "copilot"})' in proxy
    assert "include_router(agents_llm_proxy.router)" in router
