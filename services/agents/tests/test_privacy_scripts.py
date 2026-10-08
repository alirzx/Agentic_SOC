"""Privacy diagnostic scripts keep provider credentials out of output."""

from __future__ import annotations

from app.scripts.privacy_provider_probe import _safe_route


def test_provider_probe_route_never_prints_embedded_credentials() -> None:
    secret = "gateway-token-that-must-never-appear"
    rendered = _safe_route(f"https://user:password@provider.synthetic.test/gateway/{secret}/v1")
    assert rendered == "https://provider.synthetic.test/.../v1"
    assert secret not in rendered
    assert "user" not in rendered and "password" not in rendered
