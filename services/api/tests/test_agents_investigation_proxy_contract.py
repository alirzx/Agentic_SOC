"""Static contract regression for the authenticated API-to-Agents investigation proxy."""
from __future__ import annotations

import ast
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "app/api/v1/endpoints/agents.py"


def _route(name: str) -> ast.AsyncFunctionDef:
    module = ast.parse(SOURCE.read_text(encoding="utf-8"))
    return next(n for n in module.body if isinstance(n, ast.AsyncFunctionDef) and n.name == name)


def _client_posts(route: ast.AsyncFunctionDef) -> list[ast.Call]:
    # ast.walk includes @router.post(...) decorators. Count outbound client
    # calls only, otherwise the route declaration is mistaken for a network POST.
    return [
        n for n in ast.walk(route)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "post"
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "client"
    ]


def test_investigation_is_sent_once_with_signed_tenant():
    route = _route("investigate_alert")
    posts = _client_posts(route)
    assert len(posts) == 1, "One user action must create only one Agents investigation"
    headers = next((kw.value for kw in posts[0].keywords if kw.arg == "headers"), None)
    assert isinstance(headers, ast.Call)
    assert isinstance(headers.func, ast.Name)
    assert headers.func.id == "_tenant_headers"
    assert len(headers.args) == 1
    assert isinstance(headers.args[0], ast.Attribute)
    assert headers.args[0].attr == "tenant_id"


def test_investigation_poll_forwards_signed_tenant():
    route = _route("get_alert_investigation")
    # Likewise skip @router.get(...) when counting outbound polling calls.
    gets = [
        n for n in ast.walk(route)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "get"
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "client"
    ]
    assert len(gets) == 1
    headers = next((kw.value for kw in gets[0].keywords if kw.arg == "headers"), None)
    assert isinstance(headers, ast.Call)
    assert isinstance(headers.func, ast.Name)
    assert headers.func.id == "_tenant_headers"
