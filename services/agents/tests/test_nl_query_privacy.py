"""Privacy behavior for the optional, currently uncalled NL-query LLM helper."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.nl_query.translator import NLQuery, enhance_with_llm, translate
from app.privacy.context import privacy_context
from app.privacy.gateway import PRIVACY_SYSTEM_GUIDANCE

TENANT = "tenant-nl-query-privacy"
HOST = "endpoint01.corp.synthetic.test"


def _mock_client(content: str) -> MagicMock:
    response = MagicMock(spec=httpx.Response)
    response.raise_for_status.return_value = None
    response.json.return_value = {"choices": [{"message": {"content": content}}]}
    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


@pytest.mark.asyncio
async def test_nl_query_missing_privacy_tenant_falls_back_without_network(privacy_enabled) -> None:
    query = NLQuery(question=f"Show authentication failures for host={HOST}")
    expected = translate(query.question)
    client = _mock_client("{}")

    with patch("httpx.AsyncClient", return_value=client):
        result = await enhance_with_llm(query, api_key="synthetic-provider-key")

    assert result == expected
    client.post.assert_not_called()


@pytest.mark.asyncio
async def test_nl_query_projects_prompt_with_bound_tenant(privacy_enabled) -> None:
    query = NLQuery(question=f"Show authentication failures for host={HOST}")
    deterministic = translate(query.question)
    provider_content = json.dumps(deterministic.as_dict())
    client = _mock_client(provider_content)

    with patch("httpx.AsyncClient", return_value=client):
        with privacy_context(TENANT):
            result = await enhance_with_llm(query, api_key="synthetic-provider-key")

    assert result.esql == deterministic.esql
    client.post.assert_awaited_once()
    body = client.post.call_args.kwargs["json"]
    assert body["messages"][0] == {"role": "system", "content": PRIVACY_SYSTEM_GUIDANCE}
    rendered = json.dumps(body["messages"])
    assert HOST not in rendered
    assert "HOST_" in rendered
