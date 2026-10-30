"""Credential-safe HTTPX transport for the independent Privacy Gateway.

This client implements only the published REST contract. Detection,
tokenization, alias storage, encryption, and policy behavior remain Gateway
responsibilities.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx


class PrivacyGatewayRESTError(RuntimeError):
    """Sanitized Gateway transport/contract error.

    Response bodies are deliberately excluded because they may contain request
    details or credentials supplied by an upstream proxy.
    """

    def __init__(self, category: str, *, status_code: int | None = None) -> None:
        super().__init__(f"privacy gateway REST failure: {category}")
        self.category = category
        self.status_code = status_code


class PrivacyGatewayRESTClient:
    """Minimal asynchronous client for workflow Context operations."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        max_connections: int = 20,
        max_keepalive_connections: int = 10,
    ) -> None:
        if not api_key:
            raise PrivacyGatewayRESTError("service_credential_required")
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_keepalive_connections,
            ),
            transport=transport,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    @staticmethod
    def _object(response: httpx.Response, *, expected_status: int) -> dict[str, Any]:
        if response.status_code != expected_status:
            if response.is_success:
                raise PrivacyGatewayRESTError("invalid_gateway_response")
            raise PrivacyGatewayRESTError("gateway_request_rejected", status_code=response.status_code)
        try:
            payload = response.json()
        except ValueError as exc:
            raise PrivacyGatewayRESTError("invalid_gateway_response") from exc
        if not isinstance(payload, dict):
            raise PrivacyGatewayRESTError("invalid_gateway_response")
        return payload

    @staticmethod
    def _validate_object(
        payload: dict[str, Any],
        *,
        string_fields: tuple[str, ...],
        value_fields: tuple[str, ...] = (),
        stats: bool = False,
    ) -> dict[str, Any]:
        if any(not isinstance(payload.get(field), str) for field in string_fields):
            raise PrivacyGatewayRESTError("invalid_gateway_response")
        if any(field not in payload for field in value_fields):
            raise PrivacyGatewayRESTError("invalid_gateway_response")
        if stats:
            values = payload.get("stats")
            if not isinstance(values, dict) or any(
                not isinstance(key, str) or type(value) is not int for key, value in values.items()
            ):
                raise PrivacyGatewayRESTError("invalid_gateway_response")
        return payload

    async def _request_object(
        self,
        method: str,
        path: str,
        *,
        expected_status: int,
        json: dict[str, Any],
    ) -> dict[str, Any]:
        response = await self._client.request(method, path, json=json)
        return self._object(response, expected_status=expected_status)

    async def create_context(
        self,
        *,
        tenant_id: str,
        profile: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        result = await self._request_object(
            "POST",
            "/v1/contexts",
            expected_status=201,
            json={
                "tenant_id": tenant_id,
                "profile": profile,
                "ttl_seconds": ttl_seconds,
            },
        )
        return self._validate_object(
            result,
            string_fields=("context_id", "profile", "policy_version", "expires_at"),
            value_fields=("tenant_id",),
        )

    async def encode(
        self,
        payload: Any,
        *,
        format: str,
        context_id: str,
        profile: str,
        tenant_id: str,
        registrations: list[dict[str, str]],
        purpose: str = "llm-egress",
    ) -> dict[str, Any]:
        result = await self._request_object(
            "POST",
            "/v1/encode",
            expected_status=200,
            json={
                "context_id": context_id,
                "tenant_id": tenant_id,
                "profile": profile,
                "purpose": purpose,
                "format": format,
                "payload": payload,
                "registrations": registrations,
            },
        )
        return self._validate_object(
            result,
            string_fields=("context_id", "policy_version", "format", "expires_at"),
            value_fields=("payload",),
            stats=True,
        )

    async def decode(
        self,
        payload: Any,
        *,
        context_id: str,
        format: str = "json",
        purpose: str = "llm-response",
        reveal_credentials: bool = False,
    ) -> dict[str, Any]:
        result = await self._request_object(
            "POST",
            "/v1/decode",
            expected_status=200,
            json={
                "context_id": context_id,
                "format": format,
                "payload": payload,
                "purpose": purpose,
                "reveal_credentials": reveal_credentials,
            },
        )
        return self._validate_object(
            result,
            string_fields=("context_id", "format"),
            value_fields=("payload",),
            stats=True,
        )

    async def delete_context(self, context_id: str) -> None:
        response = await self._client.delete(f"/v1/contexts/{quote(context_id, safe='')}")
        if response.status_code != 204:
            raise PrivacyGatewayRESTError("gateway_request_rejected", status_code=response.status_code)


__all__ = ["PrivacyGatewayRESTClient", "PrivacyGatewayRESTError"]
