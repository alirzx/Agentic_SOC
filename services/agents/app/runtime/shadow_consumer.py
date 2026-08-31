"""Kafka consumer for Agentic SOC shadow runs. Separate group; does not touch the triage worker."""

from __future__ import annotations

import json
import os
from typing import Any

import structlog

from .flags import enabled
from .shadow_service import AgenticShadowService
from .shadow_store import PostgresShadowStore

logger = structlog.get_logger()


async def _optional_redis() -> Any | None:
    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        return None
    try:
        import redis.asyncio as aioredis
    except ImportError:
        return None
    try:
        client = aioredis.from_url(url, decode_responses=True)
        await client.ping()
        return client
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "agentic.shadow.redis_unavailable",
            error=str(exc).replace("\r", "").replace("\n", " ")[:200],
        )
        return None


class AgenticShadowConsumer:
    def __init__(
        self,
        *,
        bootstrap_servers: str,
        topic: str = "aisoc.alerts.fused",
        group_id: str = "aisoc-agents-agentic-shadow",
        service: AgenticShadowService | None = None,
    ) -> None:
        self._bootstrap = bootstrap_servers
        self._topic = topic
        self._group_id = group_id
        self._service = service
        self._consumer: Any | None = None
        self._running = False

    async def start(self) -> None:
        from aiokafka import AIOKafkaConsumer

        if self._service is None:
            governor = None
            try:
                from app.core.cost_governor import get_governor

                governor = get_governor()
            except Exception:  # noqa: BLE001
                governor = None
            self._service = AgenticShadowService(
                store=PostgresShadowStore(),
                redis=await _optional_redis(),
                governor=governor,
            )
        self._consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=self._bootstrap,
            group_id=self._group_id,
            auto_offset_reset="latest",
            enable_auto_commit=False,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )
        await self._consumer.start()
        self._running = True
        logger.info("agentic.shadow.consumer.started", topic=self._topic, group=self._group_id)
        try:
            async for msg in self._consumer:
                if not self._running:
                    break
                try:
                    await self._service.submit(msg.value if isinstance(msg.value, dict) else {})
                except Exception as exc:  # noqa: BLE001 — never kill the loop
                    logger.warning(
                        "agentic.shadow.consumer.isolated",
                        error=f"{type(exc).__name__}: {exc}".replace("\r", "").replace("\n", " ")[:200],
                    )
                try:
                    await self._consumer.commit()
                except Exception as commit_exc:  # noqa: BLE001
                    logger.warning("agentic.shadow.consumer.commit_failed", error=str(commit_exc))
        finally:
            await self._consumer.stop()

    async def stop(self) -> None:
        self._running = False
        if self._consumer is not None:
            await self._consumer.stop()


def shadow_consumer_enabled() -> bool:
    if not enabled():
        return False
    if os.getenv("AISOC_AGENT_KAFKA_DISABLE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return bool(os.getenv("KAFKA_BOOTSTRAP_SERVERS", "").strip())
