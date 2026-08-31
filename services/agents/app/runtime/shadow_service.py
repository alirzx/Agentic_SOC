"""AgenticShadowService — parallel shadow execution, never mutates Case."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from .catalog import build_agent_registry
from .comparison import build_comparison, existing_from_fused
from .contracts import AgentContext, AgentConstraints, IncidentStateSnapshot
from .flags import enabled, max_concurrent_runs, shadow_mode, timeout_seconds
from .orchestrator import SocOrchestrator
from .runtime import AgentRuntime
from .shadow_store import InMemoryShadowStore, ShadowRunRecord

logger = structlog.get_logger()

WORKFLOW_VERSION = "agentic-shadow-v1"
_IDEM_TTL_SECONDS = 86_400
_TERMINAL_SKIP = frozenset({"created", "running", "completed"})


class AgenticShadowService:
    def __init__(
        self,
        *,
        store: InMemoryShadowStore | None = None,
        orchestrator: SocOrchestrator | None = None,
        idempotency: dict[str, str] | None = None,
        max_concurrent: int | None = None,
        timeout: float | None = None,
        governor: Any | None = None,
        redis: Any | None = None,
    ) -> None:
        self._store = store or InMemoryShadowStore()
        if orchestrator is None:
            registry = build_agent_registry()
            orchestrator = SocOrchestrator(AgentRuntime(registry), registry)
        self._orchestrator = orchestrator
        self._idempotency = idempotency if idempotency is not None else {}
        self._sem = asyncio.Semaphore(max_concurrent or max_concurrent_runs())
        self._timeout = timeout if timeout is not None else timeout_seconds()
        self._governor = governor
        self._redis = redis
        self._queued = 0

    @property
    def store(self) -> InMemoryShadowStore:
        return self._store

    @property
    def queued(self) -> int:
        return self._queued

    def _idempotency_key(self, tenant_id: str, alert_id: str) -> str:
        return f"agentic-shadow:{tenant_id}:{alert_id}"

    async def _persist(self, record: ShadowRunRecord) -> None:
        saver = getattr(self._store, "save", None)
        if saver is None:
            return
        saved = saver(record)
        if asyncio.iscoroutine(saved):
            await saved

    async def _claim(self, key: str) -> bool:
        if self._redis is not None:
            try:
                ok = await self._redis.set(key, "1", nx=True, ex=_IDEM_TTL_SECONDS)
                return bool(ok)
            except Exception:  # noqa: BLE001 — fall back to in-process
                logger.debug("agentic.shadow.redis_claim_failed")
        if key in self._idempotency:
            return False
        self._idempotency[key] = "claimed"
        return True

    async def _release_claim(self, key: str) -> None:
        """Allow retry after FAILED / TIMEOUT (not after COMPLETED)."""
        self._idempotency.pop(key, None)
        if self._redis is None:
            return
        try:
            await self._redis.delete(key)
        except Exception:  # noqa: BLE001
            return

    async def submit(self, message: dict[str, Any]) -> ShadowRunRecord | None:
        """Queue (via semaphore wait) and run. Never silently drops. Never raises."""
        if not enabled():
            return None
        if self._sem.locked():
            self._queued += 1
            from . import metrics as metrics_mod

            metrics_mod.record_queued()
        try:
            async with self._sem:
                return await self._execute(message)
        except Exception as exc:  # noqa: BLE001 — production flow must continue
            logger.warning(
                "agentic.shadow.isolated_failure",
                error=f"{type(exc).__name__}: {exc}".replace("\r", "").replace("\n", " ")[:200],
            )
            return None

    async def _execute(self, message: dict[str, Any]) -> ShadowRunRecord | None:
        from . import metrics as metrics_mod

        alert = message.get("alert") if isinstance(message.get("alert"), dict) else {}
        tenant_id = str(message.get("tenant_id") or alert.get("tenant_id") or "")
        alert_id = str(message.get("alert_row_id") or message.get("id") or alert.get("id") or "")
        case_id = str(message.get("incident_id") or message.get("case_id") or "")
        if not tenant_id or not alert_id:
            return None
        key = self._idempotency_key(tenant_id, alert_id)
        existing = self._store.get_by_alert(tenant_id, alert_id)
        if existing is not None and existing.status in _TERMINAL_SKIP:
            return existing
        claimed = await self._claim(key)
        if not claimed:
            for _ in range(8):
                found = self._store.get_by_alert(tenant_id, alert_id)
                if found is not None:
                    return found
                run_id = self._idempotency.get(key)
                if run_id and run_id not in {"claimed", ""}:
                    found = self._store.get(run_id)
                    if found is not None:
                        return found
                await asyncio.sleep(0)
            return self._store.get_by_alert(tenant_id, alert_id)
        record = existing if existing is not None else ShadowRunRecord(
            tenant_id=tenant_id,
            alert_id=alert_id,
            case_id=case_id,
            status="created",
            prompt_version="agentic-soc-runtime/v1",
            workflow_version=WORKFLOW_VERSION,
        )
        record.status = "running"
        record.started_at = record_now()
        record.error = None
        self._idempotency[key] = record.id
        await self._persist(record)
        metrics_mod.record_start()
        started = time.monotonic()
        skip_heavy = False
        if self._governor is not None:
            try:
                from app.core.cost_governor import Decision as GovernorDecision

                gov = self._governor.decide(tenant_id, message)
                skip_heavy = gov.decision is GovernorDecision.CIRCUIT_OPEN
            except Exception:  # noqa: BLE001
                skip_heavy = False
        context = AgentContext(
            incident_id=case_id or alert_id,
            tenant_id=tenant_id,
            objective=str(alert.get("title") or message.get("narrative") or "shadow investigation"),
            state=IncidentStateSnapshot(
                state="NEW",
                severity=str(alert.get("severity") or "medium"),
                raw_alert={
                    **alert,
                    "severity": alert.get("severity") or "medium",
                    "asset_criticality": 10 if alert.get("hostname") else 0,
                    "user_privilege": 8 if "admin" in str(alert.get("username") or "").lower() else 0,
                    "threat_intel": 10 if alert.get("src_ip") or alert.get("file_hash") or alert.get("domain") else 0,
                    "correlation": 5 if message.get("fusion_decision") else 0,
                    "attack_chain": 8 if alert.get("mitre_techniques") else 0,
                },
                confidence=float(message.get("confidence_score") or 0.0),
            ),
            constraints=AgentConstraints(
                max_iterations=8,
                max_tool_calls=16,
                timeout_ms=max(1000, int(self._timeout * 1000)),
            ),
            metadata={
                "shadow_mode": True,
                "fail_soft": True,
                "skip_investigation": skip_heavy,
                "skip_ti": skip_heavy,
                "approval_granted": False,
            },
        )
        status = "completed"
        error: str | None = None
        results: list[Any] = []
        tracker: Any | None = None
        try:
            from app.core.cost_telemetry import CostTracker

            tracker = CostTracker(run_id=record.id, tenant_id=tenant_id)
            await tracker.__aenter__()
        except Exception:  # noqa: BLE001
            tracker = None
        try:
            results = await asyncio.wait_for(self._orchestrator.run(context), timeout=self._timeout)
        except TimeoutError:
            status = "timeout"
            error = "timeout"
        except Exception as exc:  # noqa: BLE001
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"
        finally:
            if tracker is not None:
                record.input_tokens = sum(item.prompt_tokens for item in tracker._records)
                record.output_tokens = sum(item.completion_tokens for item in tracker._records)
                record.estimated_cost = float(tracker.total_cost_usd)
                try:
                    await tracker.__aexit__(None, None, None)
                except Exception:  # noqa: BLE001
                    pass
        duration_ms = int((time.monotonic() - started) * 1000)
        if skip_heavy and status == "completed":
            error = error or "budget_exceeded"
        decision_text = ""
        actions: list[str] = []
        evidence: list[dict[str, Any]] = []
        mitre: list[str] = []
        confidence = context.state.confidence
        risk_score = float(context.state.risk_score or 0.0)
        tool_calls = 0
        for result in results:
            tool_calls += len(result.actions)
            actions.extend(action.name for action in result.actions)
            evidence.extend(item.model_dump(mode="json") for item in result.evidence)
            for finding in result.findings:
                mitre.extend(finding.mitre_techniques)
                if finding.statement.startswith("decision="):
                    decision_text = finding.statement
                    if "risk=" in finding.statement:
                        try:
                            risk_score = float(finding.statement.split("risk=")[1].split("/")[0])
                        except (IndexError, ValueError):
                            pass
            if result.confidence:
                confidence = result.confidence
        actions = list(dict.fromkeys(actions))
        seen_evidence: set[str] = set()
        unique_evidence: list[dict[str, Any]] = []
        for item in evidence:
            eid = str(item.get("id") or "")
            if eid and eid in seen_evidence:
                continue
            if eid:
                seen_evidence.add(eid)
            unique_evidence.append(item)
        evidence = unique_evidence
        iocs = [
            str(item.get("data", {}).get("ioc") or "")
            for item in evidence
            if isinstance(item.get("data"), dict) and item.get("data", {}).get("ioc")
        ]
        mitre_final = list(dict.fromkeys(mitre)) or list(alert.get("mitre_techniques") or [])
        ioc_final = [ioc for ioc in iocs if ioc] or [
            v for v in (alert.get("src_ip"), alert.get("domain"), alert.get("file_hash")) if v
        ]
        agentic_view = {
            "severity": context.state.severity,
            "riskScore": risk_score,
            "confidence": confidence,
            "classification": decision_text,
            "recommendedActions": actions,
            "mitreTechniques": mitre_final,
            "iocs": ioc_final,
            "affectedAssets": [str(alert.get("hostname") or "")] if alert.get("hostname") else [],
            "affectedUsers": [str(alert.get("username") or "")] if alert.get("username") else [],
            "privileged_account": "admin" in str(alert.get("username") or "").lower(),
            "correlated": any("correlated" in (r.reasoning or "") or "ldap" in (r.reasoning or "").lower() for r in results),
        }
        comparison = build_comparison(
            case_id=case_id,
            existing=existing_from_fused(message),
            agentic=agentic_view,
        )
        record.status = status
        record.completed_at = record_now()
        record.duration_ms = duration_ms
        record.risk_score = risk_score
        record.confidence = confidence
        record.decision = decision_text
        record.recommended_actions = actions
        record.tool_call_count = tool_calls
        record.error = error
        record.evidence = evidence
        record.comparison = comparison
        record.result = {"agentic": agentic_view, "shadow_mode": shadow_mode()}
        await self._persist(record)
        if status in {"failed", "timeout"}:
            await self._release_claim(key)
        logger.info(
            "agentic.shadow.completed",
            shadow_run_id=record.id.replace("\r", "").replace("\n", " ")[:80],
            alert_id=alert_id.replace("\r", "").replace("\n", " ")[:80],
            case_id=case_id.replace("\r", "").replace("\n", " ")[:80],
            tenant_id=tenant_id.replace("\r", "").replace("\n", " ")[:80],
            agent="soc-orchestrator",
            agent_version=record.agent_version.replace("\r", "").replace("\n", " ")[:40],
            state=status,
            tool_calls=tool_calls,
            tokens=record.input_tokens + record.output_tokens,
            cost=record.estimated_cost,
            latency=duration_ms,
            risk=risk_score,
            confidence=confidence,
            decision=decision_text.replace("\r", "").replace("\n", " ")[:120],
            recommended_actions=actions[:8],
            error=(error or "").replace("\r", "").replace("\n", " ")[:200],
            duration_ms=duration_ms,
        )
        metrics_mod.record_finish(
            status=status,
            duration_ms=duration_ms,
            tool_calls=tool_calls,
            input_tokens=record.input_tokens,
            output_tokens=record.output_tokens,
            risk_score=risk_score,
            confidence=confidence,
        )
        return record


def record_now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
