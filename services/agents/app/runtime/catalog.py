"""Default registries — wrap existing tools; do not replace app.tools.registry."""

from __future__ import annotations

from typing import Any

from .adapters import (
    CorrelationRuntimeAgent,
    InvestigationRuntimeAgent,
    ThreatIntelRuntimeAgent,
    TriageRuntimeAgent,
)
from .decision import DecisionAgent
from .registry import AgentRegistry
from .reports import ReportAgent
from .response import ResponseAgent
from .tools import CallableSOCTool, SocToolRegistry
from .validation import ValidationAgent


def _simulated_response(**kwargs: Any) -> dict[str, Any]:
    return {"status": "simulated", "dry_run": True, "input": kwargs}


def build_tool_registry() -> SocToolRegistry:
    from app.investigator.tools import enrich_ioc, extract_iocs, fetch_related_alerts, map_to_mitre
    from app.tools.mitre import lookup_technique

    registry = SocToolRegistry()
    read_agents = frozenset(
        {"triage", "investigation", "threat-intel", "correlation", "decision", "validation", "report"}
    )
    registry.register(
        CallableSOCTool(
            name="ti.lookup_ip",
            description="Enrich an IP with threat intelligence.",
            fn=lambda ioc_value, ioc_type="ip": enrich_ioc(ioc_value, ioc_type),
            risk_level="read",
            allowed_agents=read_agents,
            input_schema={"type": "object", "required": ["ioc_value"]},
        )
    )
    registry.register(
        CallableSOCTool(
            name="ti.lookup_hash",
            description="Enrich a file hash.",
            fn=lambda ioc_value, ioc_type="hash": enrich_ioc(ioc_value, ioc_type),
            risk_level="read",
            allowed_agents=read_agents,
        )
    )
    registry.register(
        CallableSOCTool(
            name="ti.search_attack_technique",
            description="Look up a MITRE ATT&CK technique by ID.",
            fn=lambda technique_id: lookup_technique(technique_id),
            risk_level="read",
            allowed_agents=read_agents,
        )
    )
    registry.register(
        CallableSOCTool(
            name="siem.get_related_events",
            description="Fetch related alerts for a case (paginated).",
            fn=fetch_related_alerts,
            risk_level="read",
            allowed_agents=frozenset({"investigation", "correlation", "validation"}),
        )
    )
    registry.register(
        CallableSOCTool(
            name="extract_iocs",
            description="Extract IOCs from free text.",
            fn=extract_iocs,
            risk_level="read",
            allowed_agents=read_agents,
        )
    )
    registry.register(
        CallableSOCTool(
            name="map_to_mitre",
            description="Map text to ATT&CK technique IDs.",
            fn=map_to_mitre,
            risk_level="read",
            allowed_agents=read_agents,
        )
    )
    for name, desc in (
        ("response.block_ip", "Block an IP (always simulated here)."),
        ("response.isolate_asset", "Isolate an asset (always simulated here)."),
        ("response.disable_user", "Disable a user (always simulated here)."),
        ("response.kill_process", "Kill a process (always simulated here)."),
        ("response.create_firewall_rule", "Change a firewall rule (always simulated here)."),
        ("firewall_change", "Change a firewall rule (always simulated here)."),
    ):
        risk = "critical" if "disable" in name or "isolate" in name else "medium"
        registry.register(
            CallableSOCTool(
                name=name,
                description=desc,
                fn=_simulated_response,
                risk_level="high" if risk != "critical" else "critical",
                requires_approval=True,
                allowed_agents=frozenset({"decision", "response"}),
            )
        )
    return registry


def build_agent_registry() -> AgentRegistry:
    registry = AgentRegistry()
    for agent in (
        TriageRuntimeAgent(),
        InvestigationRuntimeAgent(),
        ThreatIntelRuntimeAgent(),
        CorrelationRuntimeAgent(),
        DecisionAgent(),
        ResponseAgent(),
        ValidationAgent(),
        ReportAgent(),
    ):
        registry.register(agent)
    return registry
