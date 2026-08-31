"""Versioned agent registry (spec §9)."""

from __future__ import annotations

from .contracts import Agent


class UnknownAgentError(KeyError):
    pass


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, Agent] = {}

    def register(self, agent: Agent) -> None:
        self._agents[agent.name] = agent
        self._agents[agent.qualified_name] = agent

    def get(self, name: str) -> Agent:
        agent = self._agents.get(name)
        if agent is None:
            raise UnknownAgentError(f"Unknown agent: {name}")
        return agent

    def names(self) -> list[str]:
        return sorted({agent.qualified_name for agent in self._agents.values()})
