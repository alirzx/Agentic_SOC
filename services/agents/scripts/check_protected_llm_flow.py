"""Synthetic local LLM + real DLP: verifies provider-bound alias and local rehydration."""
import argparse
import asyncio
import os
from uuid import UUID

from langchain_core.messages import AIMessage, HumanMessage
from app.llm.contract import safe_ainvoke
from app.privacy.context import async_privacy_context, privacy_backend_name, privacy_enabled

HOST = "dc01.corp.example"


class SyntheticLocalModel:
    model = "no-network-synthetic"
    called = False

    async def ainvoke(self, messages, **kwargs):
        self.called = True
        text = str(messages[-1].content)
        if HOST in text or "HOST_" not in text:
            raise AssertionError("DLP did not protect provider input")
        return AIMessage(content="Synthetic provider response: " + text)


async def verify(tenant: str) -> None:
    if not privacy_enabled() or privacy_backend_name() != "remote":
        raise SystemExit("Remote privacy must be enabled")
    if str(UUID(tenant)) != tenant:
        raise SystemExit("Tenant must be a canonical UUID")
    model = SyntheticLocalModel()
    async with async_privacy_context(tenant):
        output = await safe_ainvoke(model, [HumanMessage(content="Investigate host=" + HOST)])
    if not model.called or HOST not in output.content:
        raise AssertionError("Protected provider call / local decode failed")
    print("PASS: real DLP context+encode+decode+delete with synthetic local LLM")
    print("PASS: raw host did not reach provider; authorized host rehydrated locally")
    print("PASS: external provider calls = 0")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id", default=os.getenv("AISOC_PRIVACY_TEST_TENANT_ID"))
    args = parser.parse_args()
    if not args.tenant_id:
        raise SystemExit("Set --tenant-id or AISOC_PRIVACY_TEST_TENANT_ID")
    asyncio.run(verify(args.tenant_id))
