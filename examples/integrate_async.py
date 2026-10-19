"""Integration illustration: replace fake_provider with your product's LLM adapter."""
from __future__ import annotations

import asyncio
import os

from soorin_privacy import AsyncPrivacyClient


async def fake_provider(messages: list[dict]) -> str:
    # In a real product this invokes OpenAI-compatible, Arvan, LiteLLM, etc.
    # ONLY the already protected messages are permitted to reach it.
    return messages[-1]["content"]


async def main():
    async with AsyncPrivacyClient("http://127.0.0.1:8000", os.environ["DLP_DEMO_API_KEY"]) as privacy:
        context = await privacy.create_context(profile="agentic-soc-v1")
        messages = [{"role": "user", "content": "Review dc01.corp.example at 10.20.3.7"}]
        protected = await privacy.encode(messages, format="messages", context_id=context["context_id"])
        provider_response = await fake_provider(protected["payload"])
        restored = await privacy.decode(provider_response, format="text", context_id=context["context_id"])
        print("Local response:", restored["payload"])
        await privacy.delete_context(context["context_id"])


if __name__ == "__main__":
    asyncio.run(main())
