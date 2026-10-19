from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'sdk' / 'python'))
from soorin_privacy import AsyncPrivacyClient, PrivacySDKError  # noqa: E402


@pytest.mark.asyncio
async def test_sdk_full_egress_roundtrip_without_external_provider(client):
    app=client.app
    async with AsyncPrivacyClient('http://testserver','test-copilot-key',transport=httpx.ASGITransport(app=app)) as sdk:
        ctx=await sdk.create_context(profile='soorin-copilot-v1',tenant_id='tenant-1')
        messages=[{'role':'user','content':'Investigate 10.20.3.7 and dc01.corp.example'}]
        result=await sdk.encode(messages,context_id=ctx['context_id'],format='messages',profile='soorin-copilot-v1',tenant_id='tenant-1')
        assert '10.20.3.7' not in result['payload'][-1]['content']
        assert 'HOST_' in result['payload'][-1]['content']
        simulated_provider_result=result['payload'][-1]['content']
        restored=await sdk.decode(simulated_provider_result,context_id=ctx['context_id'],format='text')
        assert restored['payload']=='Investigate 10.20.3.7 and dc01.corp.example'
        await sdk.delete_context(ctx['context_id'])
        with pytest.raises(PrivacySDKError):
            await sdk.decode(simulated_provider_result,context_id=ctx['context_id'],format='text')
