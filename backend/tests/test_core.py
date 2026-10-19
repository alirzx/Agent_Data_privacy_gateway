from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from app.core.detection import Detector
from app.core.engine import PrivacyEngine
from app.core.policy import PolicyRegistry
from app.security.auth import Principal
from app.security.crypto import Crypto
from app.storage.store import MemoryBlobStore


ROOT=Path(__file__).resolve().parents[2]


def policy():
    return PolicyRegistry(ROOT/'profiles').get('agentic-soc-v1')


def test_crypto_authenticated_envelope():
    crypto=Crypto(os.urandom(32))
    ctx='ctx_'+'a'*32
    key=os.urandom(32)
    wrapped=crypto.wrap_dek(ctx,key)
    assert crypto.unwrap_dek(ctx,wrapped)==key
    with pytest.raises(Exception):
        crypto.unwrap_dek('ctx_'+'b'*32,wrapped)
    ct=crypto.encrypt_original(key,ctx,'HOST_TOKEN','dc01.corp')
    assert crypto.decrypt_original(key,ctx,'HOST_TOKEN',ct)=='dc01.corp'
    with pytest.raises(Exception):
        crypto.decrypt_original(key,ctx,'HOST_OTHER',ct)
    root={'context_id':ctx,'password':'very-private'}
    blob=crypto.encrypt_root(ctx,root)
    assert b'very-private' not in blob
    assert crypto.decrypt_root(ctx,blob)==root
    with pytest.raises(Exception):
        crypto.decrypt_root('ctx_'+'b'*32,blob)


def test_detector_soc_noc_categories():
    values={
        'mac_address':'AA:BB:CC:DD:EE:FF','network_cidr':'10.20.0.0/24','domain_name':'corp.internal',
        'url':'https://portal.internal/admin','file_path':'C:\\Windows\\System32\\cmd.exe',
        'user':'ACME\\svc-maint','change_ticket':'CHG-2026-1001','src_ip':'B_309',
        'description':'Public IOC 8.8.8.8 and SIEM reports Registry Change',
        'jwt':'eyJaaaaaaaaaaaa.eyJbbbbbbbbbbbb.ccccccccccccc'
    }
    c=Detector(policy()).discover(values)
    kinds={entry.kind for entry in c}
    assert {'MAC','SUBNET','DOMAIN','URL_INTERNAL','PATH','USER','TICKET','IP_OPAQUE','CRED_JWT'} <= kinds
    assert not any(entry.value=='SIEM' for entry in c)
    assert not any(entry.value=='Change' for entry in c)
    assert not any(entry.value=='8.8.8.8' for entry in c)


def test_policies_differ_on_ticket():
    registry=PolicyRegistry(ROOT/'profiles')
    assert not any(c.kind=='TICKET' for c in Detector(registry.get('generic-v1')).discover({'change_ticket':'CHG-1234'}))
    assert any(c.kind=='TICKET' for c in Detector(registry.get('agentic-soc-v1')).discover({'change_ticket':'CHG-1234'}))


def test_public_ioc_kept_in_text_typed_public_ip_hidden():
    detector=Detector(policy())
    assert not any(x.value=='8.8.8.8' for x in detector.discover('Public IOC 8.8.8.8'))
    assert any(x.value=='8.8.8.8' for x in detector.discover({'src_ip':'8.8.8.8'}))


@pytest.mark.asyncio
async def test_atomic_concurrent_encode_and_separation():
    engine=PrivacyEngine(crypto=Crypto(os.urandom(32)),store=MemoryBlobStore(),policies=PolicyRegistry(ROOT/'profiles'))
    principal=Principal('a',frozenset(),True,False)
    c=await engine.create_context(principal,tenant_id=None,profile='generic-v1')
    async def one(n):
        return await engine.encode(principal,context_id=c['context_id'],fmt='json',payload={'hostname':f'node{n}.corp.internal'},registrations=[])
    results=await asyncio.gather(*(one(i) for i in range(8)))
    assert len({r['payload']['hostname'] for r in results})==8
    for i,r in enumerate(results):
        out=await engine.decode(principal,context_id=c['context_id'],fmt='json',payload=r['payload'])
        assert out['payload']['hostname']==f'node{i}.corp.internal'


@pytest.mark.asyncio
async def test_context_expiration_uses_server_time(monkeypatch):
    import app.core.engine as module
    engine=PrivacyEngine(crypto=Crypto(os.urandom(32)),store=MemoryBlobStore(),policies=PolicyRegistry(ROOT/'profiles'))
    principal=Principal('a',frozenset(),True,False)
    c=await engine.create_context(principal,tenant_id=None,profile='generic-v1',ttl_seconds=60)
    now=module.time.time()
    monkeypatch.setattr(module.time,'time',lambda: now+61)
    with pytest.raises(Exception,match='expired'):
        await engine.encode(principal,context_id=c['context_id'],fmt='text',payload='hello',registrations=[])


@pytest.mark.asyncio
async def test_canonical_token_stability_context_scoped_credential():
    engine=PrivacyEngine(crypto=Crypto(os.urandom(32)),store=MemoryBlobStore(),policies=PolicyRegistry(ROOT/'profiles'))
    principal=Principal('a',frozenset({'corp'}),True,False)
    first=await engine.create_context(principal,tenant_id='corp',profile='generic-v1')
    second=await engine.create_context(principal,tenant_id='corp',profile='generic-v1')
    original={'hostname':'DC01.CORP.INTERNAL','password':'synthetic-test-password'}
    a=await engine.encode(principal,context_id=first['context_id'],fmt='json',payload=original,registrations=[])
    b=await engine.encode(principal,context_id=second['context_id'],fmt='json',payload=original,registrations=[])
    assert a['payload']['hostname']==b['payload']['hostname']
    assert a['payload']['password'] != b['payload']['password']
