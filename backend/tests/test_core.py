from __future__ import annotations

import asyncio
import json
import os
import re
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


def test_splunk_notable_schema_gaps_generic_v1():
    """Regression: Splunk ES notable columns that previously leaked under generic-v1."""
    detector = Detector(PolicyRegistry(ROOT / 'profiles').get('generic-v1'))
    payload = {
        'entity': 'ws-finance-01',
        'entity_type': 'system',
        'risk_object': 'ws-finance-01',
        'risk_object_type': 'system',
        'src': 'B_106',
        'dest': 'ws-finance-01',
        'IpAddress': '203.0.113.50',
        'failed_user': 'svc-backup\nalice.j\nadmin.local',
        'tried_accounts': 'svc-backup\nalice.j',
        'user': 'alice.j',
        'splunk_server': 'sh-primary',
        'index': 'notable',
        'Image': 'C:\\Windows\\System32\\net.exe',
        'parent_process_path': 'C:\\Windows\\System32\\cmd.exe',
        'threat_object': 'ws-finance-01',
        'threat_object_type': 'system',
        'orig_rule_title': 'Potential password spraying attack on ws-finance-01',
        '_raw': 'IpAddress="203.0.113.50" dest="ws-finance-01" failed_user="alice.j" src="B_106"',
        'severity': 'medium',
        'risk_score': '50.0',
    }
    found = detector.discover(payload)
    values = {entry.value for entry in found}
    kinds = {entry.kind for entry in found}
    assert 'alice.j' in values and 'svc-backup' in values and 'admin.local' in values
    assert 'ws-finance-01' in values and 'B_106' in values
    assert '203.0.113.50' in values
    assert 'sh-primary' in values and 'notable' in values
    assert 'C:\\Windows\\System32\\net.exe' in values
    assert {'USER', 'HOST', 'IP', 'SPLUNK_INDEX', 'PATH'} <= kinds
    assert not any(entry.value == 'medium' for entry in found)


@pytest.mark.asyncio
async def test_splunk_notable_encode_scrubs_narrative_generic_v1():
    engine = PrivacyEngine(
        crypto=Crypto(os.urandom(32)),
        store=MemoryBlobStore(),
        policies=PolicyRegistry(ROOT / 'profiles'),
    )
    principal = Principal('a', frozenset(), True, False)
    context = await engine.create_context(principal, tenant_id=None, profile='generic-v1')
    payload = {
        'dest': 'eccairs-lab',
        'entity_type': 'system',
        'risk_object': 'eccairs-lab',
        'risk_object_type': 'system',
        'src': 'B_106',
        'IpAddress': '198.51.100.20',
        'failed_user': 'spray-user-1\nspray-user-2',
        'tried_accounts': 'spray-user-1\nspray-user-2',
        'splunk_server': 'idx-lab-01',
        'index': 'risk',
        'orig_rule_title': 'Potential password spraying attack on eccairs-lab',
        '_raw': 'dest="eccairs-lab" IpAddress="198.51.100.20" tried_accounts="spray-user-1"',
        'severity': 'medium',
    }
    protected = await engine.encode(
        principal, context_id=context['context_id'], fmt='json', payload=payload, registrations=[],
    )
    blob = json.dumps(protected['payload'])
    for secret in (
        'eccairs-lab', 'B_106', '198.51.100.20', 'spray-user-1', 'spray-user-2', 'idx-lab-01',
    ):
        assert secret not in blob
    assert protected['payload']['severity'] == 'medium'
    assert protected['payload']['index'].startswith('SPLUNK_INDEX_')
    assert protected['payload']['splunk_server'].startswith('HOST_')
    assert protected['payload']['IpAddress'].startswith('IP_V4_')


def test_polymorphic_identity_infers_without_sibling_type():
    detector = Detector(PolicyRegistry(ROOT / 'profiles').get('generic-v1'))
    found = detector.discover({'src': 'B_309', 'dest': '10.0.0.8', 'threat_object': 'CORP\\alice'})
    by_value = {entry.value: entry.kind for entry in found}
    assert by_value['B_309'] == 'HOST'
    assert by_value['10.0.0.8'] == 'IP'
    assert by_value['CORP\\alice'] == 'USER'


def test_low_signal_multivalue_fragments_rejected():
    detector = Detector(PolicyRegistry(ROOT / 'profiles').get('generic-v1'))
    found = detector.discover({
        'failed_user': '0\n1\n\\\nA\nreal.user',
        'tried_accounts': 'DC\nsvc-backup',
        'file_name': 'payload.ps1',
        'original_file_name': 'invoice.scr',
    })
    values = {entry.value for entry in found}
    assert 'real.user' in values
    assert 'svc-backup' in values
    # Two-letter spray fragments stay unprotected by design (acronym collision).
    assert 'DC' not in values
    assert 'payload.ps1' in values and 'invoice.scr' in values
    assert '0' not in values and '1' not in values and 'A' not in values
    assert '\\' not in values


def test_splunk_csv_double_quoted_failed_users_in_text():
    """Regression: CSV/_raw failed_user=\"\"SAM\"\" and bare dotted SAMs must encode as USER."""
    detector = Detector(PolicyRegistry(ROOT / 'profiles').get('generic-v1'))
    # Synthetic notables export fragment (not production customer data).
    csv_fragment = (
        'failed_user=""AB.TESTUSER"", failed_user=""XY.ANALYST"", '
        'failed_user=""LAB-PRIMARY$"", failed_user=""PPC-LAB$"", '
        'src=""::FFFF:10.0.0.50"", user_dc=""16""\n'
        '16,"AB.TESTUSER\nXY.ANALYST\nLAB-PRIMARY$\nPPC-LAB$",28,'
    )
    found = detector.discover(csv_fragment)
    values = {entry.value for entry in found}
    assert 'AB.TESTUSER' in values
    assert 'XY.ANALYST' in values
    assert 'LAB-PRIMARY$' in values
    assert 'PPC-LAB$' in values
    assert all(entry.kind == 'USER' for entry in found if entry.value in {
        'AB.TESTUSER', 'XY.ANALYST', 'LAB-PRIMARY$', 'PPC-LAB$',
    })
    # Count fields and DNS/file-like two-labels must not become USER via free text.
    assert '16' not in values
    assert not any(entry.value == 'example.com' for entry in detector.discover('visit example.com now'))
    assert not any(entry.value == 'payload.ps1' for entry in detector.discover('dropped payload.ps1'))


def test_dotted_sam_ignores_alias_suffix_after_projection():
    """Regression: prefix.USER_<hex> must not re-trigger dotted-SAM detection."""
    detector = Detector(PolicyRegistry(ROOT / 'profiles').get('generic-v1'))
    alias = 'USER_' + ('A' * 32)
    glued = f'risk_message="spray against MOD.{alias} and KEEP.{alias}"'
    found = detector.discover(glued)
    assert not any(item.kind == 'USER' for item in found)
    assert not any(alias in item.value and item.value != alias for item in found)


@pytest.mark.asyncio
async def test_splunk_csv_text_encode_scrubs_dotted_users():
    engine = PrivacyEngine(
        crypto=Crypto(os.urandom(32)),
        store=MemoryBlobStore(),
        policies=PolicyRegistry(ROOT / 'profiles'),
    )
    principal = Principal('a', frozenset(), True, False)
    context = await engine.create_context(principal, tenant_id=None, profile='generic-v1')
    text = (
        'search_name="ESCU - Detect Password Spray" '
        'failed_user=""AB.TESTUSER"", failed_user=""LAB-ISE$"", '
        'risk_message="source sprayed AB.TESTUSER and XY.ANALYST"'
    )
    protected = await engine.encode(
        principal, context_id=context['context_id'], fmt='text', payload=text, registrations=[],
    )
    blob = protected['payload']
    assert 'AB.TESTUSER' not in blob
    assert 'XY.ANALYST' not in blob
    assert 'LAB-ISE$' not in blob
    assert 'USER_' in blob


@pytest.mark.asyncio
async def test_bare_user_does_not_splice_windows_principal():
    engine = PrivacyEngine(
        crypto=Crypto(os.urandom(32)),
        store=MemoryBlobStore(),
        policies=PolicyRegistry(ROOT / 'profiles'),
    )
    principal = Principal('a', frozenset(), True, False)
    context = await engine.create_context(principal, tenant_id=None, profile='generic-v1')
    payload = {
        'tried_accounts': 'alice\nsvc.lab',
        'user': 'CORP\\alice',
        '_raw': 'user=CORP\\alice tried_accounts=alice',
        'file_name': 'beacon.exe',
        'severity': 'high',
    }
    protected = await engine.encode(
        principal, context_id=context['context_id'], fmt='json', payload=payload, registrations=[],
    )
    blob = json.dumps(protected['payload'])
    assert 'alice' not in blob.casefold() or 'CORP\\' not in blob
    assert 'CORP\\alice' not in protected['payload']['_raw']
    assert 'beacon.exe' not in blob
    assert protected['payload']['file_name'].startswith('PATH_')
    assert 'high' in blob
    # Must not leave a DOMAIN\<alias> principal shaped token for rediscovery.
    assert not re.search(r'CORP\\USER_[A-F0-9]{24,40}', blob)


def test_escaped_windows_principal_not_false_unc():
    detector = Detector(PolicyRegistry(ROOT / 'profiles').get('generic-v1'))
    # Splunk-style escaped principal glued in prose must be USER, not UNC PATH suffix.
    text = 'Account TEAM\\\\srv-backup$ failed interactively'
    found = detector.discover({
        '_raw': text,
        'registry_key_name': 'HOST_AAAAAAAAAAAAAAAABBBBBBBBBBBB\\Software',
        'registry_path': 'HKLM\\USER_AAAAAAAAAAAAAAAABBBBBBBBBBBB',
    })
    assert any(item.kind == 'USER' and 'TEAM' in item.value for item in found)
    assert not any(item.kind == 'PATH' and item.value.startswith('\\\\srv-backup') for item in found)
    assert not any(item.kind == 'USER' and item.value.startswith('HOST_') for item in found)
    assert not any(item.kind == 'USER' and item.value.upper().startswith('HKLM') for item in found)


@pytest.mark.asyncio
async def test_filename_path_replace_is_case_insensitive():
    engine = PrivacyEngine(
        crypto=Crypto(os.urandom(32)),
        store=MemoryBlobStore(),
        policies=PolicyRegistry(ROOT / 'profiles'),
    )
    principal = Principal('a', frozenset(), True, False)
    context = await engine.create_context(principal, tenant_id=None, profile='generic-v1')
    payload = {
        'file_name': 'Payload.PS1',
        '_raw': 'file_name=\"payload.ps1\" Image=C:\\\\Temp\\\\payload.ps1',
        'severity': 'low',
    }
    protected = await engine.encode(
        principal, context_id=context['context_id'], fmt='json', payload=payload, registrations=[],
    )
    blob = json.dumps(protected['payload']).casefold()
    assert 'payload.ps1' not in blob
    assert protected['payload']['file_name'].startswith('PATH_')


@pytest.mark.asyncio
async def test_registry_alias_artifact_does_not_fail_encode():
    engine = PrivacyEngine(
        crypto=Crypto(os.urandom(32)),
        store=MemoryBlobStore(),
        policies=PolicyRegistry(ROOT / 'profiles'),
    )
    principal = Principal('a', frozenset(), True, False)
    context = await engine.create_context(principal, tenant_id=None, profile='generic-v1')
    payload = {
        'dest': 'ws-lab-01',
        'entity_type': 'system',
        'registry_key_name': 'ws-lab-01\\Software\\Demo',
        'orig_rule_description': 'Registry change on ws-lab-01\\Software\\Demo by CORP\\\\svc.lab',
        '_raw': 'dest=ws-lab-01 registry_key_name=ws-lab-01\\Software\\Demo user=CORP\\\\svc.lab',
        'severity': 'medium',
    }
    protected = await engine.encode(
        principal, context_id=context['context_id'], fmt='json', payload=payload, registrations=[],
    )
    blob = json.dumps(protected['payload'])
    assert 'ws-lab-01' not in blob
    assert 'svc.lab' not in blob
    assert protected['payload']['severity'] == 'medium'


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
async def test_canonical_token_stability_within_tenant_includes_credentials():
    engine=PrivacyEngine(crypto=Crypto(os.urandom(32)),store=MemoryBlobStore(),policies=PolicyRegistry(ROOT/'profiles'))
    principal=Principal('a',frozenset({'corp'}),True,False)
    first=await engine.create_context(principal,tenant_id='corp',profile='generic-v1')
    second=await engine.create_context(principal,tenant_id='corp',profile='generic-v1')
    original={'hostname':'DC01.CORP.INTERNAL','password':'synthetic-test-password'}
    a=await engine.encode(principal,context_id=first['context_id'],fmt='json',payload=original,registrations=[])
    b=await engine.encode(principal,context_id=second['context_id'],fmt='json',payload=original,registrations=[])
    assert a['payload']['hostname']==b['payload']['hostname']
    assert a['payload']['password']==b['payload']['password']


@pytest.mark.asyncio
async def test_alias_registry_is_source_of_truth():
    store=MemoryBlobStore()
    engine=PrivacyEngine(crypto=Crypto(os.urandom(32)),store=store,policies=PolicyRegistry(ROOT/'profiles'))
    principal=Principal('a',frozenset({'corp'}),True,False)
    first=await engine.create_context(principal,tenant_id='corp',profile='generic-v1')
    payload={'src_ip':'10.20.3.7','password':'SyntheticSecretForDemo'}
    encoded=await engine.encode(principal,context_id=first['context_id'],fmt='json',payload=payload,registrations=[])
    registry_keys=[key for key in store._items if key.startswith('dlp:v1:nsalias:')]
    assert len(registry_keys) >= 2
    for key in registry_keys:
        await store.delete(key)
    second=await engine.create_context(principal,tenant_id='corp',profile='generic-v1')
    again=await engine.encode(principal,context_id=second['context_id'],fmt='json',payload=payload,registrations=[])
    assert again['payload']['src_ip'] != encoded['payload']['src_ip']
    assert again['payload']['password'] != encoded['payload']['password']


@pytest.mark.asyncio
async def test_windows_principal_json_escape_shares_registry_alias():
    engine=PrivacyEngine(crypto=Crypto(os.urandom(32)),store=MemoryBlobStore(),policies=PolicyRegistry(ROOT/'profiles'))
    principal=Principal('a',frozenset({'corp'}),True,False)
    ctx=await engine.create_context(principal,tenant_id='corp',profile='agentic-soc-v1')
    inner={'user':'CORP\\alice','hostname':'dc01.corp.example','description':'Windows Registry Change'}
    messages=[{'role':'user','content':json.dumps(inner)}]
    encoded=await engine.encode(principal,context_id=ctx['context_id'],fmt='messages',payload=messages,registrations=[])
    assert 'CORP\\\\alice' not in encoded['payload'][0]['content']
    restored=await engine.decode(principal,context_id=ctx['context_id'],fmt='messages',payload=encoded['payload'])
    assert json.loads(restored['payload'][0]['content'])==inner


@pytest.mark.asyncio
async def test_tenantless_aliases_remain_context_isolated():
    engine=PrivacyEngine(crypto=Crypto(os.urandom(32)),store=MemoryBlobStore(),policies=PolicyRegistry(ROOT/'profiles'))
    principal=Principal('a',frozenset(),True,False)
    first=await engine.create_context(principal,tenant_id=None,profile='generic-v1')
    second=await engine.create_context(principal,tenant_id=None,profile='generic-v1')
    payload={'hostname':'dc01.corp.example','password':'synthetic-test-password'}
    a=await engine.encode(principal,context_id=first['context_id'],fmt='json',payload=payload,registrations=[])
    b=await engine.encode(principal,context_id=second['context_id'],fmt='json',payload=payload,registrations=[])
    assert a['payload']['hostname']!=b['payload']['hostname']
    assert a['payload']['password']!=b['payload']['password']


@pytest.mark.asyncio
async def test_large_splunk_like_text_encode_throughput():
    """Regression: multi-MB notable CSV must finish in one encode without multi-minute stalls."""
    import time

    engine = PrivacyEngine(
        crypto=Crypto(os.urandom(32)),
        store=MemoryBlobStore(),
        policies=PolicyRegistry(ROOT / 'profiles'),
        max_entries=50_000,
    )
    principal = Principal('a', frozenset(), True, False)
    context = await engine.create_context(principal, tenant_id=None, profile='generic-v1')
    users = [f'U{i:04d}.SYNTHUSER' for i in range(400)]
    machines = [f'LAB-HOST-{i:03d}$' for i in range(50)]
    lines = []
    # ~1.2–2 MiB of dense Splunk-like free text (synthetic only).
    while sum(len(line) for line in lines) < 1_200_000:
        for user in users:
            machine = machines[len(lines) % len(machines)]
            lines.append(
                f'failed_user=""{user}"", dest=""ws-lab-01"", '
                f'src=""::FFFF:10.20.30.{len(lines) % 200}"", '
                f'service=""{machine}"", risk_message="spray against {user}"\n'
            )
    payload = ''.join(lines)
    assert len(payload.encode('utf-8')) >= 1_000_000
    started = time.perf_counter()
    protected = await engine.encode(
        principal,
        context_id=context['context_id'],
        fmt='text',
        payload=payload,
        registrations=[],
    )
    elapsed = time.perf_counter() - started
    blob = protected['payload']
    for sample_user in users[:20]:
        assert sample_user not in blob
    for sample_machine in machines[:10]:
        assert sample_machine not in blob
    assert 'USER_' in blob
    # Old 128 KiB × per-identity replace was multi-minute; one-shot must stay interactive.
    assert elapsed < 12.0, f'large text encode too slow: {elapsed:.2f}s'
