from __future__ import annotations

import copy
import hashlib
import json


def create(client, auth, *, tenant="tenant-1", profile="agentic-soc-v1"):
    response = client.post("/v1/contexts", headers=auth,
                           json={"tenant_id": tenant, "profile": profile})
    assert response.status_code == 201, response.text
    return response.json()["context_id"]


def encode(client, auth, context, payload, fmt="json"):
    response = client.post("/v1/encode", headers=auth, json={
        "context_id": context, "format": fmt, "payload": payload
    })
    assert response.status_code == 200, response.text
    return response.json()


def decode(client, auth, context, payload, fmt="json"):
    response = client.post("/v1/decode", headers=auth, json={
        "context_id": context, "format": fmt, "payload": payload
    })
    assert response.status_code == 200, response.text
    return response.json()


def test_auth_required(client):
    assert client.post("/v1/encode", json={"payload": "abc", "format": "text"}).status_code == 401
    assert client.get("/v1/policies").status_code == 401
    assert client.get("/health").status_code == 200


def test_basic_roundtrip_and_semantics(client, auth):
    ctx = create(client, auth)
    original = {
        "src_ip": "10.20.3.7", "hostname": "dc01.corp.example", "user": "CORP\\svc-maint",
        "description": "CORP\\svc-maint authenticated to dc01.corp.example from 10.20.3.7; src: SIEM; Windows Registry Change",
        "mitre_techniques": ["T1112", "T1078"], "severity": "high", "risk_score": 82,
    }
    saved = copy.deepcopy(original)
    safe = encode(client, auth, ctx, original)["payload"]
    assert original == saved
    assert safe["src_ip"].startswith("IP_V4_PRIVATE_")
    assert safe["hostname"].startswith("HOST_")
    assert safe["user"].startswith("USER_")
    assert safe["hostname"] in safe["description"]
    assert safe["src_ip"] in safe["description"]
    assert safe["user"] in safe["description"]
    assert "src: SIEM" in safe["description"]
    assert "Registry Change" in safe["description"]
    assert safe["mitre_techniques"] == original["mitre_techniques"]
    assert decode(client, auth, ctx, safe)["payload"] == original


def test_nested_json_and_opaque_source(client, auth):
    ctx = create(client, auth)
    source = {"src_endpoint": {"ip": "B_309", "name": "ws-01.corp.example"},
              "src_ip": "B_309", "risk_score": 21.0, "category": "Password Spray"}
    encoded = encode(client, auth, ctx, source)["payload"]
    assert encoded["src_ip"].startswith("IP_OPAQUE_")
    assert encoded["src_endpoint"]["ip"] == encoded["src_ip"]
    assert encoded["risk_score"] == source["risk_score"]
    assert decode(client, auth, ctx, encoded)["payload"] == source


def test_host_stopwords_not_over_tokenized(client, auth):
    ctx = create(client, auth)
    text = 'Windows Registry Change; src: SIEM; host dc01.corp.example changed'
    encoded = encode(client, auth, ctx, text, 'text')["payload"]
    assert 'Windows Registry Change' in encoded
    assert 'src: SIEM' in encoded
    assert 'dc01.corp.example' not in encoded


def test_secret_default_non_disclosing(client, auth):
    ctx = create(client, auth)
    value = {"password": "syntheticP@ssw0rd!", "api_key": "fake-api-key-for-test", "user": "alice"}
    protected = encode(client, auth, ctx, value)["payload"]
    assert protected["password"].startswith("CRED_PASSWORD_")
    assert protected["api_key"].startswith("CRED_API_KEY_")
    assert "syntheticP@ssw0rd!" not in json.dumps(protected)
    restored = decode(client, auth, ctx, protected)["payload"]
    assert restored["user"] == 'alice'
    assert restored['password'] == '[PROTECTED_CREDENTIAL]'
    assert restored['api_key'] == '[PROTECTED_CREDENTIAL]'
    forbidden = client.post('/v1/decode',headers=auth,json={"context_id":ctx,"format":"json","payload":protected,
                                                      "reveal_credentials":True,"purpose":"credential-recovery"})
    assert forbidden.status_code == 403


def test_secret_authorized_recovery_scoped_by_owner(client):
    admin = {'Authorization':'Bearer test-recovery-key'}
    ctx = create(client, admin)
    val = {"password":"syntheticPasswordOnly"}
    protected = encode(client,admin,ctx,val)['payload']
    denied = client.post('/v1/decode',headers=admin,json={'context_id':ctx,'format':'json','payload':protected,
                                                         'purpose':'llm-response','reveal_credentials':True})
    assert denied.status_code == 403
    allowed = client.post('/v1/decode',headers=admin,json={'context_id':ctx,'format':'json','payload':protected,
                                                          'purpose':'credential-recovery','reveal_credentials':True})
    assert allowed.status_code == 200
    assert allowed.json()['payload'] == val


def test_tenantless_context_is_unique(client, auth):
    ctx_a, ctx_b = create(client,auth,tenant=None), create(client,auth,tenant=None)
    a = encode(client,auth,ctx_a,{'hostname':'host123.corp.example'})['payload']['hostname']
    b = encode(client,auth,ctx_b,{'hostname':'host123.corp.example'})['payload']['hostname']
    assert a != b
    assert decode(client,auth,ctx_b,{'hostname':a})['stats']['unknown_aliases'] == 1


def test_deterministic_tenant_aliases_and_cross_tenant_isolation(client, auth):
    first, second = create(client,auth), create(client,auth)
    token1=encode(client,auth,first,{'src_ip':'10.0.0.5'})['payload']['src_ip']
    token2=encode(client,auth,second,{'src_ip':'10.0.0.5'})['payload']['src_ip']
    assert token1 == token2
    # Equal aliases are not equivalent to an authorization to restore them.
    assert decode(client,auth,second,{'other':token1})['stats']['rehydrated'] == 1
    # Second context registered its own original; it is allowed to resolve its own alias.
    ctx_other=create(client,{'Authorization':'Bearer test-soc-key'},tenant='tenant-2')
    third=encode(client,{'Authorization':'Bearer test-soc-key'},ctx_other,{'src_ip':'10.0.0.5'})['payload']['src_ip']
    assert third != token1
    denied=client.get(f'/v1/contexts/{ctx_other}',headers=auth)
    assert denied.status_code==403


def test_context_owner_not_tenant_field_is_authoritative(client, auth):
    ctx=create(client,auth)
    other={'Authorization':'Bearer test-soc-key'}
    assert client.get(f'/v1/contexts/{ctx}',headers=other).status_code==403
    assert client.post('/v1/contexts',headers=auth,json={'tenant_id':'tenant-2'}).status_code==403
    assert client.post('/v1/contexts',headers=other,json={'tenant_id':None}).status_code==403


def test_unknown_alias_and_mutated_alias_not_restored(client, auth):
    ctx=create(client,auth)
    alias=encode(client,auth,ctx,{'hostname':'dc01.corp.example'})['payload']['hostname']
    unknown='HOST_'+'F'*32
    out=decode(client,auth,ctx,{'a':unknown,'b':alias+'FFF'})['payload']
    assert out['a']==unknown
    assert out['b']==alias+'FFF'


def test_context_delete(client, auth):
    ctx=create(client,auth)
    assert client.delete(f'/v1/contexts/{ctx}',headers=auth).status_code==204
    assert client.post('/v1/encode',headers=auth,json={'context_id':ctx,'format':'text','payload':'hello'}).status_code==400


def test_classify_no_raw_values(client, auth):
    response=client.post('/v1/classify',headers=auth,json={'profile':'generic-v1','format':'json',
                   'payload':{'src_ip':'10.20.3.7','user':'CORP\\alice','password':'fake-secret'}})
    assert response.status_code==200
    result=response.json()
    assert result['counts']['IP'] >= 1
    assert result['counts']['USER'] >= 1
    assert result['counts']['CRED_PASSWORD'] >= 1
    assert '10.20.3.7' not in response.text
    assert 'fake-secret' not in response.text


def test_messages_format(client, auth):
    ctx=create(client,auth)
    messages=[{'role':'system','content':'You are a SOC assistant.'},
              {'role':'user','content':'Investigate host dc01.corp.example from 10.20.3.7'}]
    protected=encode(client,auth,ctx,messages,fmt='messages')['payload']
    assert protected[0]==messages[0]
    assert 'HOST_' in protected[1]['content']
    assert decode(client,auth,ctx,protected,fmt='messages')['payload']==messages


def test_invalid_input_and_limits(client,auth,settings):
    ctx=create(client,auth)
    assert client.post('/v1/encode',headers=auth,json={'context_id':ctx,'format':'messages','payload':['wrong']}).status_code==400
    assert client.post('/v1/encode',headers=auth,json={'context_id':ctx,'format':'text','payload':12}).status_code==400
    assert client.post('/v1/encode',headers=auth,json={'context_id':ctx,'format':'json','payload':{'x':'z'*1_050_000}}).status_code==413
    assert client.post('/v1/contexts',headers=auth,json={'profile':'does-not-exist','tenant_id':'tenant-1'}).status_code==400


def test_encrypted_storage_never_contains_identity(client,auth):
    ctx=create(client,auth)
    encode(client,auth,ctx,{'hostname':'very-sensitive-host.corp.example','password':'test-synthetic-secret'})
    import asyncio
    from app.core.engine import PrivacyEngine
    store=client.app.state.store
    raw=asyncio.run(store.get(PrivacyEngine._key(ctx)))
    assert b'very-sensitive-host.corp.example' not in raw
    assert b'test-synthetic-secret' not in raw
    assert b'HOST_' not in raw


def test_json_serialized_inside_message_has_valid_escaped_rehydration(client,auth):
    ctx=create(client,auth)
    inner={'user':'CORP\\alice','hostname':'dc01.corp.example','description':'Windows Registry Change'}
    messages=[{'role':'user','content':json.dumps(inner)}]
    encoded=encode(client,auth,ctx,messages,'messages')['payload']
    assert 'CORP\\\\alice' not in encoded[0]['content']
    assert 'USER_' in encoded[0]['content']
    assert 'Windows Registry Change' in encoded[0]['content']
    restored=decode(client,auth,ctx,encoded,'messages')['payload']
    assert json.loads(restored[0]['content'])==inner


def test_quoted_credentials_with_commas_and_spaces(client,auth):
    ctx=create(client,auth)
    source='Authorization: Bearer abc123456789xyz password="complex, secret with spaces"'
    protected=encode(client,auth,ctx,source,'text')['payload']
    assert 'abc123456789xyz' not in protected
    assert 'complex, secret with spaces' not in protected
    assert 'CRED_' in protected
    assert '[PROTECTED_CREDENTIAL]' in decode(client,auth,ctx,protected,'text')['payload']


def test_extended_soc_noc_identity_categories(client,auth):
    ctx=create(client,auth)
    payload={'mac_address':'AA:BB:CC:DD:EE:FF','network_cidr':'10.20.0.0/24',
             'device_serial':'SER-ACME-1002','cloud_resource_id':'arn:aws:ec2:us-east-1:123456789012:instance/i-abcdef',
             'snmp_community':'testing-community-only','employee_id':'emp_208','user_sid':'S-1-5-21-1000',
             'organization_id':'private-org-42','splunk_index':'customer_index',
             'phone_number':'+32 02 000 0000'}
    safe=encode(client,auth,ctx,payload)['payload']
    assert safe['device_serial'].startswith('DEVICE_SERIAL_')
    assert safe['cloud_resource_id'].startswith('CLOUD_RESOURCE_')
    assert safe['snmp_community'].startswith('CRED_SNMP_COMMUNITY_')
    assert safe['phone_number'].startswith('PHONE_')
    assert safe['network_cidr'].startswith('SUBNET_')
    back=decode(client,auth,ctx,safe)['payload']
    for key in payload:
        if key == 'snmp_community':
            assert back[key]=='[PROTECTED_CREDENTIAL]'
        else:
            assert back[key]==payload[key]


def test_profile_and_tenant_context_mismatch_fail_closed(client,auth):
    ctx=create(client,auth,profile='agentic-soc-v1')
    body={'context_id':ctx,'format':'json','payload':{'src_ip':'10.0.0.5'}}
    assert client.post('/v1/encode',headers=auth,json={**body,'profile':'generic-v1'}).status_code==400
    assert client.post('/v1/encode',headers=auth,json={**body,'tenant_id':'tenant-other'}).status_code==400
    assert client.post('/v1/encode',headers=auth,json=body).status_code==200
