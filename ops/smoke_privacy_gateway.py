#!/usr/bin/env python3
"""Synthetic Splunk-like production Gateway smoke test; no real SOC data or secrets printed."""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

BASE = "https://privacy-gateway:8443"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True, type=Path)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--tenant-id", required=True)
    args = parser.parse_args()

    tenant = str(uuid.UUID(args.tenant_id))
    if tenant != args.tenant_id:
        raise ValueError("Tenant ID must be a canonical UUID")
    token = args.token_file.read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("Empty service token")

    # Do not route private Docker DNS via an inherited HTTP(S) proxy.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(args.ca))),
    )

    def call(path: str, method: str = "GET", payload=None, auth: str = "valid"):
        headers = {}
        if auth != "missing":
            credential = token if auth == "valid" else "definitely-invalid-synthetic-key"
            headers["Authorization"] = "Bearer " + credential
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
        try:
            with opener.open(request, timeout=20) as response:
                data = response.read()
                return response.status, json.loads(data) if data else None
        except urllib.error.HTTPError as exc:
            exc.close()
            return exc.code, None  # Never print response bodies or secrets.

    def expect(name: str, actual, wanted) -> None:
        if actual != wanted:
            raise AssertionError(f"{name}: expected {wanted!r}, got {actual!r}")
        print(f"PASS: {name}")

    # The dedicated Gateway CA must be required; default system trust must
    # reject this private-CA HTTPS endpoint in our test-only Python image.
    untrusted = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        untrusted.open(BASE + "/health", timeout=10).close()
    except urllib.error.URLError as exc:
        if not isinstance(exc.reason, ssl.SSLCertVerificationError):
            raise AssertionError("Unexpected TLS failure category") from None
    else:
        raise AssertionError("Private Gateway certificate was accepted without its dedicated CA")
    print("PASS: Unknown Gateway CA rejected")

    expect("HTTPS /health", call("/health")[0], 200)
    ready_code, ready = call("/ready")
    expect("Redis /ready", (ready_code, ready.get("store") if ready else None), (200, "redis"))
    expect("Missing bearer denied", call("/v1/policies", auth="missing")[0], 401)
    expect("Invalid bearer denied", call("/v1/policies", auth="invalid")[0], 401)
    code, policies = call("/v1/policies")
    expect("Authenticated policies", code, 200)
    if "agentic-soc-v1" not in {p["name"] for p in policies["policies"]}:
        raise AssertionError("agentic-soc-v1 policy missing")
    print("PASS: agentic-soc-v1 policy available")

    unauthorized_tenant = str(uuid.uuid4())
    expect(
        "Unauthorized tenant denied",
        call("/v1/contexts", "POST", {
            "tenant_id": unauthorized_tenant, "profile": "agentic-soc-v1"
        })[0],
        403,
    )
    expect(
        "Tenantless request denied",
        call("/v1/contexts", "POST", {"profile": "agentic-soc-v1"})[0],
        403,
    )

    mock = {
        "index": "synthetic_notable",
        "sourcetype": "stash",
        "search_name": "Synthetic Password Spray",
        "src_ip": "10.20.3.7",
        "dest_ip": "10.20.3.21",
        "user": "EXAMPLE\\analyst",
        "host": "dc01.corp.example",
        "risk_score": 72,
        "mitre_techniques": ["T1110.003"],
        "description": "EXAMPLE\\analyst failed to log in from 10.20.3.7 to dc01.corp.example",
    }

    code, detected = call("/v1/classify", "POST", {
        "profile": "agentic-soc-v1", "format": "json", "payload": mock
    })
    expect("Classify request", code, 200)
    if detected["total_detected"] <= 0 or detected["includes_original_values"] is not False:
        raise AssertionError("Classification returned no findings or exposed originals")
    print("PASS: Classification found sensitive fields (counts only)")

    expect("Unknown profile denied", call("/v1/contexts", "POST", {
        "tenant_id": tenant, "profile": "nonexistent-synthetic"
    })[0], 400)

    context_id = None
    secondary_context_id = None
    try:
        code, context = call("/v1/contexts", "POST", {
            "tenant_id": tenant, "profile": "agentic-soc-v1"
        })
        expect("Authorized context creation", code, 201)
        context_id = context["context_id"]
        expect("Context metadata read", call("/v1/contexts/" + context_id)[0], 200)

        code, encoded = call("/v1/encode", "POST", {
            "context_id": context_id, "format": "json",
            "purpose": "llm-egress", "payload": mock
        })
        expect("Encode mock notable", code, 200)
        protected = encoded["payload"]
        expect("Context profile mismatch rejected", call("/v1/encode", "POST", {
            "context_id": context_id, "profile": "generic-v1",
            "format": "json", "payload": mock
        })[0], 400)
        expect("Context tenant mismatch rejected", call("/v1/encode", "POST", {
            "context_id": context_id, "tenant_id": unauthorized_tenant,
            "format": "json", "payload": mock
        })[0], 400)
        if protected == mock or protected.get("src_ip") == mock["src_ip"]:
            raise AssertionError("Expected synthetic identity was not protected")
        print("PASS: Splunk identities were tokenized")

        code, decoded = call("/v1/decode", "POST", {
            "context_id": context_id, "format": "json",
            "purpose": "llm-response", "payload": protected,
            "reveal_credentials": False
        })
        expect("Decode mock notable", code, 200)
        expect("Non-credential round-trip", decoded["payload"], mock)

        alias = protected["src_ip"]
        if not isinstance(alias, str) or len(alias) < 2 or alias[-1] not in "0123456789ABCDEF":
            raise AssertionError("Expected hexadecimal source IP alias")
        mutated = alias[:-1] + ("0" if alias[-1] != "0" else "1")
        code, unknown = call("/v1/decode", "POST", {
            "context_id": context_id, "format": "json", "payload": {"src_ip": mutated}
        })
        expect("Unknown alias decoding request", code, 200)
        if unknown["payload"]["src_ip"] != mutated or unknown["stats"]["unknown_aliases"] != 1:
            raise AssertionError("Unknown alias unexpectedly restored")
        print("PASS: Unknown alias never restored")

        messages = [
            {"role": "system", "content": "Analyze the synthetic SOC alert."},
            {"role": "user", "content": "Investigate host dc01.corp.example and 10.20.3.7"},
        ]
        code, protected_messages = call("/v1/encode", "POST", {
            "context_id": context_id, "format": "messages", "purpose": "llm-egress",
            "payload": messages
        })
        expect("LLM messages encode", code, 200)
        serialized = json.dumps(protected_messages["payload"])
        if "dc01.corp.example" in serialized or "10.20.3.7" in serialized:
            raise AssertionError("Identity leaked in encoded messages")
        code, restored_messages = call("/v1/decode", "POST", {
            "context_id": context_id, "format": "messages", "purpose": "llm-response",
            "payload": protected_messages["payload"]
        })
        expect("LLM messages decode", code, 200)
        expect("Messages round-trip", restored_messages["payload"], messages)

        code, second = call("/v1/contexts", "POST", {
            "tenant_id": tenant, "profile": "agentic-soc-v1"
        })
        expect("Same-tenant second context created", code, 201)
        secondary_context_id = second["context_id"]
        code, same_identity = call("/v1/encode", "POST", {
            "context_id": secondary_context_id, "format": "json",
            "purpose": "llm-egress", "payload": {"src_ip": mock["src_ip"]}
        })
        expect("Same-tenant second context encoded", code, 200)
        expect("Stable tenant alias across contexts", same_identity["payload"]["src_ip"], alias)

        code, secret_encoded = call("/v1/encode", "POST", {
            "context_id": context_id, "format": "json", "purpose": "llm-egress",
            "payload": {"api_key": "SYNTHETIC_EXAMPLE_KEY_NOT_REAL"}
        })
        expect("Credential encode", code, 200)
        if "SYNTHETIC_EXAMPLE_KEY_NOT_REAL" in json.dumps(secret_encoded["payload"]):
            raise AssertionError("Secret was not protected")
        print("PASS: Credential removed from egress payload")

        code, restricted = call("/v1/decode", "POST", {
            "context_id": context_id, "format": "json", "purpose": "llm-response",
            "payload": secret_encoded["payload"], "reveal_credentials": False
        })
        expect("Credential non-reveal decode", code, 200)
        expect("Credential remains protected", restricted["payload"]["api_key"], "[PROTECTED_CREDENTIAL]")

        expect("Credential reveal denied", call("/v1/decode", "POST", {
            "context_id": context_id, "format": "json",
            "purpose": "credential-recovery",
            "payload": secret_encoded["payload"],
            "reveal_credentials": True
        })[0], 403)

        expect("Invalid payload format denied", call("/v1/classify", "POST", {
            "profile": "agentic-soc-v1", "format": "text",
            "payload": {"not": "text"}
        })[0], 400)

    finally:
        if secondary_context_id:
            code, _ = call("/v1/contexts/" + secondary_context_id, "DELETE")
            expect("Secondary context deleted", code, 204)
        if context_id:
            code, _ = call("/v1/contexts/" + context_id, "DELETE")
            expect("Context deleted", code, 204)
            expect("Deleted context cannot be read", call("/v1/contexts/" + context_id)[0], 400)

    print("PASS: Extended production synthetic Splunk smoke test completed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
