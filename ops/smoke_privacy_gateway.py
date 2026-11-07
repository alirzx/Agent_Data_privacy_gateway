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

    context_id = None
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

        code, secret_encoded = call("/v1/encode", "POST", {
            "context_id": context_id, "format": "json", "purpose": "llm-egress",
            "payload": {"api_key": "SYNTHETIC_EXAMPLE_KEY_NOT_REAL"}
        })
        expect("Credential encode", code, 200)
        if "SYNTHETIC_EXAMPLE_KEY_NOT_REAL" in json.dumps(secret_encoded["payload"]):
            raise AssertionError("Secret was not protected")
        print("PASS: Credential removed from egress payload")

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
        if context_id:
            code, _ = call("/v1/contexts/" + context_id, "DELETE")
            expect("Context deleted", code, 204)

    print("PASS: Production synthetic Splunk smoke test completed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
