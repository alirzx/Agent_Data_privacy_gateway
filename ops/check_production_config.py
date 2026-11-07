#!/usr/bin/env python3
"""Fail-closed validation of server-55 secrets and certificate files, without disclosing values."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

REQUIRED_FILES = (
    "DLP_TLS_CERT_HOST_PATH", "DLP_TLS_KEY_HOST_PATH", "DLP_TLS_CA_HOST_PATH",
    "DLP_REDIS_TLS_CERT_HOST_PATH", "DLP_REDIS_TLS_KEY_HOST_PATH",
    "DLP_REDIS_CA_HOST_PATH", "DLP_REDIS_ACL_HOST_PATH",
    "DLP_REDIS_PASSWORD_HOST_PATH",
)


def read_dotenv(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", key):
            raise ValueError("Invalid environment file syntax")
        value = value.strip()
        if value.startswith(("'", '"')) and value.endswith(value[0]):
            value = value[1:-1]
        result[key] = value
    return result


def require_file(settings: dict[str, str], key: str) -> Path:
    raw = settings.get(key, "")
    if not raw:
        raise ValueError(f"Missing setting: {key}")
    path = Path(raw)
    if not path.is_absolute() or not path.is_file():
        raise ValueError(f"{key} must reference an existing absolute file")
    if path.stat().st_size == 0:
        raise ValueError(f"Empty file for: {key}")
    return path


def run_openssl(*args: str) -> bytes:
    completed = subprocess.run(
        ["openssl", *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False, timeout=8,
    )
    if completed.returncode:
        raise ValueError("TLS certificate verification failed")
    return completed.stdout.strip()


def check_cert(cert: Path, key: Path, ca: Path, hostname: str) -> None:
    run_openssl("x509", "-in", str(cert), "-noout", "-checkhost", hostname)
    run_openssl("x509", "-in", str(cert), "-noout", "-checkend", "86400")
    run_openssl("verify", "-CAfile", str(ca), str(cert))
    cert_pub = run_openssl("x509", "-in", str(cert), "-pubkey", "-noout")
    key_pub = run_openssl("pkey", "-in", str(key), "-pubout")
    if cert_pub != key_pub:
        raise ValueError("Certificate and private key do not match")


def validate(settings: dict[str, str]) -> None:
    if settings.get("DLP_DEV_MODE", "").lower() != "false":
        raise ValueError("DLP_DEV_MODE must be false")
    if settings.get("DLP_UI_ENABLED", "").lower() != "false":
        raise ValueError("DLP_UI_ENABLED must be false")
    if settings.get("DLP_DEMO_API_KEY", ""):
        raise ValueError("DLP_DEMO_API_KEY must be blank")
    if settings.get("DLP_STORE_BACKEND", "").lower() != "redis":
        raise ValueError("DLP_STORE_BACKEND must be redis")

    try:
        master = base64.b64decode(settings["DLP_MASTER_KEY_B64"], validate=True)
    except (KeyError, ValueError) as exc:
        raise ValueError("Invalid or missing DLP_MASTER_KEY_B64") from exc
    if len(master) != 32:
        raise ValueError("DLP_MASTER_KEY_B64 must decode to 32 bytes")

    try:
        clients = json.loads(settings["DLP_CLIENTS_JSON"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise ValueError("DLP_CLIENTS_JSON must be valid JSON") from exc
    if not isinstance(clients, list) or not clients:
        raise ValueError("DLP_CLIENTS_JSON requires authorized clients")
    seen: set[str] = set()
    for client in clients:
        if not isinstance(client, dict) or not isinstance(client.get("client_id"), str):
            raise ValueError("Invalid service client")
        if client["client_id"] in seen:
            raise ValueError("Duplicate client ID")
        seen.add(client["client_id"])
        if not re.fullmatch(r"[0-9a-fA-F]{64}", client.get("key_sha256", "")):
            raise ValueError("Missing/invalid client SHA-256 digest")
        tenants = client.get("tenants")
        if not isinstance(tenants, list) or not tenants:
            raise ValueError("Client needs restricted tenant UUIDs")
        if client.get("allow_tenantless") is not False or client.get("allow_secret_decode") is not False:
            raise ValueError("Client privileges too broad")
        for tenant in tenants:
            try:
                if str(uuid.UUID(tenant)) != tenant:
                    raise ValueError("Tenant UUID must be canonical")
            except (ValueError, TypeError) as exc:
                raise ValueError("Tenant must be a canonical UUID") from exc

    ttl = int(settings.get("DLP_CONTEXT_TTL", "3600"))
    max_ttl = int(settings.get("DLP_MAX_CONTEXT_TTL", "86400"))
    if not 60 <= ttl <= max_ttl <= 86400:
        raise ValueError("Invalid TTL limits")
    cap = int(settings.get("DLP_MAX_PAYLOAD_BYTES", "67108864"))
    if not 1024 <= cap <= 67108864:
        raise ValueError("Payload cap outside reviewed range")
    if not 1 <= int(settings.get("DLP_MAX_ENTRIES", "1000000")) <= 1000000:
        raise ValueError("DLP_MAX_ENTRIES outside reviewed range")

    files = {key: require_file(settings, key) for key in REQUIRED_FILES}
    host = settings.get("DLP_GATEWAY_DNS_NAME", "privacy-gateway")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", host):
        raise ValueError("Invalid DLP_GATEWAY_DNS_NAME")
    check_cert(files["DLP_TLS_CERT_HOST_PATH"], files["DLP_TLS_KEY_HOST_PATH"],
               files["DLP_TLS_CA_HOST_PATH"], host)
    check_cert(files["DLP_REDIS_TLS_CERT_HOST_PATH"], files["DLP_REDIS_TLS_KEY_HOST_PATH"],
               files["DLP_REDIS_CA_HOST_PATH"], "redis")

    url = settings.get("DLP_REDIS_URL", "")
    parts = urlsplit(url)
    if parts.scheme != "rediss" or parts.hostname != "redis" or parts.username != "dlp":
        raise ValueError("Redis URL must use authenticated rediss://")
    if parts.port != 6379 or parts.path not in ("/0", "/") or not parts.password:
        raise ValueError("Invalid Redis URL")
    query = parse_qs(parts.query)
    if query.get("ssl_cert_reqs") != ["required"]:
        raise ValueError("Redis TLS CA validation must be required")
    if query.get("ssl_check_hostname", [""])[0].lower() not in ("true", "1"):
        raise ValueError("Redis TLS hostname validation must be enabled")
    if query.get("ssl_ca_certs") != ["/run/secrets/redis-ca.pem"]:
        raise ValueError("Redis TLS CA path does not match mount")
    password = files["DLP_REDIS_PASSWORD_HOST_PATH"].read_text(encoding="utf-8").strip()
    if not password or unquote(parts.password) != password:
        raise ValueError("Redis URL password differs from healthcheck secret")
    acl = files["DLP_REDIS_ACL_HOST_PATH"].read_text(encoding="utf-8")
    digest = hashlib.sha256(password.encode()).hexdigest()
    if not re.search(r"(?m)^user default off\s*$", acl):
        raise ValueError("Redis default user must be disabled")
    if not any(line.startswith("user dlp on ") and f"#{digest}" in line for line in acl.splitlines()):
        raise ValueError("Redis ACL digest mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=Path(".env"))
    args = parser.parse_args()
    try:
        validate(read_dotenv(args.env))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("PASS: Gateway configuration, tenant ACL, Redis TLS and HTTPS certificates")
    print("NOTE: Docker runtime and SOC integration are not verified by this tool")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
