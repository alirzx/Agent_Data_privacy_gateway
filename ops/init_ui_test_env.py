#!/usr/bin/env python3
"""Provision a separate loopback-only demo UI; never reuse production credentials."""
from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".env.ui-test"

if TARGET.exists() or TARGET.is_symlink():
    raise SystemExit("UI test environment already exists; refusing to overwrite")

values = {
    "DLP_MASTER_KEY_B64": base64.b64encode(os.urandom(32)).decode("ascii"),
    "DLP_DEMO_API_KEY": secrets.token_urlsafe(48),
    "DLP_CLIENTS_JSON": "[]",
    "DLP_DEV_MODE": "true",
    "DLP_UI_ENABLED": "true",
    "DLP_STORE_BACKEND": "memory",
    "DLP_CONTEXT_TTL": "3600",
    "DLP_MAX_CONTEXT_TTL": "86400",
    "DLP_MAX_PAYLOAD_BYTES": "67108864",
    "DLP_MAX_ENTRIES": "1000000",
}

fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    output.write("# Generated test-only secrets; do not commit or expose publicly.\n")
    for name, value in values.items():
        output.write(f"{name}={value}\n")
print("PASS: Created isolated .env.ui-test (mode 0600); no secrets displayed.")
