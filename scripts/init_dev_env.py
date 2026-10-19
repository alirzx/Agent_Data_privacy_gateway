#!/usr/bin/env python3
"""Generate LOCAL-ONLY credentials; never commit .env or use them in production."""
from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".env"

if TARGET.exists():
    raise SystemExit(".env already exists. Refusing to overwrite keys, contexts or credentials.")
key = base64.b64encode(os.urandom(32)).decode()
api_key = secrets.token_urlsafe(36)
content = (
    "# Generated local-only configuration. Keep secret and never commit.\n"
    f"DLP_MASTER_KEY_B64={key}\n"
    f"DLP_DEMO_API_KEY={api_key}\n"
    "DLP_CLIENTS_JSON=[]\nDLP_DEV_MODE=true\nDLP_UI_ENABLED=true\n"
    "DLP_STORE_BACKEND=memory\nDLP_REDIS_URL=redis://localhost:6379/0\n"
    "DLP_CONTEXT_TTL=3600\nDLP_MAX_CONTEXT_TTL=86400\n"
)
fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write(content)
print("Generated .env with file permissions 0600 (local dev only).")
print(f"Local console API key: {api_key}")
print("Use only on localhost. Do not paste this key into logs, issues, or commits.")
