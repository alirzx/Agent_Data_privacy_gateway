#!/usr/bin/env python3
"""Provision LAN/VPN HTTPS demo UI with optional browser Basic Auth."""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".env.ui-lan"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare a private HTTPS demo UI, optionally with Basic Auth."
    )
    parser.add_argument("--bind-ip", required=True, help="Private IPv4 address assigned to this server")
    parser.add_argument("--port", default=8484, type=int, help="LAN HTTPS host port")
    parser.add_argument("--basic-auth", action="store_true", help="Require browser Basic Auth (default: disabled)")
    parser.add_argument("--user", default="dlp-tester", help="Basic Auth user, only with --basic-auth")
    args = parser.parse_args()

    address = ipaddress.ip_address(args.bind_ip)
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
        parser.error("Bind IP must be a server-owned private, non-loopback IPv4 address")
    if not 1024 <= args.port <= 65535:
        parser.error("LAN port must be 1024..65535")
    if args.basic_auth and not re.fullmatch(r"[A-Za-z0-9_-]{3,32}", args.user):
        parser.error("Username must be 3-32 characters using letters, digits, - or _")
    if TARGET.exists() or TARGET.is_symlink():
        raise SystemExit(".env.ui-lan already exists; refusing to overwrite")

    content = (
        "# Test-only LAN/VPN UI. Do not commit.\n"
        f"DLP_UI_LAN_BIND_IP={address}\n"
        f"DLP_UI_LAN_PORT={args.port}\n"
        f"DLP_UI_BASIC_AUTH_ENABLED={'true' if args.basic_auth else 'false'}\n"
    )

    if args.basic_auth:
        password = getpass.getpass("Choose separate UI password (>=16 chars): ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation or len(password) < 16 or any(ch in password for ch in "\r\n"):
            raise SystemExit("Password confirmation mismatch or insufficient password length")
        del confirmation
        # Hash using stdin; do not place the plaintext in process args.
        result = subprocess.run(
            ["docker", "run", "--rm", "-i", "--entrypoint", "caddy",
             "caddy:2.10-alpine", "hash-password", "--algorithm", "bcrypt"],
            input=password + "\n", text=True, capture_output=True, check=True, timeout=90,
        )
        del password
        hashed = result.stdout.strip()
        if not hashed.startswith(("$2a$", "$2b$", "$2y$")) or "\n" in hashed or "'" in hashed:
            raise SystemExit("Unexpected Caddy bcrypt hash output; no file written")
        content += f"DLP_UI_ACCESS_USER={args.user}\nDLP_UI_ACCESS_HASH='{hashed}'\n"

    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(content)
    print(f"PASS: Private-interface HTTPS UI configuration created for {address}:{args.port}")
    print("Browser Basic Auth:", "enabled" if args.basic_auth else "disabled")
    print("No-auth mode exposes the test-only /v1/dev/console token to LAN/VPN users.")
    print("No plaintext password displayed or stored.")


if __name__ == "__main__":
    main()
