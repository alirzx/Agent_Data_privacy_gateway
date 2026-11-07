#!/usr/bin/env python3
"""Provision LAN/VPN HTTPS UI access without storing cleartext passwords."""
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
        description="Prepare an optional HTTPS and Basic Auth entrypoint for the isolated test UI."
    )
    parser.add_argument("--bind-ip", required=True, help="Private IPv4 address assigned to this server")
    parser.add_argument("--user", default="dlp-tester", help="Basic-auth username")
    args = parser.parse_args()

    address = ipaddress.ip_address(args.bind_ip)
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
        parser.error("Bind IP must be a server-owned private, non-loopback IPv4 address")
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,32}", args.user):
        parser.error("Username must be 3-32 characters using letters, digits, - or _")
    if TARGET.exists() or TARGET.is_symlink():
        raise SystemExit(".env.ui-lan already exists; refusing to overwrite")

    password = getpass.getpass("Choose a separate UI network-access password (>=16 chars): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation or len(password) < 16 or any(ch in password for ch in "\r\n"):
        raise SystemExit("Password confirmation mismatch or insufficient password length")
    del confirmation

    # Caddy reads the password from stdin; it never appears in process args,
    # the shell history, a Compose file, or the output of this script.
    result = subprocess.run(
        ["docker", "run", "--rm", "-i", "--entrypoint", "caddy",
         "caddy:2.10-alpine", "hash-password", "--algorithm", "bcrypt"],
        input=password + "\n", text=True, capture_output=True, check=True, timeout=90,
    )
    del password
    hashed = result.stdout.strip()
    if not hashed.startswith(("$2a$", "$2b$", "$2y$")) or "\n" in hashed or "'" in hashed:
        raise SystemExit("Unexpected Caddy bcrypt hash output; no file written")

    content = (
        "# Test UI LAN/VPN access only. Do not commit.\n"
        f"DLP_UI_LAN_BIND_IP={address}\n"
        f"DLP_UI_ACCESS_USER={args.user}\n"
        f"DLP_UI_ACCESS_HASH='{hashed}'\n"
    )
    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(content)
    print(f"PASS: Private-interface HTTPS UI configuration created for {address}:18485")
    print("No plaintext password displayed or stored.")


if __name__ == "__main__":
    main()
