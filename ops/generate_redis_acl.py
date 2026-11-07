#!/usr/bin/env python3
"""Generate a Redis ACL from a password file without revealing the credential."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite an existing ACL")
    secret = args.password_file.read_text(encoding="utf-8").strip()
    if len(secret) < 32:
        parser.error("Password file requires at least 32 characters")
    digest = hashlib.sha256(secret.encode()).hexdigest()
    content = (
        "user default off\n"
        f"user dlp on #{digest} ~* +get +mget +set +del +ping +watch +unwatch +multi +exec +discard +client +select\n"
    )
    args.output.write_text(content, encoding="utf-8")
    args.output.chmod(0o600)
    print("PASS: Redis ACL generated without printing its secret")


if __name__ == "__main__":
    main()
