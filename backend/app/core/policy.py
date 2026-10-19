"""Versioned, allow-listed classification profiles. Profiles are operator controlled."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

SUPPORTED_KINDS = frozenset({
    "IP", "IP_OPAQUE", "HOST", "USER", "EMAIL", "ASSET", "MAC", "SUBNET", "DOMAIN",
    "PHONE", "EMPLOYEE_ID", "USER_SID", "ORG_ID", "AD_GROUP", "CLOUD_RESOURCE", "DEVICE_SERIAL", "SPLUNK_INDEX",
    "URL_INTERNAL", "PATH", "TICKET", "CASE", "REFERENCE", "CRED_PASSWORD", "CRED_PASSPHRASE",
    "CRED_API_KEY", "CRED_ACCESS_KEY", "CRED_SECRET_ACCESS_KEY", "CRED_ACCESS_TOKEN",
    "CRED_REFRESH_TOKEN", "CRED_SESSION_TOKEN", "CRED_BEARER", "CRED_AUTHORIZATION",
    "CRED_COOKIE", "CRED_PRIVATE_KEY", "CRED_CLIENT_SECRET", "CRED_JWT", "CRED_SNMP_COMMUNITY", "CRED_GENERIC",
})


@dataclass(frozen=True)
class Policy:
    name: str
    version: str
    internal_suffixes: tuple[str, ...]
    protect_public_typed_ips: bool
    protect_tickets: bool
    protect_secrets: bool
    enabled_kinds: frozenset[str]


class PolicyRegistry:
    def __init__(self, directory: Path):
        self._policies: dict[str, Policy] = {}
        for path in sorted(directory.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError(f"Invalid policy file: {path.name}")
            name = str(raw["name"])
            if name != path.stem:
                raise ValueError(f"Profile filename/name mismatch: {path.name}")
            kinds = frozenset(raw.get("enabled_kinds", list(SUPPORTED_KINDS)))
            if kinds - SUPPORTED_KINDS:
                raise ValueError(f"Unknown kinds in {name}: {sorted(kinds - SUPPORTED_KINDS)}")
            self._policies[name] = Policy(
                name=name,
                version=str(raw["version"]),
                internal_suffixes=tuple(str(s).casefold() for s in raw.get("internal_suffixes", [])),
                protect_public_typed_ips=bool(raw.get("protect_public_typed_ips", True)),
                protect_tickets=bool(raw.get("protect_tickets", False)),
                protect_secrets=bool(raw.get("protect_secrets", True)),
                enabled_kinds=kinds,
            )
        if not self._policies:
            raise RuntimeError(f"No privacy profiles found in {directory}")

    def get(self, name: str) -> Policy:
        try:
            return self._policies[name]
        except KeyError as exc:
            raise ValueError("Unknown privacy profile") from exc

    def names(self) -> list[dict[str, str]]:
        return [{"name": p.name, "version": p.version} for p in self._policies.values()]
