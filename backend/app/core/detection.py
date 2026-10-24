"""Conservative, schema-first PII/secret discovery for SOC and NOC data.

No inference from arbitrary bare words. Source field semantics and explicit
registrations take precedence over free text. Regexes deliberately focus on
high-confidence shapes; unknown organizational identities require hints.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from app.core.policy import Policy
from app.models import Registration

IP_FIELDS = {"src_ip", "source_ip", "source_address", "source_addr", "dst_ip", "dest_ip", "destination_ip", "destination_address", "client_ip", "remote_ip", "local_ip", "ip", "ip_address", "clientip"}
HOST_FIELDS = {
    "host", "hostname", "host_name", "device_name", "computer_name", "machine_name", "endpoint_name",
    "dvc", "dest_nt_host", "splunk_server", "risk_object_system", "success_dc", "failed_dc", "user_dc",
    "_risk_system", "risk_system",
}
USER_FIELDS = {
    "user", "username", "user_name", "user_id", "principal", "actor", "account", "samaccountname", "upn",
    "src_user", "dest_user", "target_user", "owner", "subject_user", "initiating_user",
    "failed_user", "tried_accounts", "risk_object_user", "_risk_user", "risk_user",
}
EMAIL_FIELDS = {"email", "email_address", "user_email", "sender_email", "recipient_email"}
ASSET_FIELDS = {"asset", "asset_id", "device_id", "endpoint_id", "host_id", "system_id", "machine_id", "risk_object_id"}
PATH_FIELDS = {
    "path", "file_path", "process_path", "parent_process_path", "image", "image_path", "image_loaded",
    "loaded_file", "loaded_file_path", "executable_path", "home_directory", "working_directory",
    "current_directory", "command_path", "process_current_directory", "file_name", "original_file_name",
    "process_name", "parent_process_name", "process_exec", "parent_process_exec",
}
MAC_FIELDS = {"mac", "mac_address", "src_mac", "dst_mac", "physical_address"}
SUBNET_FIELDS = {"subnet", "cidr", "network", "network_cidr", "ip_range"}
DOMAIN_FIELDS = {"internal_domain", "dns_domain", "domain_name", "ad_domain"}
URL_FIELDS = {"url", "uri", "internal_url", "endpoint_url", "web_url"}
PHONE_FIELDS = {"phone", "phone_number", "mobile_number", "telephone", "contact_phone"}
EMPLOYEE_FIELDS = {"employee_id", "personnel_id", "staff_id"}
SID_FIELDS = {"sid", "user_sid", "account_sid", "security_identifier", "object_sid"}
ORG_FIELDS = {"tenant_id", "organization_id", "org_id", "company_id"}
GROUP_FIELDS = {"ad_group", "group_name", "security_group", "group_sid"}
CLOUD_FIELDS = {"resource_arn", "aws_arn", "azure_resource_id", "cloud_resource_id", "subscription_id", "aws_account_id"}
SERIAL_FIELDS = {"serial_number", "device_serial", "hardware_serial", "chassis_serial", "bios_serial"}
INDEX_FIELDS = {"splunk_index", "index_name", "sourcetype_private", "index"}
REF_FIELDS = {"change_ticket", "ticket_id", "incident_id", "case_id", "case_number", "notable_id", "finding_uid", "asset_reference"}
# Splunk/OCSF identity carriers whose concrete kind depends on a sibling type field.
POLYMORPHIC_IDENTITY_FIELDS = {
    "src", "dst", "dest", "entity", "risk_object", "normalized_risk_object", "threat_object", "all_risk_objects",
}
IDENTITY_TYPE_MAP = {
    "user": "USER", "account": "USER", "username": "USER",
    "system": "HOST", "device": "HOST", "host": "HOST", "hostname": "HOST", "computer": "HOST",
    "ip": "IP", "network": "IP", "address": "IP",
    "asset": "ASSET", "file": "PATH", "file_name": "PATH", "filename": "PATH",
    "file_hash": "ASSET", "hash": "ASSET",
    "domain": "DOMAIN", "fqdn": "HOST", "url": "URL_INTERNAL",
}
MULTIVALUE_KINDS = frozenset({
    "USER", "HOST", "EMAIL", "ASSET", "IP", "IP_OPAQUE", "SPLUNK_INDEX", "DOMAIN", "PATH",
})
SECRET_KINDS = {
    "password": "CRED_PASSWORD", "passwd": "CRED_PASSWORD", "passphrase": "CRED_PASSPHRASE",
    "api_key": "CRED_API_KEY", "apikey": "CRED_API_KEY", "access_key": "CRED_ACCESS_KEY",
    "secret_access_key": "CRED_SECRET_ACCESS_KEY", "access_token": "CRED_ACCESS_TOKEN",
    "refresh_token": "CRED_REFRESH_TOKEN", "session_token": "CRED_SESSION_TOKEN",
    "bearer_token": "CRED_BEARER", "authorization": "CRED_AUTHORIZATION",
    "authorization_header": "CRED_AUTHORIZATION", "cookie": "CRED_COOKIE", "cookies": "CRED_COOKIE",
    "set_cookie": "CRED_COOKIE", "private_key": "CRED_PRIVATE_KEY", "private_key_pem": "CRED_PRIVATE_KEY",
    "client_secret": "CRED_CLIENT_SECRET", "jwt": "CRED_JWT", "snmp_community": "CRED_SNMP_COMMUNITY", "snmp_community_string": "CRED_SNMP_COMMUNITY", "secret": "CRED_GENERIC",
    "token": "CRED_GENERIC", "auth_token": "CRED_ACCESS_TOKEN", "credential": "CRED_GENERIC",
    "credentials": "CRED_GENERIC",
}
PLACEHOLDERS = {"", "-", "unknown", "n/a", "na", "none", "null", "not available", "redacted"}
KIND_RE = re.compile(r"^(?:CRED_[A-Z_]+|IP_(?:V4|V6)_[A-Z_]+|IP_OPAQUE|HOST|USER|EMAIL|ASSET|MAC|SUBNET|DOMAIN|URL_INTERNAL|PATH|TICKET|CASE|REFERENCE|PHONE|EMPLOYEE_ID|USER_SID|ORG_ID|AD_GROUP|CLOUD_RESOURCE|DEVICE_SERIAL|SPLUNK_INDEX)_[A-F0-9]{24,40}$")

EMAIL_RE = re.compile(r"(?<![\w@])[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w@])")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]{0,4}(?![\w:])")
CIDR_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/(?:\d|[12]\d|3[0-2])(?![\w.])")
MAC_RE = re.compile(r"(?<![A-Za-z0-9])(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![A-Za-z0-9])")
# Allow one or two backslashes: Splunk _raw often escapes DOMAIN\user as DOMAIN\\user.
WINDOWS_USER_RE = re.compile(
    r"(?<![\w\\])[A-Za-z0-9_.-]{1,64}\\{1,2}[A-Za-z0-9_.@$-]{1,128}(?!\w)"
)
WIN_PATH_RE = re.compile(r"(?<!\w)[A-Za-z]:\\[^\s\"'<>|]+")
# Require a non-identifier before UNC so DOMAIN\\server\share (escaped AD
# principals in Splunk _raw) is not classified as a filesystem path.
UNC_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])\\\\[A-Za-z0-9_.-]+\\[^\s\"'<>|]+")
UNIX_PATH_RE = re.compile(r"(?<![\w./])(?:/[A-Za-z0-9_.-]+){2,}/?")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
FQDN_RE = re.compile(r"(?<![\w.])(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,}\.?(?!\w)")
JWT_RE = re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?!\w)")
GH_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")
AWS_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.DOTALL)
SECRET_ASSIGN_RE = re.compile(r"(?i)(?<![\w])(?:password|passwd|passphrase|api[_-]?key|secret[_-]?access[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|session[_-]?token|secret|credential|cookie|token)\s*[:=]\s*(?:[\"'](?P<quoted>[^\"']+)[\"']|(?P<secret>[^\s;\"'}]+))")
BEARER_RE = re.compile(r"(?i)\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+(?P<secret>[^\s,;\"'}]+)")
# Keep label extraction conservative: bare src/dest in prose often bind to
# stopwords (e.g. "src: SIEM") and must not become free-text HOST tokens.
TEXT_LABEL_RE = re.compile(
    r"(?i)(?<!\w)(?P<label>src_ip|dst_ip|source_ip|dest_ip|ip_address|hostname|host|username|user|"
    r"failed_user|tried_accounts|device_name|asset_id|email|principal|splunk_server)\s*[:=]\s*"
    r"[\"']?(?P<value>[^\s,;\"'}]+)"
)


def normalize_key(raw: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(raw)).lower().replace("-", "_").replace(".", "_")


def expand_multivalue(kind: str, value: str) -> list[str]:
    """Split Splunk-style multivalue identity fields without inventing free-text tokens."""
    if kind not in MULTIVALUE_KINDS:
        return [value]
    if "\n" not in value and "\r" not in value:
        return [value]
    parts = [part.strip() for part in re.split(r"[\r\n]+", value) if part.strip()]
    return parts if len(parts) > 1 else [value]


def is_low_signal_identity(kind: str, value: str) -> bool:
    """Drop junk MV fragments that are not actionable identities."""
    trimmed = value.strip()
    if len(trimmed) < 2:
        return True
    if re.fullmatch(r"[\\/._-]+", trimmed):
        return True
    if kind in {"USER", "HOST", "ASSET", "IP_OPAQUE"} and trimmed.isdigit():
        return True
    # Bare 1-2 char USER tokens (IT, HR, DC, PC) collide with common acronyms in
    # SOC narratives and break encode validation after projection.
    if kind == "USER" and "\\" not in trimmed and "@" not in trimmed and len(trimmed) < 3:
        return True
    if kind in {"HOST", "ASSET"} and len(trimmed) < 2:
        return True
    return False


HOST_STOPWORDS = frozenset({
    "siem", "change", "windows", "registry", "source", "unknown", "null", "none", "n/a",
    "true", "false", "local", "remote", "network", "system", "host", "user", "process",
})
REGISTRY_HIVES = frozenset({
    "hklm", "hkcu", "hkcr", "hku", "hkcc",
    "hkey_local_machine", "hkey_current_user", "hkey_classes_root", "hkey_users", "hkey_current_config",
})


def infer_identity_kind(value: str) -> str | None:
    """Best-effort kind for named identity fields when a sibling type is absent."""
    trimmed = value.strip()
    if not trimmed or trimmed.casefold() in PLACEHOLDERS:
        return None
    try:
        ipaddress.ip_address(trimmed)
        return "IP"
    except ValueError:
        pass
    if EMAIL_RE.fullmatch(trimmed):
        return "EMAIL"
    if "\\" in trimmed and not trimmed.startswith("\\\\") and not re.match(r"^[A-Za-z]:\\", trimmed):
        return "USER"
    if WIN_PATH_RE.fullmatch(trimmed) or UNC_PATH_RE.fullmatch(trimmed) or UNIX_PATH_RE.fullmatch(trimmed):
        return "PATH"
    if trimmed.lower().startswith(("http://", "https://")):
        return "URL_INTERNAL"
    if trimmed.casefold() in HOST_STOPWORDS:
        return None
    return "HOST"


def sibling_identity_type(siblings: dict | None) -> str:
    if not siblings:
        return ""
    for key in (
        "entity_type", "risk_object_type", "threat_object_type", "normalized_risk_object_type",
        "src_type", "dest_type", "dst_type",
    ):
        raw = siblings.get(key)
        if raw is None:
            continue
        text = str(raw).strip()
        if text:
            return normalize_key(text)
    return ""


def canonical(kind: str, value: str) -> str:
    value = value.strip()
    if kind == "IP":
        return str(ipaddress.ip_address(value))
    if kind == "SUBNET":
        return str(ipaddress.ip_network(value, strict=False))
    # JSON / Splunk escapes often yield DOMAIN\\user; collapse to one separator so
    # registry digests and aliases stay stable across spellings of the same principal.
    if kind == "USER" and "\\" in value and not value.startswith("\\\\") and not re.match(r"^[A-Za-z]:\\", value):
        domain, _sep, account = value.partition("\\")
        account = account.lstrip("\\")
        return f"{domain.casefold()}\\{account.casefold()}"
    if kind in {"HOST", "USER", "EMAIL", "DOMAIN", "MAC", "ASSET", "IP_OPAQUE", "TICKET", "CASE", "PHONE", "EMPLOYEE_ID", "USER_SID", "ORG_ID", "AD_GROUP", "CLOUD_RESOURCE", "DEVICE_SERIAL", "SPLUNK_INDEX"}:
        return value.rstrip(".").casefold()
    return value


def is_internal_host(host: str, policy: Policy) -> bool:
    clean = host.casefold().rstrip(".")
    return any(clean.endswith(suffix) for suffix in policy.internal_suffixes)


def ip_kind(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "IP_OPAQUE"
    fam = "V4" if ip.version == 4 else "V6"
    if ip.is_loopback:
        scope = "LOOPBACK"
    elif ip.is_link_local:
        scope = "LINKLOCAL"
    elif ip.is_private or ip.is_reserved:
        scope = "PRIVATE"
    else:
        scope = "PUBLIC"
    return f"IP_{fam}_{scope}"


@dataclass(frozen=True)
class Candidate:
    kind: str
    value: str
    source: str
    path: str


class Detector:
    def __init__(self, policy: Policy):
        self.policy = policy

    def _accepted(self, kind: str, value: str, path: str, source: str) -> Candidate | None:
        value = value.strip()
        if not value or value.casefold() in PLACEHOLDERS or len(value) > 65536 or KIND_RE.fullmatch(value):
            return None
        if kind == "IP":
            kind = "IP" if ip_kind(value) != "IP_OPAQUE" else "IP_OPAQUE"
        if is_low_signal_identity(kind, value):
            return None
        # Alias tokens / registry paths can look like DOMAIN\user after projection
        # (e.g. HOST_<hex>\Software or HKLM\USER_<hex>). Those are not identities.
        if kind == "USER" and "\\" in value:
            domain, _sep, account = value.partition("\\")
            account = account.lstrip("\\")
            if domain.casefold() in REGISTRY_HIVES or domain.casefold().startswith("hkey_"):
                return None
            if KIND_RE.fullmatch(domain) or KIND_RE.fullmatch(account):
                return None
        if kind.startswith("CRED_") and not self.policy.protect_secrets:
            return None
        if kind in {"TICKET", "CASE", "REFERENCE"} and not self.policy.protect_tickets:
            return None
        if kind not in self.policy.enabled_kinds:
            return None
        return Candidate(kind, value, source, path)

    @staticmethod
    def _semantics(path: tuple[str, ...], siblings: dict | None) -> str | None:
        if not path:
            return None
        leaf = normalize_key(path[-1])
        parent = normalize_key(path[-2]) if len(path) > 1 else ""
        if leaf in SECRET_KINDS:
            return SECRET_KINDS[leaf]
        for suffix, value in (("_password", "CRED_PASSWORD"), ("_secret", "CRED_GENERIC"), ("_token", "CRED_GENERIC"), ("_api_key", "CRED_API_KEY"), ("_private_key", "CRED_PRIVATE_KEY")):
            if leaf.endswith(suffix):
                return value
        if leaf in IP_FIELDS:
            return "IP"
        if leaf in EMAIL_FIELDS:
            return "EMAIL"
        if leaf in HOST_FIELDS:
            return "HOST"
        if leaf in USER_FIELDS:
            return "USER"
        if leaf in ASSET_FIELDS:
            return "ASSET"
        if leaf in PATH_FIELDS:
            return "PATH"
        if leaf in MAC_FIELDS:
            return "MAC"
        if leaf in SUBNET_FIELDS:
            return "SUBNET"
        if leaf in DOMAIN_FIELDS:
            return "DOMAIN"
        if leaf in URL_FIELDS:
            return "URL_INTERNAL"
        if leaf in PHONE_FIELDS:
            return "PHONE"
        if leaf in EMPLOYEE_FIELDS:
            return "EMPLOYEE_ID"
        if leaf in SID_FIELDS:
            return "USER_SID"
        if leaf in ORG_FIELDS:
            return "ORG_ID"
        if leaf in GROUP_FIELDS:
            return "AD_GROUP"
        if leaf in CLOUD_FIELDS:
            return "CLOUD_RESOURCE"
        if leaf in SERIAL_FIELDS:
            return "DEVICE_SERIAL"
        if leaf in INDEX_FIELDS:
            return "SPLUNK_INDEX"
        if leaf in REF_FIELDS:
            return "CASE" if "case" in leaf else "TICKET"
        if leaf in {"name", "hostname"} and parent in {"device", "host", "src_endpoint", "dst_endpoint", "source_endpoint", "destination_endpoint"}:
            return "HOST"
        if leaf == "ip" and parent in {"device", "host", "src_endpoint", "dst_endpoint"}:
            return "IP"
        if leaf == "name" and parent in {"user", "account", "principal"}:
            return "USER"
        if leaf in POLYMORPHIC_IDENTITY_FIELDS:
            mapped = IDENTITY_TYPE_MAP.get(sibling_identity_type(siblings))
            return mapped or "IDENTITY"
        return None

    def _resolve_kind(self, path: tuple[str, ...], siblings: dict | None, value: str) -> str | None:
        sem = self._semantics(path, siblings)
        if sem == "IDENTITY":
            return infer_identity_kind(value)
        if sem == "HOST" and value.strip().casefold() in HOST_STOPWORDS:
            return None
        return sem

    def _typed(self, kind: str, value: str, path: str) -> Candidate | None:
        if kind == "URL_INTERNAL":
            try:
                if not is_internal_host(urlsplit(value).hostname or "", self.policy):
                    return None
            except ValueError:
                return None
        if kind == "IP" and not self.policy.protect_public_typed_ips:
            if ip_kind(value).endswith("PUBLIC"):
                return None
        if kind == "SUBNET":
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError:
                return None
        if kind == "DOMAIN":
            # Typed domain fields are organizational; free-text still requires internal suffixes.
            pass
        return self._accepted(kind, value, path, "structured")

    def discover(self, payload: Any, registrations: list[Registration] | None = None) -> list[Candidate]:
        found: list[Candidate] = []
        for reg in registrations or []:
            kind = reg.kind.upper().strip()
            if kind == "SECRET":
                kind = "CRED_GENERIC"
            if kind not in self.policy.enabled_kinds:
                raise ValueError("Unsupported or disabled registration kind")
            entry = self._accepted(kind, reg.value, reg.source, "explicit")
            if entry:
                found.append(entry)

        def walk(obj: Any, path: tuple[str, ...], sibling: dict | None, depth: int) -> None:
            if depth > 32:
                raise ValueError("Input nesting exceeds 32 levels")
            if isinstance(obj, dict):
                for key, child in obj.items():
                    walk(child, (*path, str(key)), obj, depth + 1)
            elif isinstance(obj, list):
                for idx, child in enumerate(obj):
                    walk(child, (*path, str(idx)), sibling, depth + 1)
            elif isinstance(obj, str):
                # Resolve against the full field first so multivalue blobs keep a typed kind,
                # then emit each MV token so narrative copies (_raw, titles) are scrubbed too.
                seed_kind = self._resolve_kind(path, sibling, obj)
                if seed_kind:
                    for piece in expand_multivalue(seed_kind, obj):
                        kind = self._resolve_kind(path, sibling, piece) or seed_kind
                        value = self._typed(kind, piece, ".".join(path))
                        if value:
                            found.append(value)
                found.extend(self.discover_text(obj, path=".".join(path)))
        walk(payload, (), None, 0)
        return list({(c.kind, c.value): c for c in found}.values())

    def discover_text(self, text: str, *, path: str = "$text") -> list[Candidate]:
        found: list[Candidate] = []
        # LLM message content commonly contains serialized JSON. Recover its
        # field semantics before fallback free-text pattern detection.
        stripped = text.strip()
        if len(stripped) <= 262144 and stripped.startswith(("{", "[")):
            try:
                nested = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                nested = None
            if isinstance(nested, (dict, list)):
                found.extend(self.discover(nested))

        def add(kind: str, value: str, source: str = "text") -> None:
            candidate = self._accepted(kind, value, path, source)
            if candidate:
                found.append(candidate)

        if self.policy.protect_secrets:
            for match in PRIVATE_KEY_RE.finditer(text):
                add("CRED_PRIVATE_KEY", match.group())
            for pattern in (SECRET_ASSIGN_RE, BEARER_RE):
                for match in pattern.finditer(text):
                    raw = match.group("secret") or match.groupdict().get("quoted")
                    if not raw:
                        continue
                    add("CRED_BEARER" if pattern is BEARER_RE else "CRED_GENERIC", raw)
            for pattern, kind in ((JWT_RE, "CRED_JWT"), (GH_RE, "CRED_API_KEY"), (AWS_RE, "CRED_ACCESS_KEY")):
                for match in pattern.finditer(text):
                    add(kind, match.group())
        for match in EMAIL_RE.finditer(text):
            add("EMAIL", match.group())
        for match in WINDOWS_USER_RE.finditer(text):
            add("USER", match.group())
        for pattern in (WIN_PATH_RE, UNC_PATH_RE, UNIX_PATH_RE):
            for match in pattern.finditer(text):
                add("PATH", match.group())
        for match in URL_RE.finditer(text):
            raw = match.group().rstrip(".,;)")
            try:
                if is_internal_host(urlsplit(raw).hostname or "", self.policy):
                    add("URL_INTERNAL", raw)
            except ValueError:
                pass
        for match in CIDR_RE.finditer(text):
            add("SUBNET", match.group())
        for match in MAC_RE.finditer(text):
            add("MAC", match.group())
        for match in IPV4_RE.finditer(text):
            value = match.group()
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not ip.is_global:
                add("IP", value)
        for match in IPV6_RE.finditer(text):
            value = match.group()
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not ip.is_global:
                add("IP", value)
        for match in FQDN_RE.finditer(text):
            if is_internal_host(match.group(), self.policy):
                add("HOST", match.group())
        for match in TEXT_LABEL_RE.finditer(text):
            label = normalize_key(match.group("label"))
            value = match.group("value")
            kind = self._resolve_kind((label,), None, value)
            if kind:
                add(kind, value, "context-label")
        return list({(c.kind, c.value): c for c in found}.values())
