"""Static regression checks for independent production deployment configuration."""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_production_network_isolation_and_https_only():
    config = yaml.safe_load((ROOT / "docker-compose.production.yml").read_text())
    services = config["services"]
    assert set(services) == {"privacy-https", "privacy-api", "redis"}
    assert all(not svc.get("ports") for svc in services.values())
    assert "soc_privacy" in services["privacy-https"]["networks"]
    assert set(services["privacy-api"]["networks"]) == {"private_http", "private_store"}
    assert services["redis"]["networks"] == ["private_store"]
    assert config["networks"]["private_http"]["internal"] is True
    assert config["networks"]["private_store"]["internal"] is True
    assert config["networks"]["soc_privacy"]["external"] is True
    assert services["privacy-https"]["expose"] == ["8443"]


def test_production_requires_authenticated_redis_and_disables_demo():
    config = yaml.safe_load((ROOT / "docker-compose.production.yml").read_text())
    env = config["services"]["privacy-api"]["environment"]
    assert env["DLP_DEV_MODE"] == "false"
    assert env["DLP_UI_ENABLED"] == "false"
    assert env["DLP_DEMO_API_KEY"] == ""
    assert env["DLP_STORE_BACKEND"] == "redis"
    assert env["DLP_REDIS_URL"].startswith("${DLP_REDIS_URL:?")
    for name in ("DLP_MAX_PAYLOAD_BYTES", "DLP_CONTEXT_TTL", "DLP_MAX_CONTEXT_TTL"):
        assert env[name].startswith("${" + name + ":-")
    assert "--tls" in config["services"]["redis"]["healthcheck"]["test"][1]


def test_tls_config_and_request_body_limit():
    caddy = (ROOT / "deploy/caddy/Caddyfile").read_text()
    redis = (ROOT / "deploy/redis/redis.conf").read_text()
    assert "tls /run/secrets/gateway-cert.pem /run/secrets/gateway-key.pem" in caddy
    assert "max_size {$DLP_MAX_PAYLOAD_BYTES}" in caddy
    assert "reverse_proxy privacy-api:8484" in caddy
    assert "tls-port 6379" in redis
    assert "port 0" in redis
    assert "tls-ca-cert-file" in redis
    assert "aclfile /run/secrets/redis-users.acl" in redis
    assert "appendonly yes" in redis


def test_python_package_index_fallback_is_ordered_and_https_only():
    dockerfile = (ROOT / "Dockerfile").read_text()
    indexes = [
        "ARG PIP_INDEX_PRIMARY=https://package-mirror.liara.ir/repository/pypi/simple/",
        "ARG PIP_INDEX_SECONDARY=https://mirror2.chabokan.net/pypi/simple/",
        "ARG PIP_INDEX_FALLBACK=https://pypi.org/simple/",
    ]
    positions = [dockerfile.index(index) for index in indexes]
    assert positions == sorted(positions)
    assert 'for index in "$PIP_INDEX_PRIMARY" "$PIP_INDEX_SECONDARY" "$PIP_INDEX_FALLBACK"' in dockerfile
    assert 'case "$index" in https://*' in dockerfile
    assert "unset PIP_EXTRA_INDEX_URL" in dockerfile
    assert 'PIP_INDEX_URL="$index" python -m pip install' in dockerfile
    assert "--no-build-isolation ./backend" in dockerfile
    assert 'if [ "$installed" -ne 1 ]; then' in dockerfile


def test_development_port_localhost_and_build_context_excludes_secrets():
    dev = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    assert dev["services"]["privacy-api"]["ports"] == ["127.0.0.1:8484:8484"]
    excludes = (ROOT / ".dockerignore").read_text().splitlines()
    assert ".env" in excludes
    assert ".env.*" in excludes
    assert ".git" in excludes
