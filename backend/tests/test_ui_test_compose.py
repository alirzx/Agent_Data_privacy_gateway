"""Ensure the demo stays isolated and LAN ingress is explicitly protected."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_ui_compose_isolated_from_production():
    compose = yaml.safe_load((ROOT / "docker-compose.ui-test.yml").read_text())
    assert set(compose["services"]) == {"privacy-ui-test", "privacy-ui-lan"}
    ui = compose["services"]["privacy-ui-test"]
    assert ui["image"] == "soorin-privacy-v2-privacy-api:latest"
    assert ui["env_file"] == ".env.ui-test"
    assert ui["ports"] == ["127.0.0.1:18484:8484"]
    assert ui["restart"] == "unless-stopped"
    assert ui["read_only"] is True
    assert ui["cap_drop"] == ["ALL"]
    assert ui["security_opt"] == ["no-new-privileges:true"]
    assert "--workers" in ui["command"]
    assert ui["command"][ui["command"].index("--workers") + 1] == "1"
    assert "networks" not in ui
    assert "volumes" not in ui
    assert "depends_on" not in ui
    assert "DLP_MASTER_KEY_B64" not in (ROOT / "docker-compose.ui-test.yml").read_text()
    assert ".env.*" in (ROOT / ".gitignore").read_text()


def test_ui_env_provisioner_refuses_overwrite():
    source = (ROOT / "ops/init_ui_test_env.py").read_text()
    assert "TARGET.exists() or TARGET.is_symlink()" in source
    assert "os.O_EXCL" in source
    assert "0o600" in source
    assert '"DLP_STORE_BACKEND": "memory"' in source
    assert '"DLP_CLIENTS_JSON": "[]"' in source


def test_lan_ui_has_https_auth_and_is_opt_in():
    compose = yaml.safe_load((ROOT / "docker-compose.ui-test.yml").read_text())
    proxy = compose["services"]["privacy-ui-lan"]
    assert proxy["profiles"] == ["lan"]
    assert proxy["image"] == "caddy:2.10-alpine"
    assert proxy["ports"] == ["${DLP_UI_LAN_BIND_IP:-127.0.0.1}:18485:8443"]
    assert proxy["cap_drop"] == ["ALL"]
    assert proxy["cap_add"] == ["NET_BIND_SERVICE"]
    assert proxy["security_opt"] == ["no-new-privileges:true"]
    assert proxy["read_only"] is True
    assert proxy["restart"] == "unless-stopped"
    assert "ui-caddy-data" in compose["volumes"]
    assert "aisoc-privacy" not in (ROOT / "docker-compose.ui-test.yml").read_text()

    caddy = (ROOT / "deploy/caddy/UI-Caddyfile").read_text()
    assert "tls internal" in caddy
    assert "basic_auth" in caddy
    assert "path /v1/policies /v1/contexts /v1/contexts/* /v1/classify /v1/encode /v1/decode" in caddy
    assert 'header Authorization "Bearer *"' in caddy
    assert "/v1/dev/console" not in caddy.split("handle @bearer_api")[0].split("path /v1/")[1].split("}")[0]
    assert "header_up -Authorization" in caddy


def test_lan_access_provisioning_is_private_and_non_overwriting():
    source = (ROOT / "ops/init_ui_lan_env.py").read_text()
    assert 'TARGET.exists() or TARGET.is_symlink()' in source
    assert "os.O_EXCL" in source
    assert "0o600" in source
    assert "getpass.getpass" in source
    assert '"hash-password", "--algorithm", "bcrypt"' in source
    assert '"--plaintext"' not in source
    assert ".env.ui-lan" in (ROOT / ".gitignore").read_text() or ".env.*" in (ROOT / ".gitignore").read_text()
