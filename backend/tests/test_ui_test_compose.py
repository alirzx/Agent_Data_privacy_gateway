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


def test_lan_ui_has_https_and_optional_browser_auth():
    compose = yaml.safe_load((ROOT / "docker-compose.ui-test.yml").read_text())
    proxy = compose["services"]["privacy-ui-lan"]
    assert proxy["profiles"] == ["lan"]
    assert proxy["image"] == "caddy:2.10-alpine"
    assert proxy["ports"] == ["${DLP_UI_LAN_BIND_IP:-127.0.0.1}:${DLP_UI_LAN_PORT:-8484}:8443"]
    assert proxy["environment"]["DLP_UI_BASIC_AUTH_ENABLED"] == "${DLP_UI_BASIC_AUTH_ENABLED:-false}"
    assert proxy["entrypoint"] == ["/bin/sh", "-ec"]
    assert isinstance(proxy["command"], list) and len(proxy["command"]) == 1
    script = proxy["command"][0]
    assert "UI-Caddyfile" in script
    assert "UI-BasicAuth.Caddyfile" in script
    assert "${DLP_UI_BASIC_AUTH_ENABLED:-false}" in script
    assert "$config" in script
    assert "exit 1" in script
    assert proxy["cap_drop"] == ["ALL"]
    assert proxy["cap_add"] == ["NET_BIND_SERVICE"]
    assert proxy["security_opt"] == ["no-new-privileges:true"]
    assert proxy["read_only"] is True
    assert proxy["restart"] == "unless-stopped"
    assert "ui-caddy-data" in compose["volumes"]
    assert "aisoc-privacy" not in (ROOT / "docker-compose.ui-test.yml").read_text()

    caddy = (ROOT / "deploy/caddy/UI-Caddyfile").read_text()
    assert "tls internal" in caddy
    assert "default_sni {$DLP_UI_LAN_BIND_IP}" in caddy
    assert "basic_auth" not in caddy
    auth_caddy = (ROOT / "deploy/caddy/UI-BasicAuth.Caddyfile").read_text()
    assert "basic_auth" in auth_caddy
    assert "path /v1/policies /v1/contexts /v1/contexts/* /v1/classify /v1/encode /v1/decode" in auth_caddy
    assert 'header Authorization "Bearer *"' in auth_caddy
    assert "/v1/dev/console" not in auth_caddy.split("handle @bearer_api")[0].split("path /v1/")[1].split("}")[0]
    assert "header_up -Authorization" in auth_caddy


def test_lan_access_provisioning_is_private_and_non_overwriting():
    source = (ROOT / "ops/init_ui_lan_env.py").read_text()
    assert 'TARGET.exists() or TARGET.is_symlink()' in source
    assert "os.O_EXCL" in source
    assert "0o600" in source
    assert "getpass.getpass" in source
    assert '"hash-password", "--algorithm", "bcrypt"' in source
    assert '"--plaintext"' not in source
    assert ".env.ui-lan" in (ROOT / ".gitignore").read_text() or ".env.*" in (ROOT / ".gitignore").read_text()


def test_lan_provisioning_noauth_does_not_prompt(tmp_path, monkeypatch):
    import importlib.util
    import sys
    module_path = ROOT / "ops/init_ui_lan_env.py"
    spec = importlib.util.spec_from_file_location("ui_lan_test_module", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "TARGET", tmp_path / ".env.ui-lan")
    monkeypatch.setattr(sys, "argv", ["init", "--bind-ip", "192.168.0.55"])
    def fail_password_prompt(*args, **kwargs):
        raise AssertionError("No password should be required")
    monkeypatch.setattr(module.getpass, "getpass", fail_password_prompt)
    module.main()
    settings = module.TARGET.read_text()
    assert "DLP_UI_BASIC_AUTH_ENABLED=false" in settings
    assert "DLP_UI_LAN_PORT=8484" in settings
    assert "DLP_UI_ACCESS_HASH" not in settings
    assert module.TARGET.stat().st_mode & 0o777 == 0o600


def test_lan_provisioner_can_opt_into_basic_auth(tmp_path, monkeypatch):
    import importlib.util
    import sys
    spec = importlib.util.spec_from_file_location("ui_lan_auth_module", ROOT / "ops/init_ui_lan_env.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "TARGET", tmp_path / ".env.ui-lan")
    monkeypatch.setattr(sys, "argv", ["init", "--bind-ip", "192.168.0.55", "--basic-auth"])
    passwords = iter(["a-very-long-test-password", "a-very-long-test-password"])
    monkeypatch.setattr(module.getpass, "getpass", lambda *args: next(passwords))
    class FakeResult:
        stdout = "$2b$12$synthetic_bcrypt_hash_not_a_secret"
    def fake_run(*args, **kwargs):
        assert kwargs["input"] == "a-very-long-test-password\n"
        return FakeResult()
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    module.main()
    settings = module.TARGET.read_text()
    assert "DLP_UI_BASIC_AUTH_ENABLED=true" in settings
    assert "DLP_UI_ACCESS_USER=dlp-tester" in settings
    assert "DLP_UI_ACCESS_HASH=" in settings
    assert "a-very-long-test-password" not in settings
