"""Self-hosted bootstrap resources, URL migration and installer behavior."""

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from link42_api import main, models
from link42_api.config import Settings
from link42_api.database import Base

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def release(tmp_path, monkeypatch):
    root = tmp_path / "releases"
    root.mkdir()
    releases = {}
    for version in ("0.1.0", "0.2.0"):
        assets = {}
        for platform, name in (("linux-x64", "binary"), ("openwrt-source", "source")):
            data = f"{name}-{version}".encode()
            path = f"{name}-{version}"
            (root / path).write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            (root / f"{path}.sha256").write_text(f"{digest}  {path}\n")
            assets[platform] = {"path": path, "sha256": digest, "size": len(data)}
            if platform == "openwrt-source":
                assets[platform]["install_mode"] = "source"
        releases[version] = {"assets": assets}
    (root / "manifest.json").write_text(json.dumps({"latest": "0.2.0", "releases": releases}))
    monkeypatch.setattr(main.settings, "agent_release_dir", str(root))
    return root


@pytest.fixture
def client(release, tmp_path, monkeypatch):
    # Include the real auth middleware and append the SPA fallback to expose
    # resource routing regressions, without running production startup hooks.
    app = FastAPI(routes=list(main.app.routes), middleware=main.app.user_middleware)
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("<html>panel</html>")
    monkeypatch.setattr(main, "app", app)
    monkeypatch.setattr(main.settings, "web_dist_dir", str(web))
    main.mount_web_panel()
    with TestClient(app) as result:
        yield result


@pytest.mark.parametrize("version", [None, "latest", "0.1.0", "0.2.0"])
@pytest.mark.parametrize("filename,kind", [("link42-agent-linux-x64", "binary"), ("link42-agent-source.tar.gz", "source")])
def test_anonymous_agent_downloads_and_checksums(client, version, filename, kind):
    prefix = "/res/link42/" + (f"{version}/" if version else "")
    response = client.get(prefix + filename)
    assert response.status_code == 200
    assert response.content == f"{kind}-{version if version not in {None, 'latest'} else '0.2.0'}".encode()
    checksum = client.get(prefix + filename + ".sha256")
    assert checksum.status_code == 200
    assert checksum.text == f"{hashlib.sha256(response.content).hexdigest()}  {filename}\n"
    # Existing self-upgrade APIs keep their version/platform wire format.
    api = client.get("/api/agent/releases/0.2.0/download?platform=linux-x64")
    assert api.content == b"binary-0.2.0"


@pytest.mark.parametrize("name", ["link42-agent.sh", "udp2raw.sh"])
def test_anonymous_install_scripts_are_real_shell(client, name):
    response = client.get(f"/sh/{name}")
    assert response.status_code == 200
    assert response.text.startswith("#!/bin/sh\n")
    assert response.headers["content-type"].startswith("text/plain")


@pytest.mark.parametrize("url", [
    "/sh/unknown.sh", "/sh/udp2raw_bin/version.txt", "/sh/udp2raw_bin/unknown",
    "/res/link42/manifest.json", "/res/link42/missing/link42-agent-linux-x64",
    "/res/link42/%2E%2E%2Fsecret", "/res/link42/0.2.0/%2E%2E%2Fsecret",
    "/sh/udp2raw_bin/%2E%2E%2Fsecret",
])
def test_unknown_resources_never_return_panel_html(client, url):
    response = client.get(url)
    assert response.status_code == 404
    assert "<html>" not in response.text


@pytest.mark.parametrize("problem", ["missing", "symlink", "parent-symlink", "manifest-symlink", "traversal"])
def test_asset_and_checksum_both_reject_unsafe_files(client, release, tmp_path, problem):
    asset = release / "binary-0.2.0"
    if problem == "missing":
        asset.unlink()
    elif problem == "symlink":
        asset.unlink()
        asset.symlink_to(release / "source-0.2.0")
    elif problem == "parent-symlink":
        alias = tmp_path / "release-alias"
        alias.symlink_to(release, target_is_directory=True)
        main.settings.agent_release_dir = str(alias)
    elif problem == "manifest-symlink":
        path = release / "manifest.json"
        saved = release / "manifest-saved.json"
        path.rename(saved)
        path.symlink_to(saved)
    else:
        path = release / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["releases"]["0.2.0"]["assets"]["linux-x64"]["path"] = "../secret"
        path.write_text(json.dumps(manifest))
    for suffix in ("", ".sha256"):
        response = client.get("/res/link42/link42-agent-linux-x64" + suffix)
        assert response.status_code in {400, 404, 500}
        assert "<html>" not in response.text


def test_udp2raw_public_download_does_not_remove_agent_api_auth(client):
    response = client.get("/sh/udp2raw_bin/udp2raw_amd64")
    assert response.status_code == 200
    assert response.content == (ROOT / "udp2raw_sh/udp2raw_bin/udp2raw_amd64").read_bytes()
    response = client.get("/api/agent/plugins/udp2raw/assets/udp2raw_amd64")
    assert response.status_code == 401


@pytest.mark.parametrize("relative,url", [
    ("deploy/sh/link42-agent.sh", "/sh/link42-agent.sh"),
    ("udp2raw_sh/udp2raw.sh", "/sh/udp2raw.sh"),
    ("udp2raw_sh/udp2raw_bin/udp2raw_amd64", "/sh/udp2raw_bin/udp2raw_amd64"),
])
def test_public_scripts_and_udp2raw_reject_symlink_files(client, tmp_path, monkeypatch, relative, url):
    root = tmp_path / "source"
    monkeypatch.setattr(main, "__file__", str(root / "apps/api/link42_api/main.py"))
    path = root / relative
    path.parent.mkdir(parents=True)
    secret = tmp_path / "private"
    secret.write_text("private file contents")
    path.symlink_to(secret)
    response = client.get(url)
    assert response.status_code == 404
    assert secret.read_text() not in response.text


@pytest.mark.parametrize("address", ["", "https://host/path", "https://user@host", "http://host:0"])
def test_upgrade_plan_requires_valid_controller_address(release, address):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        node = models.Node(id=1, name="old", agent_version="0.0.1")
        main.set_setting(db, main.SETTING_CONTROLLER_URL, address)
        plan = main.build_agent_upgrade_plan(node, db)
        assert plan.upgrade_mode == "unavailable"
        assert "主控地址" in plan.reason
        assert plan.manual_command is None


def test_manual_upgrade_uses_controller_and_checks_missing_assets(release, monkeypatch):
    monkeypatch.setattr(main.settings, "agent_install_script_url", "https://old.example/install.sh")
    monkeypatch.setattr(main.settings, "agent_res_base_url", "https://old.example/res")
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        node = models.Node(id=1, name="old", agent_version="0.0.1", last_seen_at=datetime.utcnow())
        main.set_setting(db, main.SETTING_CONTROLLER_URL, "https://panel.example:8443/")
        plan = main.build_agent_upgrade_plan(node, db)
        assert plan.upgrade_mode == "manual"
        assert "https://panel.example:8443/sh/link42-agent.sh" in plan.manual_command
        assert "LINK42_SERVER_URL=https://panel.example:8443" in plan.manual_command
        assert "old.example" not in plan.manual_command
        (release / "binary-0.2.0").unlink()
        plan = main.build_agent_upgrade_plan(node, db)
        assert plan.upgrade_mode == "unavailable"
        assert plan.manual_command is None


def run_shell(code, **env):
    return subprocess.run(["sh", "-c", code], env={
        key: value for key, value in {**os.environ, **env}.items()
        if not key.startswith("LINK42_") or key in env
    }, capture_output=True, text=True, timeout=10)


@pytest.mark.parametrize("explicit", ["", "https://new.example:8443/", "http://[2001:db8::1]:8000/"])
def test_agent_installer_resolves_urls_after_restoring_existing_env(tmp_path, explicit):
    script = (ROOT / "deploy/sh/link42-agent.sh").read_text()
    definitions = script.split('if [ "$ACTION" = "--help" ]')[0]
    restoration = script.split('INPUT_LINK42_SERVER_URL="', 1)[1]
    restoration = 'INPUT_LINK42_SERVER_URL="' + restoration.split('\nARCH="', 1)[0]
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "agent.env").write_text(
        "LINK42_SERVER_URL='http://existing.example:8000/'\nLINK42_NODE_ID=2\nLINK42_AGENT_TOKEN=old-token\n"
        "LINK42_RES_BASE_URL=https://old.example/res\n"
    )
    env = {
        "LINK42_ENV_DIR": str(env_dir), "LINK42_INSTALL_DIR": str(tmp_path / "install"),
        "LINK42_AGENT_BIN": str(tmp_path / "bin/agent"),
        "LINK42_SERVER_URL": explicit, "LINK42_NODE_ID": "3", "LINK42_AGENT_TOKEN": "new-token",
        "LINK42_RES_BASE_URL": "https://other.example/res",
    }
    result = run_shell(definitions + restoration + '\nprintf "%s\\n" "$SCRIPT_URL" "$RES_BASE_URL" "$LINK42_NODE_ID" "$LINK42_AGENT_TOKEN"', **env)
    assert result.returncode == 0, result.stderr
    base = (explicit or "http://existing.example:8000").rstrip("/")
    assert result.stdout.splitlines() == [f"{base}/sh/link42-agent.sh", f"{base}/res/link42", "3", "new-token"]


@pytest.mark.parametrize("path", ["deploy/sh/link42-agent.sh", "udp2raw_sh/udp2raw.sh"])
@pytest.mark.parametrize("address", ["", "https://host/path", "https://host?query", "https://user@host", "http://host:0", "http://host:65536", "https://host';touch /tmp/bad"])
def test_shell_download_configuration_rejects_invalid_urls(path, address):
    script = (ROOT / path).read_text()
    function = "configure_download_urls() {" + script.split("configure_download_urls() {", 1)[1].split("\n}", 1)[0] + "\n}"
    result = run_shell('fail() { echo "$*" >&2; exit 1; }; die() { fail "$@"; };\n' + function + "\nconfigure_download_urls", LINK42_SERVER_URL=address)
    assert result.returncode != 0


def test_udp2raw_saved_menu_uses_original_controller(tmp_path):
    script = (ROOT / "udp2raw_sh/udp2raw.sh").read_text()
    definitions = script.rsplit('\nmain "$@"', 1)[0]
    menu_path = tmp_path / "udp2raw-menu"
    definitions = definitions.replace('target="/usr/local/bin/udp2raw-menu"', f'target="{menu_path}"')
    result = run_shell(definitions + "\nconfigure_download_urls\ninstall_menu_command", LINK42_SERVER_URL="https://panel.example:8443/")
    assert result.returncode == 0, result.stderr
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    capture = tmp_path / "url"
    curl.write_text('''#!/bin/sh
printf '%s' "$2" > "$CAPTURE"
printf 'printf "%%s\\n" "$LINK42_SERVER_URL" "$1"' > "$4"
''')
    curl.chmod(0o700)
    result = run_shell(f'sh "{menu_path}"', PATH=f"{fake_bin}:{os.environ['PATH']}", CAPTURE=str(capture),
                       LINK42_SERVER_URL="https://wrong.example", UDP2RAW_SCRIPT_URL="https://old.example/script")
    assert result.returncode == 0, result.stderr
    assert capture.read_text() == "https://panel.example:8443/sh/udp2raw.sh"
    assert result.stdout.splitlines() == ["https://panel.example:8443", "menu"]


@pytest.mark.parametrize("damage", [None, "checksum", "missing-source", "missing-checksum", "missing-platform"])
def test_build_verifier_rejects_incomplete_release(release, damage):
    if damage == "checksum":
        (release / "binary-0.2.0").write_bytes(b"corrupt")
    elif damage == "missing-source":
        (release / "source-0.2.0").unlink()
    elif damage == "missing-checksum":
        (release / "binary-0.2.0.sha256").unlink()
    elif damage == "missing-platform":
        path = release / "manifest.json"
        data = json.loads(path.read_text())
        del data["releases"]["0.2.0"]["assets"]["openwrt-source"]
        path.write_text(json.dumps(data))
    result = subprocess.run([sys.executable, str(ROOT / "scripts/agent/verify-release-assets.py"), str(release)], capture_output=True, text=True, timeout=10)
    assert result.returncode == (0 if damage is None else 1), result.stderr


def test_old_url_settings_do_not_break_env_loading(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("LINK42_AGENT_INSTALL_SCRIPT_URL=https://old.example/script\nLINK42_AGENT_RES_BASE_URL=https://old.example/res\n")
    settings = Settings(_env_file=env_file)
    assert settings.agent_install_script_url == "https://old.example/script"
    assert settings.agent_res_base_url == "https://old.example/res"


@pytest.mark.parametrize("script", ["deploy/sh/link42-agent.sh", "udp2raw_sh/udp2raw.sh"])
def test_script_help_needs_no_controller_or_download_tools(tmp_path, script):
    # Only allow help text output; root detection and download tools are absent.
    (tmp_path / "cat").symlink_to("/bin/cat")
    result = subprocess.run(["/bin/sh", str(ROOT / script), "--help"], env={"PATH": str(tmp_path)},
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("version", ["latest", "0.2.0"])
@pytest.mark.parametrize("checksum_ok", [True, False])
def test_installer_downloads_only_controller_assets_and_verifies_before_replacing(tmp_path, version, checksum_ok):
    script = (ROOT / "deploy/sh/link42-agent.sh").read_text()
    definitions = script.split('if [ "$ACTION" = "--help" ]')[0]
    downloader = "download_agent() {" + script.split("download_agent() {", 1)[1].split("\nrollback_source_install()", 1)[0]
    binary = tmp_path / "release-binary"
    binary.write_bytes(b"#!/bin/sh\necho 0.2.0\n")
    checksum = tmp_path / "release-sha"
    checksum.write_text((hashlib.sha256(binary.read_bytes()).hexdigest() if checksum_ok else "0" * 64) + "  agent\n")
    target = tmp_path / "bin/agent"
    target.parent.mkdir()
    target.write_text("old agent")
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    capture = tmp_path / "urls"
    curl = fake_bin / "curl"
    curl.write_text('''#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  case "$1" in
    http://*|https://*) url="$1" ;;
    -o) shift; output="$1" ;;
  esac
  shift
done
printf '%s\\n' "$url" >> "$CAPTURE"
case "$url" in
  *.sha256) cp "$CHECKSUM" "$output" ;;
  *) cp "$BINARY" "$output" ;;
esac
''')
    curl.chmod(0o700)
    code = definitions + downloader + '''
stop_existing_service() { :; }
AGENT_INSTALL_MODE=binary
AGENT_FILE=link42-agent-linux-x64
configure_download_urls
download_agent
'''
    result = run_shell(code, LINK42_SERVER_URL="https://panel.example:8443/", LINK42_AGENT_VERSION=version,
                       LINK42_INSTALL_DIR=str(tmp_path / "install"), LINK42_AGENT_BIN=str(target),
                       LINK42_RES_BASE_URL="https://old.example/res", PATH=f"{fake_bin}:{os.environ['PATH']}",
                       CAPTURE=str(capture), BINARY=str(binary), CHECKSUM=str(checksum), TMPDIR=str(tmp_path))
    assert result.returncode == (0 if checksum_ok else 1), result.stderr
    prefix = "https://panel.example:8443/res/link42/" + ("" if version == "latest" else f"{version}/")
    url = prefix + "link42-agent-linux-x64"
    assert capture.read_text().splitlines() == [url, url + ".sha256"]
    assert target.read_bytes() == (binary.read_bytes() if checksum_ok else b"old agent")
