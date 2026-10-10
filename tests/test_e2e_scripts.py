"""Execute E2E shell logic with isolated files and fake host commands."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_controller_container_runs_uvicorn_as_pid_one():
    """容器停止时 uvicorn 必须直接接收 Docker 的终止信号。"""

    dockerfile = (ROOT / "Dockerfile.controller").read_text()
    assert 'CMD ["uvicorn", "link42_api.main:app"' in dockerfile
    assert 'CMD ["sh", "-c"' not in dockerfile
    assert '"--proxy-headers"' in dockerfile
    assert '"--timeout-keep-alive", "65"' in dockerfile


def test_controller_compose_exposes_forwarded_proxy_configuration():
    """Compose 部署必须能同时配置 Uvicorn 和应用层的可信代理。"""

    compose = (ROOT / "deploy/docker-compose.yml").read_text()
    assert "FORWARDED_ALLOW_IPS" in compose
    assert "LINK42_TRUSTED_PROXY_CIDRS" in compose


def shell(script, code, tmp_path, **overrides):
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith("LINK42_")
    }
    env.update({
        "LINK42_REAL_ENV_FILE": str(tmp_path / "absent.env"),
        "LINK42_REAL_RUN_DIR": str(tmp_path / "real-run"),
        "LINK42_SMOKE_RUN_DIR": str(tmp_path / "smoke-run"),
        "PYTHON_BIN": sys.executable,
        **{key: str(value) for key, value in overrides.items()},
    })
    return subprocess.run(
        ["bash", "-c", 'source "$1"\n' + code, "test-shell", str(ROOT / script)],
        env=env, capture_output=True, text=True, timeout=10,
    )


def marked_run(tmp_path):
    path = tmp_path / "real-run"
    path.mkdir(mode=0o700)
    (path / ".link42-real-e2e").write_text("Link42 real E2E run directory\n")
    return path


def test_remote_agent_script_preserves_shell_metacharacters(tmp_path):
    agent_dir = tmp_path / "remote 'quoted' directory"
    agent_dir.mkdir()
    executed = tmp_path / "unexpected-command"
    value = f"quoted' $HOME $(touch {executed}) `touch {executed}`\nSH\n"
    result = shell(
        "scripts/real-e2e/up.sh",
        'remote_agent_script "$TEST_AGENT_DIR" "$TEST_AGENT_TOKEN"', tmp_path,
        LINK42_REAL_REMOTE_AGENT_URL=value,
        REMOTE_NODE_ID="2", TEST_AGENT_DIR=agent_dir, TEST_AGENT_TOKEN=value,
    )
    assert result.returncode == 0, result.stderr
    script = agent_dir / "start-agent.sh"
    script.write_text(result.stdout)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python = bin_dir / "python3"
    python.write_text(
        f"#!{sys.executable}\nimport os,json\n"
        "print(json.dumps({k: os.environ[k] for k in "
        "['LINK42_SERVER_URL','LINK42_NODE_ID','LINK42_AGENT_TOKEN','PYTHONPATH']}))\n"
    )
    python.chmod(0o700)
    run = subprocess.run(
        ["sh", str(script)], capture_output=True, text=True, timeout=5,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
    )
    assert run.returncode == 0, run.stderr
    data = json.loads(run.stdout)
    assert data["LINK42_AGENT_TOKEN"] == data["LINK42_SERVER_URL"] == value
    assert data["LINK42_NODE_ID"] == "2"
    assert data["PYTHONPATH"] == "apps/agent:packages"
    assert not executed.exists()


def test_e2e_state_round_trips_quoted_values_with_private_permissions(tmp_path):
    run_dir = marked_run(tmp_path)
    result = shell(
        "scripts/real-e2e/up.sh",
        'write_state; source "$RUN_DIR/state.env"; printf "%s" "$LINK42_REAL_WEB_TOKEN"',
        tmp_path, WEB_TOKEN="token' $HOME\nsecond line", LOCAL_NODE_ID=1,
        REMOTE_NODE_ID=2, LOCAL_AGENT_PID=123, REMOTE_AGENT_PID=456,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "token' $HOME\nsecond line"
    assert stat.S_IMODE((run_dir / "state.env").stat().st_mode) == 0o600


@pytest.mark.parametrize("pid", ["0", "1", "-1", "-123", "123 456", "abc"])
def test_cleanup_rejects_process_groups_and_invalid_pids(tmp_path, pid):
    marked_run(tmp_path)
    result = shell(
        "scripts/real-e2e/down.sh",
        'kill() { echo "unexpected kill"; }; stop_pid "$TEST_PID"',
        tmp_path, TEST_PID=pid,
    )
    assert result.returncode != 0
    assert "refusing invalid process ID" in result.stderr
    assert "unexpected kill" not in result.stdout


@pytest.mark.parametrize("iface", ["*", "../../bad", "-bad", ".", "..", "wg0@other"])
def test_cleanup_rejects_invalid_interface_lists_before_host_commands(tmp_path, iface):
    marked_run(tmp_path)
    result = shell(
        "scripts/real-e2e/down.sh",
        'cleanup_local_middleware() { echo "unexpected cleanup"; }; main',
        tmp_path, LINK42_REAL_LOCAL_WG_IFACES=iface,
    )
    assert result.returncode != 0
    assert "invalid test interface name" in result.stderr
    assert "unexpected cleanup" not in result.stdout


def test_cleanup_expands_only_the_requested_interface_backup_glob(tmp_path):
    marked_run(tmp_path)
    result = shell(
        "scripts/real-e2e/down.sh", r'''
wg-quick() { :; }; systemctl() { :; }; ip() { :; }
rm() { printf '%s\n' "$@"; }
cleanup_local_iface l42audit
''', tmp_path,
    )
    assert result.returncode == 0, result.stderr
    # The scoped removal must allow expansion; the interface list itself still
    # uses noglob, so '*' hints cannot become unrelated file/interface names.
    assert "set +f" in (ROOT / "scripts/real-e2e/down.sh").read_text()
    assert "/etc/wireguard/l42audit.conf" in result.stdout


@pytest.mark.parametrize("script", ["scripts/real-e2e/up.sh", "scripts/smoke-real-local.sh"])
def test_e2e_bootstrap_uses_isolated_password_file_and_valid_default_database(tmp_path, script):
    fake_uvicorn = tmp_path / "uvicorn"
    captured = tmp_path / "controller-env.json"
    fake_uvicorn.write_text(
        f"#!{sys.executable}\nimport os,json\nfrom pathlib import Path\n"
        "config = Path(os.environ['LINK42_CONFIG_DIR'])\n"
        "config.mkdir(parents=True)\n"
        "(config / 'initial-admin-password').write_text('username=pmman\\npassword=file-password\\n')\n"
        "Path(os.environ['TEST_CAPTURED']).write_text(json.dumps(dict(os.environ)))\n"
        "print('Controller started; no password in logs')\n"
    )
    fake_uvicorn.chmod(0o700)
    code = r'''
id() { printf '0'; }
require() { :; }; require_command() { :; }
cleanup_interface() { :; }; cleanup() { :; }
wait_for_api() {
  for ((i=0; i<100; i++)); do
    [[ -f "$RUN_DIR/controller-config/initial-admin-password" ]] && return 0
    sleep 0.02
  done
  return 1
}
curl() {
  "$PYTHON_BIN" -c 'import json,sys
assert json.loads(sys.argv[-1]) == {"username":"pmman","password":"file-password"}
print(json.dumps({"token":"login-ok"}))' "$@"
}
api() { [[ "$WEB_TOKEN" == "login-ok" ]] || return 24; return 23; }
main
'''
    result = shell(
        script, code, tmp_path, UVICORN_BIN=fake_uvicorn, TEST_CAPTURED=captured,
        LINK42_REAL_LOCAL_ENDPOINT="192.0.2.1", LINK42_REAL_REMOTE_ENDPOINT="192.0.2.2",
        LINK42_REAL_REMOTE_AGENT_URL="http://controller.example",
    )
    assert result.returncode == 23, result.stderr
    controller_env = json.loads(captured.read_text())
    run_dir = tmp_path / ("real-run" if "real-e2e/" in script else "smoke-run")
    assert controller_env["LINK42_DATABASE_URL"] == f"sqlite:///{run_dir}/link42.db"
    assert controller_env["LINK42_CONFIG_DIR"] == str(run_dir / "controller-config")
    assert controller_env["LINK42_MASTER_KEY_FILE"] == str(run_dir / "controller-config/master.key")
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700


@pytest.mark.parametrize("iface", ["eth0", "wg0", "../../bad", "l42smoke-too-long", "-invalid"])
def test_smoke_rejects_interfaces_outside_its_dedicated_prefix(tmp_path, iface):
    result = shell("scripts/smoke-real-local.sh", 'validate_iface_name "$TEST_IFACE"',
                   tmp_path, TEST_IFACE=iface)
    assert result.returncode != 0
    assert "invalid smoke interface name" in result.stderr


def test_publish_verification_reads_password_file_instead_of_logs():
    """发布验证必须使用受限引导文件，避免依赖已移除的日志密码。"""

    script = (ROOT / "scripts/controller/publish-dockerhub.sh").read_text()
    assert "/link42/config/initial-admin-password" in script
    assert 'docker exec "$TEST_CONTAINER"' in script
    assert 'docker logs "$TEST_CONTAINER"' not in script.split('password="', 1)[-1].split('login_payload=', 1)[0]


def test_agent_bootstrap_caps_release_and_checksum_downloads():
    """首次安装也必须限制不可信发布响应的落盘大小。"""

    script = (ROOT / "deploy/sh/link42-agent.sh").read_text()
    assert "MAX_AGENT_DOWNLOAD_SIZE=$((512 * 1024 * 1024))" in script
    assert 'curl -fL --max-filesize "$MAX_AGENT_DOWNLOAD_SIZE"' in script
    assert 'downloaded_size="$(wc -c < "$tmp_file")"' in script
    assert 'curl -fsL --max-filesize 4096' in script
    assert 'checksum_size="$(wc -c < "$tmp_sha")"' in script
