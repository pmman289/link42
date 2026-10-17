"""Run the complete installer entrypoint, stopping before host mutations."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/sh/link42-agent.sh"


def installer_environment(tmp_path):
    fake_bin = tmp_path / "commands"
    fake_bin.mkdir()
    commands = {
        "id": "echo 0",
        "uname": "echo x86_64",
        "ldd": "echo 'glibc 2.36'",
        "systemctl": "exit 0",
        "wg": "exit 1",
        "curl": "echo unexpected-download >&2; exit 1",
        # Reach dependency installation, but do not install packages, download
        # an Agent, stop a service or write any system service definitions.
        "apt-get": "echo dependency-stage-reached >&2; exit 37",
    }
    for name, body in commands.items():
        path = fake_bin / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o700)
    env = {key: value for key, value in os.environ.items() if not key.startswith("LINK42_")}
    env.update({
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "LINK42_INSTALL_DIR": str(tmp_path / "agent"),
        "LINK42_AGENT_BIN": str(tmp_path / "bin/link42-agent"),
        "LINK42_ENV_DIR": str(tmp_path / "env"),
        "LINK42_WIREGUARD_DIR": str(tmp_path / "wireguard"),
        "LINK42_GRE_DIR": str(tmp_path / "gre"),
        "LINK42_UDP2RAW_BIN": str(tmp_path / "bin/udp2raw"),
        "LINK42_MIMIC_SYSTEM_CONFIG_DIR": str(tmp_path / "mimic"),
        "LINK42_AGENT_SERVICE_NAME": "link42-installer-entrypoint-test",
    })
    return env


@pytest.mark.parametrize("existing_install", [False, True])
@pytest.mark.parametrize("args", [[], ["install"]])
def test_full_installer_reaches_dependency_stage(tmp_path, existing_install, args):
    env = installer_environment(tmp_path)
    credentials = {
        "LINK42_SERVER_URL": "https://controller.example:8443/",
        "LINK42_NODE_ID": "1",
        "LINK42_AGENT_TOKEN": "isolated-test-token",
    }
    if existing_install:
        env_dir = Path(env["LINK42_ENV_DIR"])
        env_dir.mkdir()
        (env_dir / "agent.env").write_text("".join(f"{key}='{value}'\n" for key, value in credentials.items()))
    else:
        env.update(credentials)
    result = subprocess.run(["sh", str(SCRIPT), *args], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert "installing dependencies" in result.stdout
    assert "dependency-stage-reached" in result.stderr
    assert "required tools are missing" in result.stderr
    assert "unexpected-download" not in result.stderr
    assert not Path(env["LINK42_AGENT_BIN"]).exists()


def test_full_installer_reports_missing_settings_instead_of_silent_exit(tmp_path):
    result = subprocess.run(["sh", str(SCRIPT)], env=installer_environment(tmp_path),
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 1
    assert "missing required environment variable: LINK42_SERVER_URL" in result.stderr
    assert "dependency-stage-reached" not in result.stderr


@pytest.mark.parametrize("directory", ["env", 'env with spaces %n "quotes"'])
def test_systemd_unit_loads_literal_environment_file_path(tmp_path, directory):
    analyze = shutil.which("systemd-analyze")
    if not analyze:
        pytest.skip("systemd-analyze is needed to validate the real unit parser")
    result, unit, env_file = render_systemd_unit(tmp_path, directory=directory)
    assert result.returncode == 0, result.stderr
    expected = str(env_file).replace("%", "%%")
    assert f"EnvironmentFile={expected}\n" in unit.read_text()
    verification = subprocess.run([analyze, "verify", str(unit)], capture_output=True, text=True, timeout=10)
    assert verification.returncode == 0, verification.stderr
    assert "EnvironmentFile=" not in verification.stderr


def render_systemd_unit(tmp_path, *, directory="env", active=True):
    script = SCRIPT.read_text()
    definitions = script.split('if [ "$ACTION" = "--help" ]')[0]
    function = "install_systemd_service() {" + script.split("\ninstall_systemd_service() {", 1)[1].split("\ninstall_openrc_service()", 1)[0]
    function = function.replace('"/etc/systemd/system/$SERVICE_NAME.service"', '"$TEST_UNIT_PATH"')
    fake_bin = tmp_path / "commands"
    fake_bin.mkdir()
    for name, body in {
        "systemctl": 'if [ "$1" = is-active ]; then exit "$TEST_ACTIVE_STATUS"; fi',
        "sleep": ":",
    }.items():
        path = fake_bin / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o700)
    binary = tmp_path / "agent"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o700)
    env_file = tmp_path / directory / "agent.env"
    env_file.parent.mkdir()
    env_file.write_text("LINK42_SERVER_URL=http://controller:8000\n")
    unit = tmp_path / "link42-installer-test.service"
    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}",
           "TEST_UNIT_PATH": str(unit), "TEST_ENV_FILE": str(env_file),
           "TEST_BIN_PATH": str(binary), "TEST_ACTIVE_STATUS": "0" if active else "1"}
    code = definitions + function + '''
ENV_FILE="$TEST_ENV_FILE"
BIN_PATH="$TEST_BIN_PATH"
install_systemd_service
printf 'installation-succeeded\\n'
'''
    result = subprocess.run(["sh", "-c", code], env=env, capture_output=True, text=True, timeout=5)
    return result, unit, env_file


def test_systemd_startup_failure_is_reported_as_install_failure(tmp_path):
    result, _, _ = render_systemd_unit(tmp_path, active=False)
    assert result.returncode == 1
    assert "did not become healthy" in result.stderr
    assert "installation-succeeded" not in result.stdout


def test_uninstall_discovers_percent_path_from_systemd_unit(tmp_path):
    result, unit, env_file = render_systemd_unit(tmp_path, directory="custom %n env")
    assert result.returncode == 0, result.stderr
    script = SCRIPT.read_text()
    definitions = script.split('if [ "$ACTION" = "--help" ]')[0]
    function = "discover_uninstall_env_file() {" + script.split("\ndiscover_uninstall_env_file() {", 1)[1].split("\nif [ \"$(id -u)\"", 1)[0]
    function = function.replace('unit_file="/etc/systemd/system/$SERVICE_NAME.service"', 'unit_file="$TEST_UNIT_PATH"')
    code = definitions + function + '''
ACTION=uninstall
INPUT_LINK42_ENV_DIR=""
discover_uninstall_env_file
printf '%s' "$ENV_DIR"
'''
    result = subprocess.run(["sh", "-c", code], env={**os.environ, "TEST_UNIT_PATH": str(unit)},
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout == str(env_file.parent)


@pytest.mark.parametrize("control", ["\n", "\r", "\t"])
def test_full_installer_rejects_control_characters_in_paths(tmp_path, control):
    env = installer_environment(tmp_path)
    env["LINK42_ENV_DIR"] = str(tmp_path / ("env" + control + "injected"))
    result = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 1
    assert "installation paths must not contain control characters" in result.stderr
