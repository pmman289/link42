import json
import os
from pathlib import Path
import subprocess

import pytest

from link42_agent import upgrade


def test_schedule_systemd_upgrade_uses_transient_unit(monkeypatch, tmp_path):
    script = tmp_path / "upgrade.sh"
    monkeypatch.setattr(upgrade, "UPGRADE_SCRIPT", script)
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: "/usr/bin/systemd-run")
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs)))

    upgrade.schedule_upgrade_script("systemd")

    assert calls == [(([
        "systemd-run", "--unit=link42-agent-upgrade", "--on-active=1", str(script),
    ],), {"check": True, "timeout": 15})]


@pytest.mark.parametrize("manager", ["systemd", "openwrt-uci"])
def test_schedule_upgrade_fallback_detaches_process(monkeypatch, tmp_path, manager):
    script = tmp_path / "upgrade's script.sh"
    monkeypatch.setattr(upgrade, "UPGRADE_SCRIPT", script)
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: None)
    calls = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: calls.append((args, kwargs)))

    upgrade.schedule_upgrade_script(manager)

    assert calls == [(([
        "sh", "-c", f"sleep 2; exec sh {upgrade.shell_quote(str(script))}",
    ],), {
        "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "start_new_session": True,
    })]


def executable(path, content):
    path.write_text("#!/bin/sh\nset -eu\n" + content)
    path.chmod(0o755)


@pytest.fixture
def upgrade_paths(tmp_path, monkeypatch):
    for name, filename in [("UPGRADE_SCRIPT", "upgrade.sh"), ("STATE_FILE", "state.json"), ("NEW_BINARY", "new")]:
        monkeypatch.setattr(upgrade, name, tmp_path / filename)
    monkeypatch.setattr(upgrade, "UPGRADE_DIR", tmp_path)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    executable(binaries / "sleep", "exit 0\n")
    monkeypatch.setenv("PATH", f"{binaries}:/usr/bin:/bin")
    return tmp_path, binaries


@pytest.mark.parametrize("failure", ["none", "install", "stop", "replace", "start", "health"])
def test_systemd_upgrade_recovers_service_and_binary(upgrade_paths, monkeypatch, failure):
    root, binaries = upgrade_paths
    installed = root / "installed"
    installed.write_text("old")
    upgrade.NEW_BINARY.write_text("new")
    running = root / "running"
    running.touch()
    monkeypatch.setenv("FAIL_PHASE", failure)
    monkeypatch.setenv("TEST_ROOT", str(root))
    executable(binaries / "systemctl", '''
case "$1" in
  stop) rm -f "$TEST_ROOT/running"; [ "$FAIL_PHASE" != stop ] ;;
  start)
    if [ "$FAIL_PHASE" = start ] && [ "$(cat "$TEST_ROOT/installed")" = new ]; then exit 1; fi
    touch "$TEST_ROOT/running" ;;
  is-active) [ "$FAIL_PHASE" != health ] ;;
esac
''')
    executable(binaries / "install", '''
[ "$FAIL_PHASE" != install ] || exit 1
exec /usr/bin/install "$@"
''')
    executable(binaries / "mv", '''
if [ "$FAIL_PHASE" = replace ] && [ "$3" = "$TEST_ROOT/installed" ] && [ "$(cat "$2")" = new ]; then exit 1; fi
exec /usr/bin/mv "$@"
''')
    upgrade.write_systemd_upgrade_script("link42-agent", installed)
    result = subprocess.run(["sh", str(upgrade.UPGRADE_SCRIPT)], capture_output=True, timeout=10)
    assert result.returncode == (0 if failure == "none" else 1), result.stderr
    assert installed.read_text() == ("new" if failure == "none" else "old")
    assert running.exists()
    assert json.loads(upgrade.STATE_FILE.read_text())["status"] == ("healthy" if failure == "none" else "rolled_back")
    assert not list(root.glob("installed.upgrade.*"))


@pytest.mark.parametrize("failure", ["none", "stop", "backup", "replace", "start", "health"])
def test_openwrt_upgrade_recovers_source_and_service(upgrade_paths, monkeypatch, failure):
    root, binaries = upgrade_paths
    source = root / "source"
    source.mkdir()
    (source / "version").write_text("old")
    staged = root / "staged"
    staged.mkdir()
    (staged / "version").write_text("new")
    running = root / "running"
    running.touch()
    monkeypatch.setenv("FAIL_PHASE", failure)
    monkeypatch.setenv("TEST_ROOT", str(root))
    service = binaries / "agent-service"
    executable(service, '''
case "$1" in
  stop) rm -f "$TEST_ROOT/running"; [ "$FAIL_PHASE" != stop ] ;;
  start)
    if [ "$FAIL_PHASE" = start ] && [ "$(cat "$TEST_ROOT/source/version")" = new ]; then exit 1; fi
    touch "$TEST_ROOT/running" ;;
  status) [ "$FAIL_PHASE" != health ] ;;
esac
''')
    executable(binaries / "mv", '''
if [ "$FAIL_PHASE" = backup ] && [ "$1" = "$TEST_ROOT/source" ]; then exit 1; fi
if [ "$FAIL_PHASE" = replace ] && [ "$1" = "$TEST_ROOT/staged" ]; then exit 1; fi
exec /usr/bin/mv "$@"
''')
    upgrade.write_openwrt_upgrade_script("link42-agent", source, staged, "0.6.21")
    content = upgrade.UPGRADE_SCRIPT.read_text().replace("'/etc/init.d/link42-agent'", upgrade.shell_quote(str(service)))
    upgrade.UPGRADE_SCRIPT.write_text(content)
    result = subprocess.run(["sh", str(upgrade.UPGRADE_SCRIPT)], capture_output=True, timeout=10)
    assert result.returncode == (0 if failure == "none" else 1), result.stderr
    assert (source / "version").read_text() == ("new" if failure == "none" else "old")
    assert running.exists()
    assert json.loads(upgrade.STATE_FILE.read_text())["status"] == ("healthy" if failure == "none" else "rolled_back")


@pytest.mark.parametrize("reported", ["0.6.21", "0.6.210", "error: expected 0.6.21"])
def test_binary_version_requires_exact_output(tmp_path, reported):
    binary = tmp_path / "agent"
    executable(binary, f"printf '%s\\n' {upgrade.shell_quote(reported)}\n")
    if reported == "0.6.21":
        upgrade.verify_binary_version(binary, "0.6.21", ["--version"])
    else:
        with pytest.raises(RuntimeError, match="version mismatch"):
            upgrade.verify_binary_version(binary, "0.6.21", ["--version"])


def test_state_write_replaces_symlink_without_overwriting_target(upgrade_paths):
    root, _ = upgrade_paths
    other = root / "other"
    other.write_text("keep")
    upgrade.STATE_FILE.symlink_to(other)
    upgrade.write_state({"status": "verified"})
    assert other.read_text() == "keep"
    assert json.loads(upgrade.STATE_FILE.read_text()) == {"status": "verified"}
    assert upgrade.STATE_FILE.stat().st_mode & 0o777 == 0o600
