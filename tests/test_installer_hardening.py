"""Exercise bootstrap failure paths without installing host services."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
AGENT = (ROOT / "deploy/sh/link42-agent.sh").read_text()
UDP = (ROOT / "udp2raw_sh/udp2raw.sh").read_text().rsplit('\nmain "$@"', 1)[0]
AGENT_DEFS = AGENT.split('if [ "$ACTION" = "--help" ]')[0] + AGENT[AGENT.index("\ndependency_install_failed() {"):AGENT.index('\nlog "installing dependencies"')]


def run(code, tmp_path, *, input=None, **overrides):
    env = {key: value for key, value in os.environ.items() if not key.startswith("LINK42_")}
    env.update({"LINK42_INSTALL_DIR": str(tmp_path / "install"), "LINK42_ENV_DIR": str(tmp_path / "env"),
                "LINK42_AGENT_BIN": str(tmp_path / "bin/agent"), "LINK42_WIREGUARD_DIR": str(tmp_path / "wg"),
                "LINK42_SERVER_URL": "https://panel.example:8443/", "LINK42_NODE_ID": "1",
                "LINK42_AGENT_TOKEN": "test-token", **{key: str(value) for key, value in overrides.items()}})
    return subprocess.run(["/bin/sh", "-c", code], env=env, input=input, capture_output=True, text=True, timeout=10)


def fake_command(directory, name, body):
    directory.mkdir(exist_ok=True)
    path = directory / name
    path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
    path.chmod(0o700)
    return path


@pytest.mark.parametrize("runtime", [False, True])
def test_env_reader_round_trips_literals_without_executing_them(tmp_path, runtime):
    marker = tmp_path / "executed"
    value = f"a'b \\ \" $HOME $(touch {marker}) `touch {marker}`"
    code = AGENT_DEFS + '''
LINK42_AGENT_TOKEN="$TEST_VALUE"
write_env_file
unset LINK42_AGENT_TOKEN
'''
    if runtime:
        code += '. "$ENV_DIR/load-env.sh"\n'
    code += 'load_env_file "$ENV_FILE"\nprintf "%s" "$LINK42_AGENT_TOKEN"\n'
    result = run(code, tmp_path, TEST_VALUE=value)
    assert result.returncode == 0, result.stderr
    assert result.stdout == value
    assert not marker.exists()


def test_env_reader_ignores_shell_commands_and_unknown_variables(tmp_path):
    marker = tmp_path / "executed"
    env_file = tmp_path / "untrusted.env"
    env_file.write_text(f"touch {marker}\nLINK42_AGENT_TOKEN=$(touch {marker})\nPATH=/invalid\n")
    result = run(AGENT_DEFS + 'load_env_file "$TEST_ENV"\nprintf "%s" "$LINK42_AGENT_TOKEN"', tmp_path, TEST_ENV=env_file)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"$(touch {marker})"
    assert not marker.exists()


@pytest.mark.parametrize("definitions", [AGENT_DEFS, UDP], ids=["agent", "udp2raw"])
def test_http_scheme_is_case_insensitive(tmp_path, definitions):
    result = run(definitions + '\nconfigure_download_urls\nprintf "%s" "$LINK42_SERVER_URL"', tmp_path,
                 LINK42_SERVER_URL="HtTpS://Panel.Example:8443/")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "https://Panel.Example:8443"


@pytest.mark.parametrize("definitions,function", [(AGENT_DEFS, "download_file"), (UDP, "download")], ids=["agent", "udp2raw"])
def test_wget_transfer_cannot_exceed_file_limit(tmp_path, definitions, function):
    commands = tmp_path / "commands"
    commands.mkdir()
    wget = commands / "wget"
    wget.write_text(f"#!{sys.executable}\nimport sys\na=sys.argv; i=next(i for i,v in enumerate(a) if v in ('-O','-qO')); open(a[i+1],'wb').write(b'x'*65536)\n")
    wget.chmod(0o700)
    output = tmp_path / "download"
    result = run(definitions + f'\n{function} https://panel.example/test "$OUTPUT" 4096', tmp_path,
                 PATH=commands, OUTPUT=output)
    assert result.returncode != 0
    assert output.stat().st_size <= 4096


CURL_STUB = '''
while [ "$#" -gt 0 ]; do
  case "$1" in https://*) url="$1" ;; -o) shift; output="$1" ;; esac
  shift
done
case "$url" in *.sha256) cp "$CHECKSUM" "$output" ;; *) cp "$PAYLOAD" "$output" ;; esac
'''


@pytest.mark.parametrize("checksum_ok", [False, True])
def test_udp2raw_checks_before_replacing_running_binary(tmp_path, checksum_ok):
    target = tmp_path / "udp2raw"
    shutil.copyfile(shutil.which("sleep"), target)
    target.chmod(0o700)
    old_bytes = target.read_bytes()
    payload = tmp_path / "payload"
    payload.write_bytes(Path(shutil.which("true")).read_bytes())
    checksum = tmp_path / "checksum"
    checksum.write_text((hashlib.sha256(payload.read_bytes()).hexdigest() if checksum_ok else "0" * 64) + "  binary\n")
    commands = tmp_path / "commands"
    fake_command(commands, "curl", CURL_STUB)
    process = subprocess.Popen([str(target), "30"])
    try:
        result = run(UDP + '\nINSTALL_BIN="$TARGET"\ninstall_udp2raw_bin', tmp_path,
                     PATH=f"{commands}:{os.environ['PATH']}", UDP2RAW_BIN="udp2raw_amd64",
                     TARGET=target, PAYLOAD=payload, CHECKSUM=checksum, TMPDIR=tmp_path)
        assert result.returncode == (0 if checksum_ok else 1), result.stderr
        assert target.read_bytes() == (payload.read_bytes() if checksum_ok else old_bytes)
        assert process.poll() is None
        assert not list(tmp_path.glob("tmp.*"))
        assert not list(tmp_path.glob(".udp2raw.*"))
    finally:
        process.terminate()
        process.wait(timeout=5)


@pytest.mark.parametrize("side", ["server", "client"])
def test_menu_password_shell_syntax_stays_literal(tmp_path, side):
    marker = tmp_path / "executed"
    password = f"a'b $HOME $(touch {marker}) `touch {marker}`"
    inputs = ["23002", "127.0.0.1", "51820", password, "faketcp", "xor", "n"]
    code = UDP + f'\nargs="$(build_{side}_args)"\neval "set -- $args"\n' + 'printf "%s\\n" "$@"'
    result = run(code, tmp_path, input="\n".join(inputs) + "\n")
    assert result.returncode == 0, result.stderr
    assert password in result.stdout.splitlines()
    assert not marker.exists()


@pytest.mark.parametrize("field", [1, 4, 5])
def test_menu_rejects_invalid_host_and_modes(tmp_path, field):
    marker = tmp_path / "executed"
    inputs = ["23002", "127.0.0.1", "51820", "key", "faketcp", "xor", "n"]
    inputs[field] = f"x;touch {marker}"
    result = run(UDP + '\nargs="$(build_server_args)"\neval "set -- $args"', tmp_path, input="\n".join(inputs) + "\n")
    assert result.returncode != 0
    assert not marker.exists()


def make_release(tmp_path, source):
    payload = tmp_path / "release"
    if source:
        with tarfile.open(payload, "w:gz") as archive:
            archive.addfile(tarfile.TarInfo("apps/agent/link42_agent/__init__.py"), io.BytesIO(b""))
            data = b"print('0.2.0')\n"
            info = tarfile.TarInfo("apps/agent/link42_agent/main.py")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    else:
        payload.write_text("#!/bin/sh\necho 0.2.0\n")
    checksum = tmp_path / "checksum"
    checksum.write_text(hashlib.sha256(payload.read_bytes()).hexdigest() + "  release\n")
    return payload, checksum


@pytest.mark.parametrize("source", [False, True])
@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("failure", ["health", "start", "none"])
def test_full_systemd_install_rolls_back_or_commits(tmp_path, source, existing, failure):
    payload, checksum = make_release(tmp_path, source)
    commands = tmp_path / "commands"
    for name, body in {"id": "echo 0", "uname": "echo x86_64", "ldd": "echo " + ("musl" if source else "glibc"),
                       "apt-get": "exit 0", "wg": "exit 0", "sleep": ":", "curl": CURL_STUB}.items():
        fake_command(commands, name, body)
    fake_command(commands, "systemctl", '''
printf '%s\\n' "$*" >> "$CALLS"
case "$1" in
  is-active)
    if [ -e "$STARTED" ]; then [ "$FAILURE" != health ]; else [ "$EXISTING" = 1 ]; fi ;;
  is-enabled) [ "$EXISTING" = 1 ] ;;
  enable)
    if [ "${2:-}" = --now ]; then touch "$STARTED"; [ "$FAILURE" != start ]; fi ;;
esac
''')
    script = tmp_path / "installer.sh"
    script.write_text(AGENT.replace('"/etc/systemd/system/$SERVICE_NAME.service"', '"$TEST_UNIT"'))
    unit = tmp_path / "agent.service"
    target = tmp_path / "bin/agent"
    target.parent.mkdir()
    env_file = tmp_path / "env/agent.env"
    env_file.parent.mkdir()
    source_dir = tmp_path / "install/src"
    if existing:
        target.write_text("#!/bin/sh\necho 0.1.0\n")
        target.chmod(0o700)
        unit.write_text("old service\n")
        env_file.write_text("LINK42_AGENT_TOKEN='old-token'\n")
        if source:
            source_dir.mkdir(parents=True)
            (source_dir / "old.py").write_text("old source")
    result = run('sh "$TEST_SCRIPT" install', tmp_path,
                 PATH=f"{commands}:{os.environ['PATH']}", TEST_SCRIPT=script, TEST_UNIT=unit,
                 PAYLOAD=payload, CHECKSUM=checksum, LINK42_AGENT_VERSION="0.2.0",
                 CALLS=tmp_path / "calls", STARTED=tmp_path / "started", FAILURE=failure,
                 EXISTING="1" if existing else "0", TMPDIR=tmp_path)
    assert result.returncode == (0 if failure == "none" else 1), (result.stdout, result.stderr)
    if failure == "none":
        assert "version: 0.2.0" in result.stdout
        assert "test-token" in env_file.read_text()
        assert "ExecStart=" in unit.read_text()
    elif existing:
        assert target.read_text() == "#!/bin/sh\necho 0.1.0\n"
        assert env_file.read_text() == "LINK42_AGENT_TOKEN='old-token'\n"
        assert unit.read_text() == "old service\n"
        assert "start link42-agent.service" in (tmp_path / "calls").read_text()
        if source:
            assert (source_dir / "old.py").read_text() == "old source"
    else:
        assert not target.exists() and not env_file.exists() and not unit.exists()
        assert not source_dir.exists()
    assert not list(tmp_path.glob("install/.rollback.*"))
    assert not (tmp_path / "install/.src.new").exists()
    assert not list(tmp_path.glob("link42-agent.*"))


@pytest.mark.parametrize("node_id", ["0", "00", "-1", "abc", "1;echo x", "1.5"])
def test_invalid_node_id_is_rejected_before_install(tmp_path, node_id):
    start = AGENT.index('INPUT_LINK42_SERVER_URL="')
    restoration = AGENT[start:AGENT.index('\nARCH="', start)]
    result = run(AGENT_DEFS + restoration, tmp_path, LINK42_NODE_ID=node_id)
    assert result.returncode != 0
    assert "positive integer" in result.stderr


@pytest.mark.parametrize("damage", ["unsafe-archive", "broken-module"])
def test_failed_source_preflight_cleans_staging_without_touching_old_agent(tmp_path, damage):
    payload, checksum = make_release(tmp_path, True)
    with tarfile.open(payload, "w:gz") as archive:
        archive.addfile(tarfile.TarInfo("apps/agent/link42_agent/__init__.py"), io.BytesIO(b""))
        data = b"raise SystemExit(1)\n"
        info = tarfile.TarInfo("../outside" if damage == "unsafe-archive" else "apps/agent/link42_agent/main.py")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    checksum.write_text(hashlib.sha256(payload.read_bytes()).hexdigest() + "  release\n")
    commands = tmp_path / "commands"
    fake_command(commands, "curl", CURL_STUB)
    target = tmp_path / "bin/agent"
    target.parent.mkdir()
    target.write_text("old program")
    code = AGENT_DEFS + '''
AGENT_INSTALL_MODE=source
AGENT_FILE=link42-agent-source.tar.gz
configure_download_urls
download_agent
'''
    result = run(code, tmp_path, PATH=f"{commands}:{os.environ['PATH']}", PAYLOAD=payload, CHECKSUM=checksum, TMPDIR=tmp_path)
    assert result.returncode != 0
    assert target.read_text() == "old program"
    assert not (tmp_path / "install/.src.new").exists()
    assert not (tmp_path / "outside").exists()
    assert not list(tmp_path.glob("link42-agent.*"))


@pytest.mark.parametrize("available", [True, False])
def test_package_mirror_failure_only_continues_with_usable_dependencies(tmp_path, available):
    commands = tmp_path / "commands"
    fake_command(commands, "apt-get", "exit 1")
    fake_command(commands, "wg", "exit " + ("0" if available else "1"))
    result = run(AGENT_DEFS + '\nAGENT_INSTALL_MODE=binary\ninstall_packages\nprintf "finished"', tmp_path,
                 PATH=f"{commands}:{os.environ['PATH']}")
    assert result.returncode == (0 if available else 1), result.stderr
    assert ("finished" in result.stdout) == available


@pytest.mark.parametrize("target", ["2.99", "2.1"])
def test_glibc_asset_label_matches_filename_and_actual_requirements(tmp_path, target):
    if not shutil.which("readelf"):
        pytest.skip("binutils needed for ELF verification")
    script = (ROOT / "scripts/agent/build-x64.sh").read_text()
    definitions = script.split('if [[ "$(uname -m)"')[0]
    # BASH_SOURCE in this fragment belongs to the temporary test file.
    definitions = definitions.replace('ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"', f'ROOT_DIR="{ROOT}"')
    output = tmp_path / "assets"
    output.mkdir()
    shutil.copyfile(shutil.which("true"), output / "link42-agent-linux-x64")
    test_script = tmp_path / "build.sh"
    test_script.write_text(definitions + '\nOUT_DIR="$TEST_OUTPUT"\nwrite_release_files 0.2.0\n')
    result = subprocess.run(["bash", str(test_script)], capture_output=True, text=True, timeout=5,
                            env={**os.environ, "PYTHON_BIN": sys.executable, "LINK42_AGENT_PLATFORM": f"linux-x64-glibc{target}", "TEST_OUTPUT": str(output)})
    if target == "2.1":
        assert result.returncode != 0
        assert "exceeding platform label" in result.stderr
        assert not (output / "manifest.json").exists()
    else:
        import json
        assert result.returncode == 0, result.stderr
        asset = json.loads((output / "manifest.json").read_text())["releases"]["0.2.0"]["assets"][f"linux-x64-glibc{target}"]
        assert asset["path"] == f"link42-agent-linux-x64-glibc{target}-0.2.0"
        assert asset["sha256"] == hashlib.sha256((output / asset["path"]).read_bytes()).hexdigest()


@pytest.mark.parametrize("kind", ["agent", "udp2raw"])
@pytest.mark.parametrize("signal_name", ["SIGINT", "SIGTERM"])
def test_signal_during_download_exits_and_cleans_temp_files(tmp_path, kind, signal_name):
    import signal
    import time

    commands = tmp_path / "commands"
    fake_command(commands, "curl", 'printf ready > "$READY"\nexec sleep 30')
    ready = tmp_path / "ready"
    if kind == "agent":
        code = AGENT_DEFS + '\nAGENT_INSTALL_MODE=binary\nAGENT_FILE=link42-agent-linux-x64\nconfigure_download_urls\ndownload_agent'
    else:
        code = UDP + '\ninstall_udp2raw_bin'
    env = {**os.environ, "PATH": f"{commands}:{os.environ['PATH']}", "READY": str(ready), "TMPDIR": str(tmp_path),
           "LINK42_INSTALL_DIR": str(tmp_path / "install"), "LINK42_AGENT_BIN": str(tmp_path / "bin/agent"),
           "LINK42_SERVER_URL": "https://panel.example", "UDP2RAW_BIN": "udp2raw_amd64"}
    process = subprocess.Popen(["/bin/sh", "-c", code], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        deadline = time.monotonic() + 3
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists()
        os.killpg(process.pid, getattr(signal, signal_name))
        process.communicate(timeout=5)
        assert process.returncode == (130 if signal_name == "SIGINT" else 143)
        assert not list(tmp_path.glob("link42-agent.*"))
        assert not list(tmp_path.glob("tmp.*"))
        assert not (tmp_path / "bin/agent").exists()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
