from __future__ import annotations

from dataclasses import dataclass
import math
import os
import selectors
import signal
import subprocess
import time
from typing import Mapping


MAX_COMMAND_OUTPUT_BYTES = 256 * 1024


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    truncated: bool = False


def decode_output(data: bytes, limit: int) -> str:
    """Decode invalid output safely while keeping the UTF-8 result within its limit."""

    text = data.decode("utf-8", errors="replace")
    return text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def run_bounded_command(
    command: list[str],
    *,
    timeout: float,
    output_limit: int = MAX_COMMAND_OUTPUT_BYTES,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Drain both pipes continuously, retaining bounded output and enforcing a deadline.

    The agent runs on POSIX nodes. A separate process group lets a timeout also
    terminate child commands that keep a pipe open after their parent exits.
    Output past the limit is discarded, so neither memory nor disk grows with it.
    """

    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("command timeout must be a finite positive number")
    limit = max(1, min(int(output_limit), MAX_COMMAND_OUTPUT_BYTES))
    deadline = time.monotonic() + timeout
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = False
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )

    def kill_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        with selectors.DefaultSelector() as selector:
            for name in captured:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output = captured[key.data]
                    available = limit - len(output)
                    output.extend(chunk[:available])
                    truncated = truncated or len(chunk) > available
            process.wait(timeout=max(0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        kill_group()
        process.wait()
        raise subprocess.TimeoutExpired(
            command, timeout,
            output=decode_output(bytes(captured["stdout"]), limit),
            stderr=decode_output(bytes(captured["stderr"]), limit),
        ) from None
    except BaseException:
        kill_group()
        process.wait()
        raise
    finally:
        process.stdout.close()
        process.stderr.close()
    return CommandResult(
        process.returncode,
        decode_output(bytes(captured["stdout"]), limit),
        decode_output(bytes(captured["stderr"]), limit),
        truncated,
    )
