"""Read-only verification of controller-hosted bootstrap downloads."""

import hashlib
import json
import sys
from urllib.request import urlopen


def verify(base_url: str, version: str) -> None:
    def download(path: str) -> bytes:
        with urlopen(base_url.rstrip("/") + path, timeout=30) as response:
            if response.status != 200:
                raise ValueError(f"download failed: {path}")
            return response.read()

    for name in ("link42-agent.sh", "udp2raw.sh"):
        if not download(f"/sh/{name}").startswith(b"#!/bin/sh\n"):
            raise ValueError(f"invalid installation script: {name}")
    for name in ("link42-agent-linux-x64", "link42-agent-source.tar.gz"):
        for prefix in ("/res/link42", f"/res/link42/{version}"):
            data = download(f"{prefix}/{name}")
            checksum = download(f"{prefix}/{name}.sha256").decode().split()[0]
            if hashlib.sha256(data).hexdigest() != checksum:
                raise ValueError(f"download checksum mismatch: {prefix}/{name}")
    binary = download(f"/api/agent/releases/{version}/download?platform=linux-x64")
    checksum = json.loads(download(f"/api/agent/releases/{version}/sha256?platform=linux-x64"))["sha256"]
    if hashlib.sha256(binary).hexdigest() != checksum:
        raise ValueError("self-upgrade API checksum mismatch")
    for name in (
        "udp2raw_amd64", "udp2raw_amd64_hw_aes", "udp2raw_x86", "udp2raw_x86_asm_aes",
        "udp2raw_arm", "udp2raw_arm_asm_aes", "udp2raw_mips24kc_le",
        "udp2raw_mips24kc_le_asm_aes", "udp2raw_mips24kc_be", "udp2raw_mips24kc_be_asm_aes",
    ):
        data = download(f"/sh/udp2raw_bin/{name}")
        if not data.startswith(b"\x7fELF"):
            raise ValueError(f"invalid UDP2RAW binary: {name}")
        checksum = download(f"/sh/udp2raw_bin/{name}.sha256").decode().split()[0]
        if hashlib.sha256(data).hexdigest() != checksum:
            raise ValueError(f"UDP2RAW checksum mismatch: {name}")
    print("controller bootstrap downloads and checksums verified")


if __name__ == "__main__":
    verify(sys.argv[1], sys.argv[2])
