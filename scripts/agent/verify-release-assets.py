"""Fail builds if the embedded installation resources are incomplete or corrupt."""

import hashlib
import json
from pathlib import Path
import sys


def require_regular_file(path: Path) -> None:
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise ValueError(f"missing or unsafe release file: {path}")


def verify(root: Path) -> None:
    project = Path(__file__).resolve().parents[2]
    for relative in ("deploy/sh/link42-agent.sh", "udp2raw_sh/udp2raw.sh"):
        require_regular_file(project / relative)
    for name in (
        "udp2raw_amd64", "udp2raw_amd64_hw_aes", "udp2raw_x86", "udp2raw_x86_asm_aes",
        "udp2raw_arm", "udp2raw_arm_asm_aes", "udp2raw_mips24kc_le",
        "udp2raw_mips24kc_le_asm_aes", "udp2raw_mips24kc_be", "udp2raw_mips24kc_be_asm_aes",
    ):
        binary_root = project / "plugins/udp2raw/assets"
        if not binary_root.exists():
            binary_root = project / "udp2raw_sh/udp2raw_bin"
        require_regular_file(binary_root / name)
    manifest_path = root / "manifest.json"
    require_regular_file(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    releases = manifest["releases"]
    assets = releases[manifest["latest"]]["assets"]
    if not {"linux-x64", "openwrt-source"} <= assets.keys():
        raise ValueError("latest release must include linux-x64 and openwrt-source")
    for release in releases.values():
        for asset in release["assets"].values():
            relative_path = Path(asset["path"])
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise ValueError(f"invalid release path: {relative_path}")
            path = root / relative_path
            path.resolve().relative_to(root.resolve())
            require_regular_file(path)
            checksum = path.with_name(path.name + ".sha256")
            require_regular_file(checksum)
            with path.open("rb") as handle:
                digest = hashlib.file_digest(handle, "sha256").hexdigest()
            if digest != asset["sha256"] or digest != checksum.read_text().split()[0]:
                raise ValueError(f"release checksum mismatch: {path}")
            if path.stat().st_size != asset["size"]:
                raise ValueError(f"release size mismatch: {path}")


if __name__ == "__main__":
    try:
        verify(Path(sys.argv[1]))
    except (ValueError, KeyError, IndexError, OSError, TypeError) as exc:
        raise SystemExit(f"invalid embedded installation resources: {exc}") from exc
