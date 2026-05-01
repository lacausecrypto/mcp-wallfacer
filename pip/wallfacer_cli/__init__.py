"""Python launcher for the `wallfacer` Rust binary.

`pip install mcp-wallfacer` installs this package, which on first
`wallfacer ...` invocation fetches the matching GitHub release tarball
into a per-user cache directory and execs the binary. Subsequent calls
reuse the cached binary.

Pure-stdlib (urllib + tarfile + zipfile) — no extra dependencies.

Mirrors the npm wrapper's behaviour so all install paths converge on
the same prebuilt binary.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

__version__ = "0.4.1"

_REPO = "lacausecrypto/mcp-wallfacer"
_RELEASE_TEMPLATE = "https://github.com/{repo}/releases/download/{version}/{archive}"


def _target_triple() -> str:
    """Map the current Python runtime to a Rust release triple."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    arch = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }.get(machine)
    if not arch:
        raise RuntimeError(
            f"unsupported architecture {machine!r}. "
            "Build from source: `cargo install mcp-wallfacer`."
        )

    if system == "linux":
        return f"{arch}-unknown-linux-gnu"
    if system == "darwin":
        return f"{arch}-apple-darwin"
    if system == "windows":
        if arch != "x86_64":
            raise RuntimeError(
                "only x86_64 windows builds are published; "
                "run `cargo install mcp-wallfacer` to build for ARM."
            )
        return "x86_64-pc-windows-msvc"
    raise RuntimeError(
        f"unsupported OS {system!r}. Supported: linux, darwin, windows."
    )


def _archive_name(triple: str) -> str:
    ext = "zip" if "windows" in triple else "tar.gz"
    return f"wallfacer-{triple}.{ext}"


def _binary_name(triple: str) -> str:
    return "wallfacer.exe" if "windows" in triple else "wallfacer"


def _cache_root() -> Path:
    """Per-user cache directory holding the downloaded binary."""
    override = os.environ.get("WALLFACER_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = str(Path.home() / "Library" / "Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "mcp-wallfacer"


def _download(url: str, dest: Path) -> None:
    """Stream `url` into `dest` with a User-Agent header."""
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-wallfacer-py"})
    with urllib.request.urlopen(req) as response, open(dest, "wb") as fh:
        shutil.copyfileobj(response, fh)


def _extract(archive: Path, dest_dir: Path) -> None:
    if archive.suffix == ".zip" or str(archive).endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest_dir)
    else:
        with tarfile.open(archive, mode="r:gz") as tf:
            tf.extractall(dest_dir)


def _ensure_binary(version: str) -> Path:
    """Return the path to a usable wallfacer binary, downloading if absent."""
    triple = _target_triple()
    binary_name = _binary_name(triple)
    cache_dir = _cache_root() / version / triple
    binary_path = cache_dir / binary_name
    if binary_path.exists():
        return binary_path

    cache_dir.mkdir(parents=True, exist_ok=True)
    archive_name = _archive_name(triple)
    url = _RELEASE_TEMPLATE.format(repo=_REPO, version=version, archive=archive_name)

    sys.stderr.write(f"[mcp-wallfacer] downloading {archive_name} from {url}\n")
    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / archive_name
        _download(url, archive_path)
        _extract(archive_path, cache_dir)

    if not binary_path.exists():
        raise RuntimeError(
            f"expected {binary_name} after extraction; got {list(cache_dir.iterdir())}"
        )
    if sys.platform != "win32":
        binary_path.chmod(binary_path.stat().st_mode | stat.S_IEXEC | stat.S_IRUSR)
    return binary_path


def main() -> int:
    """Entry point installed as `wallfacer` by `[project.scripts]`."""
    version = os.environ.get("WALLFACER_VERSION") or f"v{__version__}"
    try:
        binary = _ensure_binary(version)
    except Exception as err:  # noqa: BLE001 — surface any failure verbatim.
        sys.stderr.write(
            f"[mcp-wallfacer] install failed: {err}\n"
            "[mcp-wallfacer] build from source: `cargo install mcp-wallfacer`\n"
        )
        return 1

    # Forward argv + stdio. `os.execv` would be lighter but Windows
    # doesn't honour it; subprocess.run + return-code is portable.
    completed = subprocess.run([str(binary), *sys.argv[1:]], check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
