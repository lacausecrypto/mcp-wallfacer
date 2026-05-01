# mcp-wallfacer (pip wrapper)

> Thin Python wrapper around the [`mcp-wallfacer`](https://github.com/lacausecrypto/mcp-wallfacer)
> Rust binary. On first invocation, downloads the matching platform
> binary from the GitHub release into a per-user cache and execs it.

```bash
pip install mcp-wallfacer
wallfacer --help
```

## What it installs

The Python package is tiny — pure-stdlib launcher, no extra deps. The
actual `wallfacer` binary is downloaded on the first run from the
matching GitHub release.

| Platform | Architecture |
|---|---|
| Linux | `x86_64`, `aarch64` |
| macOS | `x86_64` (Intel), `aarch64` (Apple silicon) |
| Windows | `x86_64` |

For other platforms, build from source:

```bash
cargo install mcp-wallfacer
```

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `WALLFACER_VERSION` | `v<package version>` | Pin the GH release to download. |
| `WALLFACER_CACHE_DIR` | platform default | Override the binary cache location. |

Default cache locations:

- Linux: `$XDG_CACHE_HOME/mcp-wallfacer` (or `~/.cache/mcp-wallfacer`)
- macOS: `~/Library/Caches/mcp-wallfacer`
- Windows: `%LOCALAPPDATA%\mcp-wallfacer`

## How the wrapper works

1. `wallfacer` is registered as a console script via
   `[project.scripts]` in `pyproject.toml`. It maps to
   `wallfacer_cli.main`.
2. On invocation, `main()` checks the cache for a binary matching the
   current platform + version. If absent, it downloads + extracts the
   GitHub release tarball.
3. `subprocess.run` forwards argv and stdio to the binary, exit code
   propagates back.

The wrapper executes no Python at runtime beyond the launcher itself,
so behaviour is identical to a direct `cargo install` of the same
version.
