# Installing wallfacer

Five paths, one binary. Pick whichever fits your toolchain — the
underlying `wallfacer` CLI is byte-identical across all of them.

## TL;DR

| Path | Command | When to pick it |
|---|---|---|
| **Cargo** | `cargo install mcp-wallfacer` | You already have a Rust toolchain. Slowest to install, but you compile from source so any platform with `cargo` works. |
| **GitHub release** | Download the matching tarball from the [Releases page](https://github.com/lacausecrypto/mcp-wallfacer/releases) | You want a single static binary with no toolchain dep. Best for air-gapped servers. |
| **npm** | `npm install -g mcp-wallfacer` | You're a TypeScript / JavaScript MCP author. The wrapper postinstall-downloads the GitHub release binary. |
| **pip** | `pip install mcp-wallfacer` | You're a Python MCP author. Same wrapper trick: the Python launcher fetches the binary on first invocation. |
| **GitHub Action** | `uses: lacausecrypto/mcp-wallfacer@v0.4.1` | You want wallfacer running in CI. The action handles install, caching, and forwards arguments to `wallfacer property`. |

## Cargo

```bash
cargo install mcp-wallfacer
wallfacer --version
```

Builds wallfacer-core and the CLI from source. MSRV is **Rust 1.88**.
Requires a network connection at install time to fetch crates.io
dependencies.

## Prebuilt binaries (GitHub releases)

Each tagged release publishes five binaries:

- `wallfacer-x86_64-unknown-linux-gnu.tar.gz`
- `wallfacer-aarch64-unknown-linux-gnu.tar.gz`
- `wallfacer-x86_64-apple-darwin.tar.gz`
- `wallfacer-aarch64-apple-darwin.tar.gz`
- `wallfacer-x86_64-pc-windows-msvc.zip`

```bash
VERSION=v0.4.1
TRIPLE=aarch64-apple-darwin   # adjust per host
curl -LO "https://github.com/lacausecrypto/mcp-wallfacer/releases/download/${VERSION}/wallfacer-${TRIPLE}.tar.gz"
tar xzf "wallfacer-${TRIPLE}.tar.gz"
./wallfacer --version
```

## npm

```bash
npm install -g mcp-wallfacer
wallfacer --help
```

A `postinstall` script (in [`npm/scripts/install.js`](../npm/scripts/install.js))
detects the platform, downloads the matching tarball from the GitHub
release, and drops the binary in `node_modules/.bin/`. Subsequent
upgrades (`npm update -g mcp-wallfacer`) re-trigger the download.

Set `WALLFACER_SKIP_INSTALL=1` to skip the download (useful in
container builds that vendor the binary themselves).

## pip

```bash
pip install mcp-wallfacer
wallfacer --help
```

Pure-stdlib launcher (no extra Python deps) that downloads the binary
into a per-user cache on the first invocation:

- Linux: `$XDG_CACHE_HOME/mcp-wallfacer`
- macOS: `~/Library/Caches/mcp-wallfacer`
- Windows: `%LOCALAPPDATA%\mcp-wallfacer`

Set `WALLFACER_CACHE_DIR=/path` to override the cache location.

## GitHub Action

```yaml
- name: Run wallfacer
  uses: lacausecrypto/mcp-wallfacer@v0.4.1
  with:
    pack-all: "true"
    config: wallfacer.toml
    format: sarif

- name: Upload findings to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.run.outputs.findings-sarif }}
```

The action is a [composite action](../action.yml). Inputs:

| Input | Default | Notes |
|---|---|---|
| `version` | `v0.4.1` | Pin to a specific release. |
| `pack` | empty | Newline-separated list of packs to run. |
| `pack-all` | `false` | When `true`, runs every embedded pack. Mutually exclusive with `pack`. |
| `config` | `wallfacer.toml` | Path to your `wallfacer.toml`. |
| `format` | `human` | `human`, `json`, or `sarif`. |
| `seed` | empty | Master seed for deterministic re-runs. |
| `cases` | `100` | Default cases per invariant. |
| `fail-on-finding` | `true` | Exit non-zero when at least one finding surfaces. |

Outputs:

- `findings-json` — path to the JSON envelope when `format: json`.
- `findings-sarif` — path to the SARIF report when `format: sarif`.

The action caches the binary under `runner.tool_cache` keyed by
version + platform, so repeated runs in the same workflow are
instant.

## Verifying the install

```bash
wallfacer --version
wallfacer pack list
wallfacer pack test --all
```

The last command is offline-only (no MCP server needed) and runs
every shipped pack against its synthetic fixtures. Useful to confirm
wallfacer itself is healthy before pointing it at a real server.
