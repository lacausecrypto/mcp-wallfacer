# mcp-wallfacer (npm wrapper)

> Thin npm wrapper around the [`mcp-wallfacer`](https://github.com/lacausecrypto/mcp-wallfacer)
> Rust binary. Installs the matching platform binary from the GitHub
> release at `postinstall` time and exposes it as `wallfacer`.

```bash
npm install -g mcp-wallfacer
wallfacer --help
```

## What it installs

| Platform | Architecture | Triple |
|---|---|---|
| Linux | x86_64 | `x86_64-unknown-linux-gnu` |
| Linux | aarch64 | `aarch64-unknown-linux-gnu` |
| macOS | Intel | `x86_64-apple-darwin` |
| macOS | Apple silicon | `aarch64-apple-darwin` |
| Windows | x86_64 | `x86_64-pc-windows-msvc` |

For other platforms, build from source:

```bash
cargo install mcp-wallfacer
```

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `WALLFACER_VERSION` | `v<package.json#version>` | Pin the GH release to download. |
| `WALLFACER_SKIP_INSTALL` | unset | When `1`, the postinstall script is a no-op. Useful in container builds that vendor the binary themselves. |

## How the wrapper works

1. `postinstall` (`scripts/install.js`) runs once per `npm install`.
2. It maps `process.platform` × `process.arch` to a Rust target
   triple, downloads the matching GitHub release tarball, and extracts
   the `wallfacer` binary into `node_modules/mcp-wallfacer/bin/`.
3. `bin/wallfacer.js` (the package's only `bin` entry) is a tiny
   shim that forwards argv + stdio to the binary and exits with its
   exit code.

The wrapper does not execute any Rust at runtime; it just runs the
prebuilt binary verbatim, so behaviour is identical to a direct
`cargo install` of the same version.
