# mcp-wallfacer

> Runtime fuzzing & invariant testing for MCP servers — catch crashes, hangs, schema drift, race conditions, and state leaks **before** they ship.

[![Crates.io](https://img.shields.io/crates/v/mcp-wallfacer?style=flat-square&logo=rust&color=informational)](https://crates.io/crates/mcp-wallfacer)
[![Downloads](https://img.shields.io/crates/d/mcp-wallfacer?style=flat-square&label=downloads&color=blue)](https://crates.io/crates/mcp-wallfacer)
[![Docs.rs](https://img.shields.io/docsrs/wallfacer-core?style=flat-square&logo=docs.rs&label=docs.rs)](https://docs.rs/wallfacer-core)
[![CI](https://img.shields.io/github/actions/workflow/status/lacausecrypto/mcp-wallfacer/ci.yml?branch=main&style=flat-square&logo=github&label=CI)](https://github.com/lacausecrypto/mcp-wallfacer/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blueviolet?style=flat-square&logo=rust)](https://blog.rust-lang.org/)
[![License](https://img.shields.io/crates/l/mcp-wallfacer?style=flat-square)](#license)
[![Stars](https://img.shields.io/github/stars/lacausecrypto/mcp-wallfacer?style=flat-square&logo=github)](https://github.com/lacausecrypto/mcp-wallfacer/stargazers)

**`mcp-wallfacer` is the only runtime testing harness purpose-built for [Model Context Protocol](https://modelcontextprotocol.io) servers.** It connects over stdio or Streamable HTTP, fuzzes tools with schema-driven adversarial payloads, validates responses against declared output schemas, evaluates user-defined YAML invariants, and stress-tests for concurrency races and session-state leaks — then stores every finding as a reproducible JSON record under `.wallfacer/corpus/`.

It complements static scanners (Snyk Agent Scan, Cisco MCP Scanner, Enkrypt) by exercising **observable runtime behavior** instead of inspecting source code or tool descriptions. Run it in CI as a branch-protection gate, or locally before publishing your server.

### What it catches

* **`Crash`** — server process dies on a tool call.
* **`Hang`** — call exceeds its timeout.
* **`SchemaViolation`** — response drifts from declared output schema.
* **`PropertyFailure`** — user-declared YAML invariant fails.
* **`ProtocolError`** — server returns malformed JSON-RPC.
* **`StateLeak`** — session state visible across the wrong boundary.

A six-bug demo server is included at [`examples/python_server/`](examples/python_server/) — running the four wallfacer modes against it surfaces every kind above.

## Install

Five paths, one binary — pick whichever fits your toolchain. Full details in [docs/install.md](docs/install.md).

| Path | Command | Best for |
|---|---|---|
| **Cargo** | `cargo install mcp-wallfacer` | Rust toolchain already present (MSRV 1.88) |
| **GitHub release** | [Download tarball](https://github.com/lacausecrypto/mcp-wallfacer/releases) | Air-gapped servers, no toolchain dep |
| **npm** | `npm install -g mcp-wallfacer` | TypeScript / Node MCP authors |
| **pip** | `pip install mcp-wallfacer` | Python MCP authors |
| **GitHub Action** | `uses: lacausecrypto/mcp-wallfacer@v0.4.1` | CI gating with caching |

The npm and pip wrappers are thin launchers that download the matching prebuilt binary from the GitHub release at install / first-run time; the underlying CLI is byte-identical to a `cargo install` build of the same version.

The crates.io package is `mcp-wallfacer`; the installed binary is `wallfacer`.

## Quickstart

```bash
wallfacer init                       # writes wallfacer.toml + invariants.yaml
wallfacer doctor                     # lists tools/resources/prompts
wallfacer fuzz --seed 42 --iterations 200
wallfacer differential --learn       # snapshot declared output schemas
wallfacer differential               # check responses against the snapshot
wallfacer property invariants.yaml   # YAML invariants
wallfacer property --pack auth       # built-in rule pack (Phase F4)
wallfacer torture --concurrency 100
wallfacer ci --format sarif > wallfacer.sarif

wallfacer corpus list                # browse stored findings
wallfacer replay <finding-id>        # rerun a finding (env-var unredact)
wallfacer diff baseline/ candidate/  # regressions vs fixes between two runs
```

Findings are serialized as JSON under `.wallfacer/corpus/<tool>/<finding_id>.json` with the seed and the exact tool call needed for reproduction. Sensitive headers, environment variables, and payload fields (`Authorization`, `Cookie`, `*-token`, `password`, `api_key`, ...) are redacted on persistence — see [docs/security.md](docs/security.md).

## Commands

- `init [--http|--stdio] [--ci] [--skip-invariants]`: write `wallfacer.toml` + a starter `invariants.yaml`, optionally with the GitHub Actions workflow.
- `doctor`: connect and list tools, resources, and prompts.
- `fuzz [--coverage-strict] [--include glob] [--exclude glob]`: generate adversarial tool inputs and detect crashes, hangs, and protocol errors. Honors `globset` patterns (`**/foo`, `tools.{a,b}`).
- `differential [--learn]`: compare runtime responses with declared or learned output schemas.
- `property <file.yaml> | --pack <name>`: evaluate YAML invariants over generated or fixed cases. Built-in packs: `auth`, `path-traversal`, `error-shape`.
- `torture [--mode parallel|state-leak] [--concurrency N] [--duration <span>]`: concurrency and state-boundary checks under a global cancellation deadline.
- `corpus {list, show <id>, replay <id>, minimize <id>}`: inspect, replay, and minimize stored findings.
- `replay <id> [--show-payload]`: rerun a stored finding, substituting `<redacted>` payload fields from `WALLFACER_REPLAY_<KEY>` env vars locally (never logged).
- `diff <baseline> <candidate> [--fail-on-regression]`: compare two corpus directories; reports new findings (regressions) and resolved ones (fixes).
- `ci [--format sarif|json|human] [--severity-threshold low|medium|high|critical]`: short, deterministic boundary-payload pass; emits SARIF for branch protection.

## Configuration

```toml
[target]
kind = "stdio"
command = "python3"
args = ["server.py"]
timeout_ms = 5000

[output]
corpus_dir = ".wallfacer/corpus"
lock_timeout_ms = 30000   # Phase E3, default 30s

[allow_destructive]
# Regex patterns matched against tool name; matching tools bypass the
# destructive classifier. Phase C5.
tools = ["^logs_.*$"]

[destructive]
# Replace the default keyword detector (delete/drop/destroy/...) with
# custom regexes. Empty = use defaults. Phase C5.
patterns = []
```

HTTP targets use:

```toml
[target]
kind = "http"
url = "http://localhost:8000/mcp"
headers = { Authorization = "Bearer xxx" }
```

## Example

[`examples/python_server/`](examples/python_server/) ships a six-bug Python MCP server that exercises every `FindingKind` (`Crash`, `Hang`, `SchemaViolation`, `PropertyFailure`, `ProtocolError`, `StateLeak`). It is also the Phase F acceptance fixture for the e2e suite.

```bash
cd examples/python_server
wallfacer fuzz
wallfacer differential --learn && wallfacer differential
wallfacer property invariants.yaml
wallfacer torture --mode state-leak
wallfacer corpus list
```

## Rule packs

15 invariant packs ship embedded in the binary. Discover them with `wallfacer pack list`; render the human reference with `cargo run -p wallfacer-tools -- gen-pack-docs` (output under [`docs/packs/`](docs/packs/index.md)).

### When to use which pack

| If your server… | Pack | Catches |
|---|---|---|
| has any user-facing tool | [`secrets-leakage`](docs/packs/secrets-leakage.md) | bearer/api-key/secret strings echoed in responses |
| has any user-facing tool | [`unicode`](docs/packs/unicode.md) | RTL override, ZWJ, escape-sequence echoes |
| has any user-facing tool | [`large-payload`](docs/packs/large-payload.md) | graceful handling of 10 MB strings / 1M items |
| has any user-facing tool | [`error-shape`](docs/packs/error-shape.md) | envelope shape, no stack traces, no internal paths |
| has authentication (whoami/login) | [`auth`](docs/packs/auth.md) | anonymous rejection, bearer echo, session cookies |
| has RBAC | [`authorization`](docs/packs/authorization.md) | role filtering, escalation, ACL on resources |
| bridges to a filesystem | [`path-traversal`](docs/packs/path-traversal.md) | `../`, absolute, UNC, URL-encoded, symlink escapes |
| bridges to a database | [`injection-sql`](docs/packs/injection-sql.md) | `'; DROP`, UNION SELECT, comment bypass |
| spawns processes | [`injection-shell`](docs/packs/injection-shell.md) | `;`, `&&`, backticks, `$(...)` expansion |
| proxies LLM completions | [`prompt-injection`](docs/packs/prompt-injection.md) | "ignore previous", role override, jailbreak markers |
| paginates lists | [`pagination`](docs/packs/pagination.md) | limit honored, cursor stable, no leak across pages |
| declares `idempotentHint: true` | [`idempotency`](docs/packs/idempotency.md) | envelope stability under repeated calls |
| declares any MCP annotations | [`tool-annotations`](docs/packs/tool-annotations.md) | hints match observable behaviour |
| bridges to a rate-limited API | [`rate-limit`](docs/packs/rate-limit.md) | quota envelope shape, 429 with Retry-After |
| **wants a security baseline** | [`security`](docs/packs/security.md) | meta-pack: auth + authorization + path-traversal + injection-* + prompt-injection + secrets-leakage |

```bash
# Run a single pack against your server (after `wallfacer init`):
wallfacer property --pack secrets-leakage

# Compose multiple:
wallfacer property --pack auth --pack error-shape

# Run every embedded pack:
wallfacer property --pack-all

# Override a pack's tool-name parameter for your codebase:
wallfacer property --pack auth --param whoami_tool=getCurrentUser
```

Override patterns persist in `wallfacer.toml`:

```toml
[packs.auth]
whoami_tool = "getCurrentUser"
list_resources_tool = "myListResources"
```

Customise a pack: `wallfacer pack init <name>` copies the embedded YAML to `packs/<name>.yaml`, where you can edit it freely (workspace copy shadows the embedded one).

## Documentation

- [docs/architecture.md](docs/architecture.md) — workspace layout, plan lifecycle, reproducibility contract.
- [docs/security.md](docs/security.md) — redaction model, file permissions, replay unredaction, threat model.
- [docs/real-world.md](docs/real-world.md) — running packs against external MCP servers, reporting upstream.
- [docs/packs/](docs/packs/index.md) — auto-generated reference for every embedded pack.
- API: <https://docs.rs/wallfacer-core>.

## Roadmap

- v0.2: Phases A–F — workspace hardening, full JSON Schema generation, plan layer, property DSL v2, robustness pass, DX & docs. ✅ **shipped**.
- v0.3: rule packs for common MCP security and reliability issues; reusable invariant libraries. **in progress (Phases G–K)**.
- v0.4: shared corpus workflows and reporting; remote pack registries.
