<div align="center">

# `mcp-wallfacer`

**Runtime fuzzing & invariant testing for MCP servers — catch crashes, hangs, schema drift, race conditions, and state leaks before they ship.**

[![Crates.io](https://img.shields.io/crates/v/mcp-wallfacer?style=flat&logo=rust&label=crates.io&color=informational)](https://crates.io/crates/mcp-wallfacer)
[![Crates.io downloads](https://img.shields.io/crates/d/mcp-wallfacer?style=flat&label=cargo%20downloads&color=blue)](https://crates.io/crates/mcp-wallfacer)
[![npm](https://img.shields.io/npm/v/mcp-wallfacer?style=flat&logo=npm&label=npm&color=cb3837)](https://www.npmjs.com/package/mcp-wallfacer)
[![npm downloads](https://img.shields.io/npm/dt/mcp-wallfacer?style=flat&label=npm%20downloads&color=cb3837)](https://www.npmjs.com/package/mcp-wallfacer)
[![PyPI](https://img.shields.io/pypi/v/mcp-wallfacer?style=flat&logo=pypi&logoColor=white&label=pypi&color=3775a9&cacheSeconds=60)](https://pypi.org/project/mcp-wallfacer/)
[![PyPI downloads](https://img.shields.io/pypi/dm/mcp-wallfacer?style=flat&label=pypi%20downloads&color=3775a9&cacheSeconds=300)](https://pypi.org/project/mcp-wallfacer/)

[![docs.rs](https://img.shields.io/docsrs/wallfacer-core?style=flat&logo=docs.rs&label=docs.rs)](https://docs.rs/wallfacer-core)
[![CI](https://img.shields.io/github/actions/workflow/status/lacausecrypto/mcp-wallfacer/ci.yml?branch=main&style=flat&logo=github&label=CI)](https://github.com/lacausecrypto/mcp-wallfacer/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blueviolet?style=flat&logo=rust)](https://blog.rust-lang.org/)
[![License](https://img.shields.io/crates/l/mcp-wallfacer?style=flat)](#license)
[![GitHub stars](https://img.shields.io/github/stars/lacausecrypto/mcp-wallfacer?style=flat&logo=github)](https://github.com/lacausecrypto/mcp-wallfacer/stargazers)
[![Marketplace](https://img.shields.io/badge/marketplace-mcp--wallfacer-2ea44f?style=flat&logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/mcp-wallfacer)

</div>

---

`mcp-wallfacer` is the only runtime testing harness purpose-built for [Model Context Protocol](https://modelcontextprotocol.io) servers. It connects over **stdio** or **Streamable HTTP**, fuzzes tools with schema-driven adversarial payloads, validates responses against declared output schemas, evaluates user-defined YAML invariants and multi-step sequences, and stress-tests for concurrency races and session-state leaks — then stores every finding as a reproducible JSON record under `.wallfacer/corpus/`.

It complements static scanners (Snyk Agent Scan, Cisco MCP Scanner, Enkrypt) by exercising **observable runtime behaviour** instead of inspecting source code or tool descriptions. Run it in CI as a branch-protection gate, or locally before publishing your server.

## What it catches

| Finding kind | Trigger |
|---|---|
| `Crash` | server process dies on a tool call |
| `Hang` | call exceeds its timeout |
| `SchemaViolation` | response drifts from declared output schema |
| `PropertyFailure` | user-declared YAML invariant fails |
| `ProtocolError` | server returns malformed JSON-RPC |
| `StateLeak` | session state visible across the wrong boundary |
| `SequenceFailure` | multi-step invariant breaks (e.g. delete-then-read finds the deleted record) |

A seven-bug demo server is included at [`examples/python_server/`](examples/python_server/) — running every wallfacer mode against it surfaces every kind above.

## Quickstart

```bash
# 1. Install (pick any of the five paths — they all serve the same binary)
cargo install mcp-wallfacer            # Rust toolchain
npm install -g mcp-wallfacer           # npm wrapper
pip install mcp-wallfacer              # pip wrapper

# 2. Generate a config + sample invariants in your project
wallfacer init

# 3. Verify the connection
wallfacer doctor

# 4. Run the security baseline (auth + authorization + path-traversal +
#    injection-sql/shell + prompt-injection + secrets-leakage)
wallfacer property --pack security
```

Findings stream to stdout (Human / JSON / SARIF) and persist as JSON under `.wallfacer/corpus/<tool>/<finding-id>.json` with the seed and exact tool call needed for reproduction. Sensitive headers, environment variables, and payload fields (`Authorization`, `Cookie`, `*-token`, `password`, `api_key`, ...) are redacted on persistence — see [`docs/security.md`](docs/security.md).

## Install

Five canonical channels, one binary. Full details in [`docs/install.md`](docs/install.md).

| Channel | Command | Best for |
|---|---|---|
| **Cargo** | `cargo install mcp-wallfacer` | Rust toolchain present (MSRV 1.88) |
| **GitHub release** | [download tarball](https://github.com/lacausecrypto/mcp-wallfacer/releases) | air-gapped servers, no toolchain |
| **npm** | `npm install -g mcp-wallfacer` | TypeScript / Node MCP authors |
| **pip** | `pip install mcp-wallfacer` | Python MCP authors |
| **GitHub Action** | `uses: lacausecrypto/mcp-wallfacer@v0.6.0` | CI gating with caching |

The npm and pip wrappers are thin launchers that download the matching prebuilt binary from the GitHub release at install / first-run time; the underlying CLI is byte-identical to a `cargo install` build of the same version. The crates.io package is `mcp-wallfacer`; the installed binary is `wallfacer`.

## CI usage

```yaml
# .github/workflows/wallfacer.yml
name: Wallfacer
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: lacausecrypto/mcp-wallfacer@v0.6.0
        with:
          pack-all: "true"          # or pack: "security\nstateful"
          config: wallfacer.toml
          format: sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.run.outputs.findings-sarif }}
```

## Commands

| Command | Purpose |
|---|---|
| `init [--http \| --stdio] [--ci]` | scaffold `wallfacer.toml` + starter `invariants.yaml` |
| `doctor` | connect, list tools / resources / prompts (capability-aware: shows `n/a` when the server doesn't declare a capability) |
| `fuzz [--coverage-strict]` | adversarial schema-driven inputs; catches Crash / Hang / ProtocolError |
| `differential [--learn]` | compare runtime responses against declared / learned output schemas |
| `property <file.yaml> \| --pack <name> \| --pack-all` | evaluate YAML invariants + multi-step sequences |
| `torture [--mode parallel\|state-leak]` | concurrency + session-boundary stress |
| `pack {list, show, init, test, params}` | inspect / scaffold / offline-test the embedded rule pack library |
| `corpus {list, show, replay, minimize}` | inspect, re-run, and shrink stored findings |
| `replay <id> [--show-payload]` | rerun a finding; substitutes `<redacted>` payload fields from `WALLFACER_REPLAY_<KEY>` env vars |
| `diff <baseline> <candidate> [--fail-on-regression]` | compare two corpus runs; reports new / resolved findings |
| `ci [--format sarif\|json\|human]` | short, deterministic boundary pass for branch protection |

## Rule packs

17 invariant packs ship embedded in the binary. Discover them with `wallfacer pack list`; render the auto-generated reference into [`docs/packs/`](docs/packs/index.md) with `cargo run -p wallfacer-tools -- gen-pack-docs`.

### When to use which pack

| If your server… | Pack | Catches |
|---|---|---|
| has any user-facing tool | [`secrets-leakage`](docs/packs/secrets-leakage.md) | bearer / api-key / secret strings echoed in responses |
| has any user-facing tool | [`unicode`](docs/packs/unicode.md) | RTL override, ZWJ, escape-sequence echoes |
| has any user-facing tool | [`large-payload`](docs/packs/large-payload.md) | graceful handling of 10 MB strings / 1M items |
| has any user-facing tool | [`error-shape`](docs/packs/error-shape.md) | envelope shape, no stack traces, no internal paths |
| has authentication (whoami / login) | [`auth`](docs/packs/auth.md) | anonymous rejection, bearer echo, session cookies |
| has RBAC | [`authorization`](docs/packs/authorization.md) | role filtering, escalation, ACL on resources |
| bridges to a filesystem | [`path-traversal`](docs/packs/path-traversal.md) | `../`, absolute, UNC, URL-encoded, symlink escapes |
| bridges to a database | [`injection-sql`](docs/packs/injection-sql.md) | `'; DROP`, UNION SELECT, comment bypass |
| spawns processes | [`injection-shell`](docs/packs/injection-shell.md) | `;`, `&&`, backticks, `$(...)` expansion |
| proxies LLM completions | [`prompt-injection`](docs/packs/prompt-injection.md) | "ignore previous", role override, jailbreak markers |
| paginates lists | [`pagination`](docs/packs/pagination.md) | limit honoured, cursor stable, no leak across pages |
| declares `idempotentHint: true` | [`idempotency`](docs/packs/idempotency.md) | envelope stability under repeated calls |
| declares any MCP annotations | [`tool-annotations`](docs/packs/tool-annotations.md) | hints match observable behaviour |
| bridges to a rate-limited API | [`rate-limit`](docs/packs/rate-limit.md) | quota envelope shape, 429 with Retry-After |
| **has create/read/delete tools** | [`stateful`](docs/packs/stateful.md) | multi-step state-leak: delete-then-read finds the deleted record |
| **has login/logout flow** | [`auth-flow`](docs/packs/auth-flow.md) | multi-step: token revoked after logout |
| **wants a security baseline** | [`security`](docs/packs/security.md) | meta-pack: auth + authorization + path-traversal + injection-* + prompt-injection + secrets-leakage |

```bash
# Single pack
wallfacer property --pack secrets-leakage

# Multiple packs (deduped by canonical invariant name)
wallfacer property --pack auth --pack error-shape

# Every embedded pack
wallfacer property --pack-all

# Override a pack's tool-name parameter for your codebase
wallfacer property --pack auth --param whoami_tool=getCurrentUser
```

Persist overrides in `wallfacer.toml`:

```toml
[packs.auth]
whoami_tool = "getCurrentUser"
list_resources_tool = "myListResources"

[packs.stateful]
create_tool = "create_record"
delete_tool = "delete_record"
read_tool = "read_record"
```

Customise a pack: `wallfacer pack init <name>` copies the embedded YAML to `packs/<name>.yaml`, where you can edit it freely (the workspace copy shadows the embedded one).

## Configuration

```toml
[target]
kind = "stdio"                # or "http"
command = "python3"
args = ["server.py"]
timeout_ms = 5000

# HTTP target — ${VAR} is expanded against the process env at load
# time (use $$ to keep a literal $).
# kind = "http"
# url = "http://localhost:8000/mcp"
# [target.headers]
# Authorization = "Bearer ${WALLFACER_BEARER}"

[output]
corpus_dir = ".wallfacer/corpus"
lock_timeout_ms = 30000

[allow_destructive]
# Regex allowlist for tools the destructive classifier would
# otherwise refuse to invoke (matched against tool name).
tools = ["^logs_.*$"]

[destructive]
# Add custom destructive patterns on top of the built-in keyword
# detector (delete / drop / destroy / ...). Set
# `replace_defaults = true` to opt out of the built-ins.
patterns = ["^remove_.*$"]
replace_defaults = false

[severity]
# Override the default per-kind severity. Useful when concurrency
# races are not security-critical for your tool surface.
state_leak = "medium"
```

## Example

[`examples/python_server/`](examples/python_server/) ships a seven-bug Python MCP server that exercises every `FindingKind` (`Crash`, `Hang`, `SchemaViolation`, `PropertyFailure`, `ProtocolError`, `StateLeak`, `SequenceFailure`). The Phase F + L acceptance suite gates CI against this fixture.

```bash
cd examples/python_server
wallfacer fuzz
wallfacer differential --learn && wallfacer differential
wallfacer property --pack-all
wallfacer torture --mode state-leak
wallfacer corpus list
```

A parallel HTTP fixture lives at [`examples/python_server/server_http.py`](examples/python_server/server_http.py) — same buggy tools served over `POST /mcp`, used by the Phase M end-to-end test.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — workspace layout, plan lifecycle, reproducibility contract.
- [`docs/security.md`](docs/security.md) — redaction model, file permissions, replay unredaction, threat model.
- [`docs/sequences.md`](docs/sequences.md) — multi-step DSL, substitution rules, reconnect policy.
- [`docs/http-target.md`](docs/http-target.md) — Streamable HTTP transport, env-var headers, fixture.
- [`docs/install.md`](docs/install.md) — every install path, with troubleshooting.
- [`docs/real-world.md`](docs/real-world.md) — running packs against external MCP servers, reporting upstream.
- [`docs/packs/`](docs/packs/index.md) — auto-generated reference for every embedded pack.
- API: <https://docs.rs/wallfacer-core>.

## Roadmap

- **v0.2** ✅ — workspace hardening, full JSON Schema generation, plan layer, property DSL v2, robustness pass, DX & docs.
- **v0.3** ✅ — embedded rule pack library (15 packs), `for_each_tool` directive, multi-pack composition, real-world validation methodology.
- **v0.4** ✅ — sequence-aware property testing (`stateful`, `auth-flow` packs), HTTP transport CI-gated, distribution to npm + pip + GitHub Action Marketplace.
- **v0.5** ✅ — `wallfacer suggest` (auto-detect which packs apply), `wallfacer coverage` (tool × pack matrix + `--strict` CI gate), `wallfacer report --html` (self-contained dashboard).
- **v0.6** ✅ — stateful fuzzing with persistent corpus + 90/10 mutate-vs-random (`fuzz --corpus-feedback`), `mcp-spec-conformance` pack (validates the MCP wire-format itself), `context-poisoning` pack (detects malicious servers planting prompt injections), `$.tool.{name,description,annotations}` DSL extension.
- **v0.7** ✅ — sequence corpus seeding (cross-pollinates fuzz + sequences), HTTP fault injection fixture (`502 / 504 / FIN-empty / FIN-mid / slow`), real input shrinker (`corpus minimize --replay`, delta-debug), real-world campaign across 6 popular OSS MCPs (clean-bill of health, methodology in `docs/real-world-findings.md`).
- **v0.8** — per-invariant shrinking (re-evaluate the exact failing invariant on each shrink trial), HTTP torture mode (`torture --mode http-faults` driving the v0.7 fault fixture under concurrent load), grammar-aware prompt-injection variants (jailbreak chains-of-thought, multilingual, base64-encoded), continued real-world campaign on the next batch of OSS MCPs.

## Contributing

Issues, PRs, and pack contributions welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) if it exists, otherwise open a discussion on the [issues](https://github.com/lacausecrypto/mcp-wallfacer/issues) page.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
