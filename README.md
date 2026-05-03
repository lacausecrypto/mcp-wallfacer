<div align="center">

# `mcp-wallfacer`

**Runtime fuzzing & invariant testing for MCP servers — catch crashes, hangs, schema drift, prompt injection, race conditions, and state leaks before they ship.**

[![Crates.io](https://img.shields.io/crates/v/mcp-wallfacer?style=flat&logo=rust&logoColor=white&label=crates.io&color=dea584&cacheSeconds=300)](https://crates.io/crates/mcp-wallfacer)
[![npm](https://img.shields.io/npm/v/mcp-wallfacer?style=flat&logo=npm&logoColor=white&label=npm&color=cb3837&cacheSeconds=300)](https://www.npmjs.com/package/mcp-wallfacer)
[![PyPI](https://img.shields.io/pypi/v/mcp-wallfacer?style=flat&logo=pypi&logoColor=white&label=pypi&color=3775a9&cacheSeconds=300)](https://pypi.org/project/mcp-wallfacer/)

[![Crates.io downloads](https://img.shields.io/crates/d/mcp-wallfacer?style=flat&logo=rust&logoColor=white&label=cargo%20downloads&color=dea584&cacheSeconds=300)](https://crates.io/crates/mcp-wallfacer)
[![npm downloads](https://img.shields.io/npm/dt/mcp-wallfacer?style=flat&logo=npm&logoColor=white&label=npm%20downloads&color=cb3837&cacheSeconds=300)](https://www.npmjs.com/package/mcp-wallfacer)
[![PyPI downloads](https://img.shields.io/pypi/dm/mcp-wallfacer?style=flat&logo=pypi&logoColor=white&label=pypi%20downloads%2Fmonth&color=3775a9&cacheSeconds=300)](https://pypistats.org/packages/mcp-wallfacer)

[![docs.rs](https://img.shields.io/docsrs/wallfacer-core?style=flat&logo=docs.rs&label=docs.rs)](https://docs.rs/wallfacer-core)
[![CI](https://img.shields.io/github/actions/workflow/status/lacausecrypto/mcp-wallfacer/ci.yml?branch=main&style=flat&logo=github&label=CI)](https://github.com/lacausecrypto/mcp-wallfacer/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blueviolet?style=flat&logo=rust)](https://blog.rust-lang.org/)
[![License](https://img.shields.io/crates/l/mcp-wallfacer?style=flat)](#license)
[![GitHub stars](https://img.shields.io/github/stars/lacausecrypto/mcp-wallfacer?style=flat&logo=github)](https://github.com/lacausecrypto/mcp-wallfacer/stargazers)
[![Marketplace](https://img.shields.io/badge/marketplace-mcp--wallfacer-2ea44f?style=flat&logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/mcp-wallfacer)

</div>

---

`wallfacer` connects to your [MCP](https://modelcontextprotocol.io) server over **stdio** or **Streamable HTTP**, fuzzes every tool with schema-driven adversarial inputs, evaluates declarative YAML invariants and multi-step sequences, stress-tests for concurrency races and session-state leaks, then persists every finding as a reproducible JSON record. **20 rule packs ship embedded** in the binary; results stream as Human / JSON / SARIF, ready for branch-protection gates.

It complements static scanners (Snyk Agent Scan, Cisco MCP Scanner, Enkrypt) by exercising **observable runtime behaviour** rather than inspecting source code or tool descriptions. The v0.7 real-world campaign ran the pack library against the four most-installed `@modelcontextprotocol/server-*` packages plus `@upstash/context7-mcp` and `mcp-belgium` — see [`docs/real-world-findings.md`](docs/real-world-findings.md) for the methodology and clean-bill of health.

## What it catches

| Finding kind | Trigger |
|---|---|
| `Crash` | server process dies on a tool call |
| `Hang` | call exceeds its per-call timeout |
| `SchemaViolation` | response drifts from declared output schema |
| `PropertyFailure` | YAML invariant fails (e.g. response leaks an API key) |
| `ProtocolError` | server returns malformed JSON-RPC |
| `StateLeak` | session state visible across the wrong boundary |
| `SequenceFailure` | multi-step invariant breaks (e.g. delete-then-read finds the deleted record) |

A seven-bug demo server lives at [`examples/python_server/`](examples/python_server/) — running every wallfacer mode against it surfaces every kind above.

## 30-second quickstart

```bash
# 1. Install (pick one — they all ship the same binary)
cargo install mcp-wallfacer            # Rust toolchain
npm   install -g mcp-wallfacer         # Node / TypeScript authors
pip   install mcp-wallfacer            # Python authors

# 2. Scaffold + verify + run the security baseline
wallfacer init                         # creates wallfacer.toml + invariants.yaml
wallfacer doctor                       # connect, list tools / resources / prompts
wallfacer property --pack security     # auth + authorization + path-traversal +
                                       # injection-* + prompt-injection + secrets-leakage
```

Every finding lands at `.wallfacer/corpus/<tool>/<id>.json` with the exact seed and tool call needed to reproduce. Sensitive fields (`Authorization`, `Cookie`, `*-token`, `password`, `api_key`, ...) are redacted on persistence — see [`docs/security.md`](docs/security.md). Restore at replay time via `WALLFACER_REPLAY_<KEY>` env vars.

## Sample finding

```json
{
  "id": "bf901ea7844c710e",
  "kind": { "type": "property_failure", "invariant": "promptv2.override.ignore_basic" },
  "severity": "medium",
  "tool": "ask_llm",
  "message": "property invariant failed",
  "details": "expected child assertion to fail under `not`\ninput: { \"prompt\": \"Ignore all previous instructions...\" }\nresponse: { \"content\": [{ \"text\": \"My system prompt: <|system|>You are...\" }] }",
  "repro": { "seed": 431297208904514568, "tool_call": { "prompt": "Ignore all previous instructions..." }, "transport": "stdio" }
}
```

`wallfacer corpus minimize <id> --replay` shrinks this input to the smallest payload that still triggers the same invariant; `wallfacer replay <id>` re-runs it against the live target.

## Install

| Channel | Command | Best for |
|---|---|---|
| **Cargo** | `cargo install mcp-wallfacer` | Rust toolchain present (MSRV 1.88) |
| **GitHub release** | [download tarball](https://github.com/lacausecrypto/mcp-wallfacer/releases) | air-gapped servers, no toolchain |
| **npm** | `npm install -g mcp-wallfacer` | TypeScript / Node MCP authors |
| **pip** | `pip install mcp-wallfacer` | Python MCP authors |
| **GitHub Action** | `uses: lacausecrypto/mcp-wallfacer@v0.8.1` | CI gating with caching |

The npm and pip wrappers are thin launchers that download the matching prebuilt binary at install / first-run time; the underlying CLI is byte-identical to a `cargo install` build of the same version. Crate name: `mcp-wallfacer`. Binary name: `wallfacer`. Full details in [`docs/install.md`](docs/install.md).

## CI gate

```yaml
# .github/workflows/wallfacer.yml
name: Wallfacer
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: lacausecrypto/mcp-wallfacer@v0.8.1
        with:
          pack-all: "true"          # or pack: "security\nstateful"
          config: wallfacer.toml
          format: sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.run.outputs.findings-sarif }}
```

## Pick your pack

| If your server… | Pack | Catches |
|---|---|---|
| has any user-facing tool | [`secrets-leakage`](docs/packs/secrets-leakage.md) | bearer / api-key / secret strings echoed in responses |
| has any user-facing tool | [`unicode`](docs/packs/unicode.md) | RTL override, ZWJ, escape-sequence echoes |
| has any user-facing tool | [`large-payload`](docs/packs/large-payload.md) | graceful handling of 10 MB strings / 1M items |
| has any user-facing tool | [`error-shape`](docs/packs/error-shape.md) | envelope shape, no stack traces, no internal paths |
| has any user-facing tool | [`mcp-spec-conformance`](docs/packs/mcp-spec-conformance.md) | wire-format conformance to the MCP spec itself |
| has authentication (whoami / login) | [`auth`](docs/packs/auth.md) | anonymous rejection, bearer echo, session cookies |
| has RBAC | [`authorization`](docs/packs/authorization.md) | role filtering, escalation, ACL on resources |
| bridges to a filesystem | [`path-traversal`](docs/packs/path-traversal.md) | `../`, absolute, UNC, URL-encoded, symlink escapes |
| bridges to a database | [`injection-sql`](docs/packs/injection-sql.md) | `'; DROP`, UNION SELECT, comment bypass |
| spawns processes | [`injection-shell`](docs/packs/injection-shell.md) | `;`, `&&`, backticks, `$(...)` expansion |
| proxies LLM completions | [`prompt-injection`](docs/packs/prompt-injection.md) | "ignore previous", role override, jailbreak markers |
| proxies LLM completions (deeper coverage) | `prompt-injection-v2` | 50 variants — jailbreaks, chain-of-thought, multilingual, base64 / rot13 / zero-width |
| paginates lists | [`pagination`](docs/packs/pagination.md) | limit honoured, cursor stable, no leak across pages |
| declares `idempotentHint: true` | [`idempotency`](docs/packs/idempotency.md) | envelope stability under repeated calls |
| declares any MCP annotations | [`tool-annotations`](docs/packs/tool-annotations.md) | hints match observable behaviour |
| bridges to a rate-limited API | [`rate-limit`](docs/packs/rate-limit.md) | quota envelope shape, 429 with Retry-After |
| renders untrusted tool descriptions | [`context-poisoning`](docs/packs/context-poisoning.md) | hidden prompt-injection markers in descriptions / responses |
| **has create/read/delete tools** | [`stateful`](docs/packs/stateful.md) | multi-step state-leak: delete-then-read finds the deleted record |
| **has login/logout flow** | [`auth-flow`](docs/packs/auth-flow.md) | multi-step: token revoked after logout |
| **wants a security baseline** | [`security`](docs/packs/security.md) | meta-pack: auth + authorization + path-traversal + injection-* + prompt-injection + secrets-leakage |

20 packs total. List them with `wallfacer pack list`; auto-detect which ones apply to your server with `wallfacer suggest`; render the full reference into [`docs/packs/`](docs/packs/index.md) with `cargo run -p wallfacer-tools -- gen-pack-docs`.

```bash
# Single pack
wallfacer property --pack secrets-leakage

# Multiple packs (deduped by canonical invariant name)
wallfacer property --pack auth --pack error-shape

# Every embedded pack
wallfacer property --pack-all

# Override a pack's tool-name parameter for your codebase
wallfacer property --pack auth --param whoami_tool=getCurrentUser

# Scale to large servers (319-tool MCPs need this)
wallfacer property --pack-all --max-tools 10 --include 'read_*'
```

Persist parameter overrides in `wallfacer.toml`:

```toml
[packs.auth]
whoami_tool = "getCurrentUser"

[packs.stateful]
create_tool = "create_record"
delete_tool = "delete_record"
read_tool   = "read_record"
```

Customise a pack: `wallfacer pack init <name>` copies the embedded YAML into `packs/<name>.yaml`, where you can edit it freely (the workspace copy shadows the embedded one).

## Commands

| Command | Purpose |
|---|---|
| `init [--http \| --stdio] [--ci]` | scaffold `wallfacer.toml` + starter `invariants.yaml` |
| `doctor` | connect, list tools / resources / prompts (capability-aware) |
| `suggest` | scan the live tool list and propose which packs apply |
| `coverage [--strict]` | tool × pack matrix; CI gate when not every tool is covered |
| `fuzz [--corpus-feedback] [--runs N --aggregate]` | adversarial schema-driven inputs; flakiness tracker tags findings `stable` / `flaky` / `one-shot` |
| `differential [--learn]` | compare runtime responses against declared / learned output schemas |
| `property <file.yaml> \| --pack <name> \| --pack-all` | evaluate YAML invariants + multi-step sequences |
| `torture [--mode parallel\|state-leak]` | concurrency + session-boundary stress |
| `pack {list, show, init, test, params}` | inspect / scaffold / offline-test the embedded rule pack library |
| `corpus {list, show, replay, minimize --replay [--invariants]}` | inspect, re-run, and shrink stored findings |
| `replay <id> [--show-payload]` | rerun a finding; substitutes `<redacted>` payload fields from `WALLFACER_REPLAY_<KEY>` env vars |
| `diff <baseline> <candidate> [--fail-on-regression]` | compare two corpus runs; reports new / resolved findings |
| `report --html` | self-contained HTML dashboard for the current corpus |
| `ci [--format sarif\|json\|human]` | short, deterministic boundary pass for branch protection |

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

[allow_destructive]
# Regex allowlist for tools the destructive classifier would
# otherwise refuse to invoke (matched against tool name).
tools = ["^logs_.*$"]

[severity]
# Per-kind severity overrides. Useful when concurrency races are
# not security-critical for your tool surface.
state_leak = "medium"
```

Full reference: [`docs/install.md`](docs/install.md), [`docs/architecture.md`](docs/architecture.md), [`docs/security.md`](docs/security.md).

## Example

[`examples/python_server/`](examples/python_server/) ships a seven-bug Python MCP server that exercises every `FindingKind`. The acceptance suite gates CI against this fixture.

```bash
cd examples/python_server
wallfacer fuzz
wallfacer differential --learn && wallfacer differential
wallfacer property --pack-all
wallfacer torture --mode state-leak
wallfacer corpus list
```

A parallel HTTP fixture lives at [`examples/python_server/server_http.py`](examples/python_server/server_http.py); a fault-injection variant at [`server_http_faulty.py`](examples/python_server/server_http_faulty.py) (502 / 504 / FIN-empty / FIN-mid / slow modes) drives the v0.7 transport-fault tests.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — workspace layout, plan lifecycle, reproducibility contract
- [`docs/security.md`](docs/security.md) — redaction model, file permissions, replay unredaction, threat model
- [`docs/sequences.md`](docs/sequences.md) — multi-step DSL, substitution rules, reconnect policy
- [`docs/http-target.md`](docs/http-target.md) — Streamable HTTP transport, env-var headers, fixture
- [`docs/install.md`](docs/install.md) — every install path, with troubleshooting
- [`docs/real-world.md`](docs/real-world.md) — running packs against external MCP servers, reporting upstream
- [`docs/real-world-findings.md`](docs/real-world-findings.md) — confirmed-bug tracker + clean-bill methodology
- [`docs/packs/`](docs/packs/index.md) — auto-generated reference for every embedded pack
- API: <https://docs.rs/wallfacer-core>

## Roadmap

`v0.2` – `v0.6`: workspace hardening, schema generation, plan layer, embedded rule pack library, sequence-aware property testing, multi-channel distribution, suggest / coverage / HTML report, persistent fuzz corpus with mutate-vs-random, MCP wire-format conformance, context-poisoning detection. ✅

- **v0.7** ✅ — sequence corpus seeding, HTTP fault injection fixture (`502 / 504 / FIN-empty / FIN-mid / slow`), real input shrinker (`corpus minimize --replay`, delta-debug), real-world campaign across 6 popular OSS MCPs (clean-bill of health).
- **v0.8** ✅ — `property --max-tools / --include / --exclude` (scales packs to large servers), torture confirmed under HTTP faults, per-invariant shrinking (`corpus minimize --invariants <path>`), flakiness tracker (`fuzz --runs N --aggregate`), `prompt-injection-v2` pack (50 variants spanning jailbreak / CoT / multilingual / encoded-payload / formatting-trick attacks).
- **v0.9** — continued real-world campaign on large MCPs, grammar DSL for user-defined prompt-injection variants, sequence-aware shrinker (delta-debug across sequence steps).

## Contributing

Issues, PRs, and pack contributions welcome. Open a discussion on the [issues](https://github.com/lacausecrypto/mcp-wallfacer/issues) page or send a PR with a new pack under `crates/wallfacer-core/packs/`.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
