# Architecture — wallfacer

This document describes how the workspace is laid out, how plans drive
runs against an MCP server, and where each Phase A-F change sits.

## Workspace layout

```
mcp-wallfacer/
├── Cargo.toml                  # workspace deps + lints (Phase A1/A2)
├── deny.toml                   # cargo-deny config (Phase A3)
├── .typos.toml                 # typos config (Phase A3)
├── crates/
│   ├── wallfacer-core/         # library: plans, generators, runner, IO
│   └── mcp-wallfacer-cli/      # binary: parses args, picks reporter
├── packs/                      # built-in rule packs (Phase F4)
│   ├── auth.yaml
│   ├── path-traversal.yaml
│   └── error-shape.yaml
├── examples/python_server/     # six-bug demo server (Phase F acceptance)
├── tests/fixtures/             # canonical fixtures (used by core e2e)
└── docs/                       # this directory
```

## High-level data flow

```
+----------------+        +---------------+       +--------------+
|  CLI commands  |  args  |  core::run::  | calls |  rmcp Client |
|  (cli crate)   |------->|  *Plan        |------>|  / MockClient|
|                |        |               |       |              |
|  picks the     |        | drives the    |       +------+-------+
|  Reporter and  | events | run, streams  |              |
|  config; never | <----- | findings to:  |              v
|  spawns calls  |        |               |       +--------------+
|  itself        |        +-------+-------+       | MCP server   |
+----------------+                |               +--------------+
                                  v
                          +---------------+
                          | Corpus disk   |
                          | (.wallfacer/) |
                          +---------------+
```

* Each CLI command parses args, builds a typed `Plan` from
  `wallfacer_core::run`, picks a `Reporter`, and calls
  `plan.execute(&client, &corpus, &mut *reporter)`.
* The plan is responsible for all execution: generating payloads, calling
  tools, persisting findings, and emitting `Reporter` callbacks
  (`on_run_start`, `on_iteration_*`, `on_finding`, `on_skipped`,
  `on_run_end`).
* The reporter never speaks MCP; it only renders. `HumanReporter` (table +
  progress bar), `JsonReporter` (`{findings, skipped}` JSON), and
  `SarifReporter` (SARIF 2.1.0) all live in `mcp-wallfacer-cli/src/reporters.rs`.
* The corpus on disk is the source of truth for findings. Plans stream
  writes (Phase E4): the in-memory `*Report` only carries counts and
  diagnostic lists.

## `wallfacer-core` modules

| Module | Role |
|---|---|
| [`client`](../crates/wallfacer-core/src/client.rs) | `Arc<RwLock<RunningService>>` wrapper around `rmcp` (Phase E1) |
| [`corpus`](../crates/wallfacer-core/src/corpus.rs) | Finding persistence + cooperative locks (Phase A5 / E3) |
| [`differential`](../crates/wallfacer-core/src/differential.rs) | Schema inference helpers + boundary-payload generator |
| [`finding`](../crates/wallfacer-core/src/finding.rs) | `Finding`, `FindingKind`, `Severity`, `ReproInfo` |
| [`mutate`](../crates/wallfacer-core/src/mutate/mod.rs) | Schema-driven payload generator: `compose`, `schema_gen`, `strategies` (Phases B1–B4) |
| [`property`](../crates/wallfacer-core/src/property/mod.rs) | YAML invariants DSL + runner (Phase D) |
| [`redact`](../crates/wallfacer-core/src/redact.rs) | Pattern-based scrubber for secrets before persistence (Phase A4) |
| [`run`](../crates/wallfacer-core/src/run/mod.rs) | Plans (`FuzzPlan`, `DifferentialPlan`, `PropertyPlan`, `TortureRun`), `McpExec` trait, `Reporter` trait, `MockClient` (Phase C/E) |
| [`sarif`](../crates/wallfacer-core/src/sarif.rs) | SARIF 2.1.0 serializer |
| [`seed`](../crates/wallfacer-core/src/seed.rs) | Canonical 256-bit seed derivation feeding `ChaCha20Rng` (Phase E5) |
| [`target`](../crates/wallfacer-core/src/target.rs) | `wallfacer.toml` loader; transports + output config |

## `mcp-wallfacer-cli` modules

| Module | Role |
|---|---|
| `commands/init` | `wallfacer init [--http|--stdio] [--ci]` (Phase F1) |
| `commands/doctor` | Lists tools / resources / prompts |
| `commands/fuzz` | Builds `FuzzPlan` |
| `commands/differential` | Builds `DifferentialPlan` (with `--learn`) |
| `commands/property` | Loads invariants (file or `--pack <name>`) into `PropertyPlan` (Phases C, F4) |
| `commands/torture` | Builds `TortureRun` (parallel / state-leak modes) |
| `commands/corpus` | `corpus list/show/replay/minimize` |
| `commands/ci` | Differential pass + SARIF/JSON/Human + severity threshold |
| `commands/replay` | `wallfacer replay <id>`: env-var-driven unredaction (Phase F2) |
| `commands/diff` | `wallfacer diff <a> <b>`: regressions / fixes (Phase F3) |
| `reporters` | `HumanReporter`, `JsonReporter`, `SarifReporter` |

## Plan lifecycle

```rust
let plan = FuzzPlan { /* iterations, mode, seed, glob filters, ... */ };
let report = plan.execute(&mut client, &corpus, &mut reporter).await?;
```

1. `select_tools` queries the server, applies include/exclude globs and
   the destructive detector (annotations + regex patterns + allowlist —
   Phase C5).
2. `Reporter::on_run_start(&RunInfo { kind, total_iterations, tools, ... })`.
3. For each `(tool, iteration)`:
   - `derive_seed_canonical` produces a 256-bit seed; `ChaCha20Rng`
     drives a `try_generate_payload` call (Phase B + E5).
   - On `Skip`, the tool is recorded in `report.skipped` and we move on.
   - On call success, no finding.
   - On `Hang/Crash/ProtocolError`, a `Finding` is built, written to
     `Corpus`, surfaced via `Reporter::on_finding`, and the plan calls
     `client.reconnect()` so subsequent iterations have a fresh
     transport (Phase E1).
4. `Reporter::on_run_end()` flushes summary tables / final JSON / SARIF.

`TortureRun` is a sibling: it fans out parallel calls under a shared
`CancellationToken` whose watchdog fires after `global_deadline = 4 ×
per-call timeout` (Phase E2), keeping the run wall-clock bounded.

## Reproducibility contract

A finding's `repro` block carries the seed (`u64` truncated form), the
tool call (post-redaction), the transport label, and the composition
trail (`oneOf`, `allOf` choices). Together with the master seed and the
tool name + iteration index, a replay re-derives the same
`ChaCha20Rng` and, given the same generator code, the same payload.

Replay is exact when:

* the wallfacer version matches (or only patch-level changes have
  happened);
* the tool's input schema hasn't drifted in a way that changes
  composition picks.

When the persisted payload contains `<redacted>` placeholders, the
`wallfacer replay <id>` command substitutes them locally from
`WALLFACER_REPLAY_<KEY>` environment variables (Phase F2). The
substitution is never echoed to logs or stdout.

## Test surface

```
cargo test --workspace
├── wallfacer-core tests (lib + integration)
│   ├── lib unit tests          # 65+ across compose, redact, run::*, etc.
│   ├── invariant_fixtures.rs   # walks tests/fixtures/invariants/*.yaml (Phase D)
│   ├── proptest_schemas.rs     # 200 synthetic schemas, ≥99% conformance (Phase B)
│   └── torture_no_deadlock.rs  # 4 crash-prone tools, <30s wall clock (Phase E)
└── mcp-wallfacer-cli e2e
    ├── doctor_lists_tools.rs
    ├── fuzz_finds_crash.rs
    ├── differential_catches_drift.rs
    ├── property_runs.rs
    ├── torture_finds_race.rs
    └── example_six_kinds.rs    # examples/python_server triggers 6 finding kinds (Phase F)
```
