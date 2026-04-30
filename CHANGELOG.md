# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely
and the project adheres to [SemVer](https://semver.org).

## v0.2.0 — 2026-04-30

A six-phase rewrite focused on robustness, correctness, and DX. The CLI
surface is largely backwards-compatible; the JSON output shape and a few
internal types changed (see "Breaking" below).

### Highlights

* **Full JSON Schema 2020-12 generation** — `$ref`, `$defs`/`definitions`,
  `allOf`, `oneOf`/`anyOf`, `not`, `if/then/else`, `dependentRequired`,
  plus `format` support for `email`/`uri`/`uuid`/`date-time`/`password`.
  Acceptance proptest: 200 synthetic schemas, **100 % conformance**.
* **Property DSL v2** — `all_of` / `any_of` / `not` combinators,
  `for_each`, `matches_schema` (inline JSON Schema), and explicit
  `{path: ...}` / `{value: ...}` operands. `version: 1` files keep
  parsing identically.
* **Plan-based execution layer** (`wallfacer_core::run`) — every command
  parses args, builds a `*Plan`, picks a `Reporter`, and hands off. The
  CLI commands are now thin wrappers (every `commands/*.rs` ≤ 153 LOC).
  Plans are unit-testable without spawning a child process via the new
  `MockClient`.
* **Robustness pass** — `Client` is `Clone` and reentrant
  (`Arc<RwLock<RunningService>>`); torture has cancellation tokens with
  a global watchdog (no deadlocks even with hung tools); corpus lock is
  configurable with exponential backoff; canonical 256-bit `ChaCha20Rng`
  seed.
* **Security by default** — secrets are redacted on persistence
  (`Authorization`, `Cookie`, `*-token`, `password`, `api_key`, ...);
  Unix corpus files written `0o600`; `wallfacer replay <id>` substitutes
  back from `WALLFACER_REPLAY_<KEY>` env vars without ever logging the
  unredacted payload.
* **Six-bug demo** — `examples/python_server/` triggers every
  `FindingKind` (Crash, Hang, SchemaViolation, PropertyFailure,
  ProtocolError, StateLeak); the e2e test
  `example_six_kinds.rs` walks each command end-to-end.

### Added

* `wallfacer init`: `--http`, `--stdio`, `--skip-invariants` flags. Now
  also writes a starter `invariants.yaml`. HTTP template references
  `${WALLFACER_BEARER}` so secrets stay out of the file.
* `wallfacer replay <id>`: top-level command. Loads a stored finding,
  substitutes `<redacted>` payload fields from `WALLFACER_REPLAY_<KEY>`
  env vars locally (never logged unless `--show-payload` is set), and
  asserts the original outcome reproduces.
* `wallfacer diff <baseline> <candidate>`: compares two corpus
  directories, reports regressions / fixes / persisting findings, with
  `--fail-on-regression` for CI gating.
* `wallfacer property --pack <name>`: built-in rule packs at
  `packs/{auth,path-traversal,error-shape}.yaml`.
* `wallfacer fuzz --coverage-strict`: exits `2` when any tool's schema
  could not be generated, gating CI on full coverage.
* `wallfacer fuzz --include`/`--exclude` accept full `globset` patterns
  (`**/foo`, `tools.{a,b}`, `[abc]`, `?`).
* `wallfacer_core::run` module: `FuzzPlan`, `DifferentialPlan`,
  `PropertyPlan`, `TortureRun`, plus the `McpExec` and `Reporter`
  traits. `MockClient::register_async` for tests that need real
  cancellation.
* `wallfacer_core::redact` module with `Redact` trait, applied to all
  corpus writes. 14 unit tests cover the patterns.
* `wallfacer_core::seed::derive_seed_canonical -> [u8; 32]` (SHA-256
  composite) feeding `ChaCha20Rng::from_seed`. Reproducibility contract
  documented at the top of `src/seed.rs`.
* `[destructive]` and regex-based `[allow_destructive]` config sections.
  Detection now layers MCP `tool.annotations.{destructive,read_only}_hint`,
  configured patterns, and an allowlist regex.
* `[output] lock_timeout_ms` (default `30_000`) with exponential backoff.
* `docs/architecture.md`; `docs/security.md` extended with the replay
  unredaction model.
* CI: `cargo-deny`, `cargo-audit`, `cargo-llvm-cov` (PR comment),
  `typos`, and `cargo doc --workspace --no-deps` with
  `RUSTDOCFLAGS=-D warnings`.

### Changed (breaking)

* JSON output: `fuzz` / `differential` / `property` / `torture` now
  print `{findings: [...], skipped: [...]}` instead of a top-level
  array. SARIF output is unchanged.
* `*Report` types in `wallfacer_core::run` carry `findings_count: usize`
  and stream the actual `Finding` objects to the reporter via
  `on_finding`. Findings are also written to disk immediately.
* `Client` is `Clone` and all methods take `&self` — including
  `reconnect` and `shutdown`. `McpExec::reconnect(&self)` accordingly.
* `wallfacer_core::client`, `wallfacer_core::corpus`, and
  `wallfacer_core::run` are the new home of orchestration logic; CLI
  modules use them directly.
* `derive_seed` returns the first 8 bytes of the new canonical 256-bit
  seed (was `Sha256[..8]` of the same components — same value, different
  derivation chain). `repro.seed` stays a `u64` for human readability.
* `Property` invariants files now declare `version: 1` or `version: 2`;
  any other value is rejected.

### Fixed

* Integer-range generation no longer overflows on `i64::MIN..=i64::MAX`
  (was producing `% 0` panics).
* JSONPath now goes through `serde_json_path` (RFC 9535): non-final
  wildcards, recursive descent, and filter expressions all work.
* `parse_duration("500ms")` now returns `Some(500ms)` (the legacy
  implementation matched `s` first and choked on the leftover `m`).
* `Property` runner module carries
  `#![deny(clippy::expect_used, clippy::unwrap_used, clippy::panic)]`
  so future regressions to panic-on-bad-invariant are caught at build
  time.

### Tests & quality

* 13 test suites, ~80 tests in total: lib units, fixture round-trip,
  proptest acceptance (200 schemas), torture-no-deadlock acceptance,
  six-kinds e2e, plus the existing per-command e2e.
* `cargo fmt --all --check`, `cargo clippy -D warnings`, and
  `cargo doc --no-deps` with `RUSTDOCFLAGS=-D warnings` are all clean.
* No `unwrap`/`expect`/`panic` in production source (workspace lints).

## v0.1.0

Initial release.

* Added `wallfacer init`.
* Added `wallfacer doctor`.
* Added `wallfacer fuzz`.
* Added `wallfacer differential`.
* Added `wallfacer property`.
* Added `wallfacer torture`.
* Added `wallfacer corpus`.
* Added `wallfacer ci` with SARIF output.
