# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely
and the project adheres to [SemVer](https://semver.org).

## v0.3.2 — 2026-05-01

Patch focused on correctness and footgun-removal in the run plans and
the persistence layer. No surface API breakage; the wallfacer CLI keeps
the same flags and config schema.

### Fixed (correctness / security)

* **Server-echoed secrets no longer leak into the corpus.**
  `Finding::message` and `Finding::details` carry raw text from the MCP
  target — including error messages that may echo back the
  `Authorization` header or a key/value the tool was called with. Both
  fields now run through a new `redact_string()` regex pass that masks
  `Bearer <token>` / `Basic <token>` and `<sensitive-key>=<value>` /
  `<sensitive-key>: <value>` patterns. Defence-in-depth on top of the
  existing JSON-key redactor.
* **Filesystem-safe tool names in the corpus.** Tool names come from
  the server we are fuzzing; a malicious one declaring a name like
  `../../etc/passwd` could previously have steered the corpus writer
  outside `corpus_dir`. New `sanitize_tool_name()` helper replaces any
  character outside `[A-Za-z0-9_-]` with `_`.
* **`at_most` / `at_least` integer comparisons past 2^53.** The runner
  routed both operands through `f64`, so values above the f64 mantissa
  boundary (e.g. `9_007_199_254_740_993`) silently rounded to their
  neighbour and produced wrong-but-passing assertions. Comparisons now
  fast-path through `i128` for any pair of JSON integers.
* **Destructive guard in `torture` and `differential`.** Both run plans
  used to call out to target tools without checking the configured
  `[destructive]` / `[allow_destructive]` rules — only `fuzz` honoured
  them. They now refuse to invoke a destructive tool that isn't
  allowlisted, matching the existing `fuzz` behaviour.
* **`[destructive].patterns` is additive by default.** Setting one
  custom pattern previously suppressed the built-in keywords entirely
  (`delete`, `drop`, `destroy`, ...) — surprising, easy to miss, and
  exactly the wrong direction for a safety knob. Built-ins now stay
  active alongside user patterns; opt out explicitly with
  `replace_defaults = true`.
* **`ci --max-duration` actually enforces the timeout.** The flag
  parsed but was never wired through; long-running diff runs could
  blow past the budget. Now wrapped in `tokio::time::timeout` with a
  clean shutdown + exit `2` on overrun.
* **`compact_json` no longer panics on multi-byte chars.** The 120-byte
  truncation used to slice mid-codepoint when server output contained
  emoji or wide-form unicode; now snaps back to the nearest UTF-8 char
  boundary.

### Added

* **`${VAR}` expansion in `wallfacer.toml`.** The HTTP template already
  documented `Authorization = "Bearer ${WALLFACER_BEARER}"`, but the
  loader never substituted: secrets had to be hard-coded or piped
  through a separate templating step. Placeholders now resolve against
  the process env at load time. Use `$$` to keep a literal `$`; bare
  `$` is passed through unchanged for backward compatibility with
  shell-style command lines.
* **`[severity]` overrides applied across all run plans.** The
  config block existed but only `fuzz` honoured it; `differential`,
  `property`, `torture`, and `ci` now layer the override on every
  finding before persistence. New helpers: `FindingKind::keyword()`
  and `Finding::with_severity()`.
* **Empty `for_each` set surfaces a warning.** A typo'd JSONPath used
  to silently make an invariant vacuously true — the runner now logs a
  `tracing::warn!` so authors running with `-v` see the gap. Behaviour
  is unchanged when the empty set is intentional.
* **`corpus replay` honours `WALLFACER_REPLAY_<KEY>` env vars.** Reused
  the same unredaction step as `wallfacer replay <id>` so a `<redacted>`
  payload doesn't get sent verbatim to the server. Implementation
  shared via the new `commands/unredact` module; the standalone replay
  test moved with it.
* **`corpus minimize` prints a clear "inspect-only" note.** Automatic
  input shrinking is on the v0.4 roadmap; in the meantime the command
  no longer pretends to minimise — it states the limitation and prints
  the finding so authors can hand-shrink.

## v0.3.1 — 2026-05-01

Patch release fixing two release-pipeline bugs that surfaced while
cutting v0.3.0. No behavioral changes to the wallfacer CLI itself.

### Fixed

* **Embedded packs missing from the published tarball.** The 15 v3
  rule packs lived at `<workspace>/packs/` and were embedded via
  `include_str!("../../../../packs/...")`, but `cargo publish` only
  packages files that live inside the crate directory. The resulting
  v0.3.0 tarball referenced YAML files that weren't included, so
  `cargo install wallfacer-core@0.3.0` failed with `couldn't read
  packs/<name>.yaml: No such file or directory`. Moved the packs to
  `crates/wallfacer-core/packs/` so they ship with the crate.
* **macOS Intel release builds queued indefinitely.** The
  `release.yml` matrix used `macos-13` for `x86_64-apple-darwin`;
  GitHub's free-tier macos-13 runner pool is small and often saturated
  for hours (the v0.3.0 build sat queued for 1.5 h before being
  cancelled). Both Apple targets now build on `macos-latest` (Apple
  silicon hosts have the SDK to cross-compile to x86_64).

### Note

v0.3.0 was tagged and a GitHub release was published, but the crate
was never uploaded to crates.io because of the packaging bug above.
v0.3.1 is the first v0.3 release on crates.io.

## v0.3.0 — 2026-05-01

A five-phase rewrite of the rule-pack subsystem. The CLI surface gains
a `pack` command group and `property --pack` learns to compose multiple
packs in a single run. v0.2 packs (`auth`, `path-traversal`,
`error-shape`) keep working unchanged because the v3 format is a strict
superset of v2.

### Highlights

* **15 embedded rule packs** covering MCP-specific failure modes:
  `auth`, `authorization`, `error-shape`, `idempotency`,
  `injection-shell`, `injection-sql`, `large-payload`, `pagination`,
  `path-traversal`, `prompt-injection`, `rate-limit`, `secrets-leakage`,
  `tool-annotations`, `unicode`, plus a `security` meta-pack that
  inherits seven of them via `extends:`.
* **Pack format v3** — Mustache `{{var}}` templating, parameter
  declarations with `kind: string|number|bool|array`, default values,
  descriptions; `extends: [parent, ...]` for composition; `for_each_tool:`
  for fanning a single template across every tool that matches a name /
  description regex or annotation hint.
* **`wallfacer pack {list, show, init, test, params}`** — discover
  embedded packs, view rendered YAML with parameter overrides,
  scaffold a workspace pack from a template, run a pack against its
  `test_fixtures`, and inspect declared parameters.
* **Multi-pack composition** — `wallfacer property --pack auth
  --pack secrets-leakage` (or `--pack-all`) merges invariants by
  canonical name with dedup; the human reporter groups findings by
  source pack.
* **Auto-generated pack reference** — `cargo run -p wallfacer-tools --
  gen-pack-docs` renders [`docs/packs/<name>.md`](docs/packs/) for
  every embedded pack plus an [`index.md`](docs/packs/index.md)
  catalog. Checked into the repo so reviewers see pack changes in the
  same diff.
* **Real-world validation guide** —
  [`docs/real-world.md`](docs/real-world.md) walks through pointing
  wallfacer at an external MCP server (yours or OSS), triaging
  findings, and filing them upstream via
  [`docs/templates/upstream-report.md`](docs/templates/upstream-report.md).
  Confirmed findings are tracked in
  [`docs/real-world-findings.md`](docs/real-world-findings.md).

### Added

* `wallfacer-core::run::EMBEDDED_PACKS: &[(&str, &str)]` — every pack
  is `include_str!`'d into the binary; no on-disk dependency at run
  time.
* `wallfacer-core::run::pack` — `EmbeddedLoader`, `LayeredLoader<P, S>`
  (workspace `packs/` overrides embedded), `resolve_pack(name)` with
  cycle detection and depth cap.
* `wallfacer-core::property::dsl` — `PackMetadata`, `Parameter`,
  `ParamKind`, `ForEachToolBlock`, `ToolMatch`, `ToolAnnotationMatch`,
  `ApplyTemplate`, `parse_with_overrides`, `expand_for_each_tool`,
  `synthesize_for_test`, `render_template` (Mustache). Auto-injects
  `tool_name` as a no-op substitution when `for_each_tool:` is present.
* `wallfacer property --pack <name>` (repeatable), `--pack-all`,
  `--param key=value` flags. Findings carry their source pack name in
  human-readable output.
* `wallfacer pack list / show / init / test / params` subcommands.
* `crates/wallfacer-tools/` build-time crate (`publish = false`) with
  the `gen-pack-docs` subcommand.
* `.github/workflows/real-world.yml` — scaffolded GitHub Actions
  workflow for running packs against external MCP servers (manual
  dispatch only; cron trigger commented pending human curation).
* `examples/python_server/server.py` extended with `bug_log`,
  `read_file`, `query_db`, `run_shell`, `ask_llm`, `broken_reader`,
  `list_active_users` — exercising the new packs end-to-end.

### Changed

* Property DSL `MAX_VERSION = 3`. v1 / v2 files keep parsing
  identically; v3 unlocks metadata, parameters, templating, and
  `for_each_tool`.
* `wallfacer property --pack` previously accepted a single pack; the
  flag is now repeatable. The legacy single-pack form keeps working.
* Human reporter groups invariant findings by source pack when more
  than one pack is loaded.
* README has a new "When to use which pack" matrix linking each pack
  to its auto-generated reference under [`docs/packs/`](docs/packs/).

### Fixed

* `any_of` / `not` no longer escalate a missing JSONPath to a
  structural error — branches with absent paths fail softly so the
  surrounding combinator can still pass.
* `bad_protocol` example tool now raises a runtime error so the
  framework writes a JSON-RPC error envelope instead of hanging the
  test.
* YAML control-character handling in the `unicode` pack: tests
  `\x[0-9A-Fa-f]{2}` escape sequences in tool inputs rather than
  embedding literal NUL bytes (which YAML cannot carry).
* Pack regex parameters use single-quoted YAML around `{{...}}`
  substitution sites so `\d` / `\b` survive the substitution intact.

### Tests & quality

* 16 test suites, ~95 tests in total. New: pack fixture round-trip,
  pack parameter coverage, every pack declares v3 metadata, pack
  acceptance suites for Phases I and J, embedded-loader cycle
  detection.
* `cargo fmt`, `cargo clippy -D warnings`, `cargo test --workspace
  --locked`, and `cargo doc --no-deps` with `RUSTDOCFLAGS=-D warnings`
  all clean.

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
