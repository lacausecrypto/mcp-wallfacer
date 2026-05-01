# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely
and the project adheres to [SemVer](https://semver.org).

## v0.4.3 — 2026-05-01

Tooling-only patch — no functional change to the wallfacer CLI.

### Fixed

* **GitHub Marketplace publish.** The composite action's `name`
  field was the bare `wallfacer`, which clashes with an existing
  GitHub user / org / action and gets rejected by the Marketplace
  validator. Renamed to `mcp-wallfacer` to match the crates.io,
  npm, and pip package names. Consumers using
  `uses: lacausecrypto/mcp-wallfacer@v0.4.3` are unaffected.
* **Release workflow no longer fails on already-published versions.**
  The previous `cargo publish --workspace --locked` step painted
  the Release run red whenever the maintainer published manually
  before CI got there. The step now grep's stderr for
  `already (uploaded|exists|published)` and exits 0 on those
  patterns; any other publish failure still fails the job.
* **Action's default `version: v0.4.3`** so a fresh
  `uses: lacausecrypto/mcp-wallfacer@main` pulls a real published
  release.

## v0.4.2 — 2026-05-01

Phase M: **HTTP / Streamable transport gated in CI**. v0.3 already
shipped the HTTP target code path through `rmcp::StreamableHttpClientTransport`,
but it was only exercised against external servers in manual smoke
tests. v0.4.2 adds a local HTTP MCP fixture, an end-to-end
acceptance test, and the missing operator docs.

### Added

* **HTTP MCP fixture** at
  [`examples/python_server/server_http.py`](examples/python_server/server_http.py)
  — pure-stdlib Python (`http.server.ThreadingHTTPServer`) that
  exposes the same buggy tool catalog as the stdio `server.py` over
  a single `POST /mcp` endpoint. Replies with
  `Content-Type: application/json`, which `rmcp`'s client accepts
  alongside the SSE variant.
* **Phase M acceptance suite** at
  [`crates/mcp-wallfacer-cli/tests/e2e/http_target_runs_packs.rs`](crates/mcp-wallfacer-cli/tests/e2e/http_target_runs_packs.rs).
  Two tests:
  - `http_transport_runs_secrets_leakage_pack_against_python_fixture`
    spawns the HTTP fixture, points wallfacer at it, runs the
    `secrets-leakage` pack, and asserts the same findings surface
    over HTTP as over stdio (the fixture's `bug_log` echo trips
    `secrets.bearer_tokens_not_echoed` etc).
  - `http_transport_doctor_lists_tools_with_capability_aware_resources`
    confirms `doctor` reports `transport=http` and renders `n/a`
    for the resources / prompts capabilities the fixture doesn't
    advertise (the v0.3.3 capability-aware fix applies cleanly to
    HTTP targets too).
* **`docs/http-target.md`** — operator-facing reference covering
  `[target] kind = "http"` config, env-var header expansion (`${VAR}`
  added in v0.3.2), the local fixture, what's CI-gated vs.
  manually-verified, and known limitations (no HTTP-specific
  torture mode yet).

### Tests & quality

* New e2e test exercises the HTTP transport end-to-end on every CI
  run; the previous coverage was stdio-only against
  `examples/python_server/server.py`.
* `pack test --all` still 117/117. `cargo fmt`, `cargo clippy -D
  warnings`, `cargo test --workspace --locked`, and
  `RUSTDOCFLAGS=-D warnings cargo doc` all clean.

### Notes

* The Phase M fixture is **JSON-only** (no SSE push). `rmcp` accepts
  both `application/json` and `text/event-stream` responses; servers
  that speak only SSE are not currently CI-gated but should work
  end-to-end based on the manual smoke tests against `mcp-belgium`
  and `@modelcontextprotocol/server-everything`. Tracking that as a
  v0.4.3+ follow-up.
* No HTTP-specific torture pack yet — `wallfacer torture` runs over
  HTTP but the destructive guard / cancellation paths haven't been
  hardened against HTTP-specific failure modes (proxy 502s,
  mid-stream disconnects). Out of scope for this release.

## v0.4.1 — 2026-05-01

Phase N: **distribution + reach**. Same Rust binary, four new install
paths so MCP authors who don't already have a Rust toolchain can run
wallfacer without building from source.

### Added

* **npm wrapper** at [`npm/`](npm/). `npm install -g mcp-wallfacer`
  drops a `wallfacer` shim on `$PATH`. The wrapper's `postinstall`
  detects the host platform, downloads the matching tarball from the
  GitHub release, and extracts the binary into the package's `bin/`
  directory. `bin/wallfacer.js` is a tiny shim that forwards argv +
  stdio to the binary and propagates its exit code.
* **pip wrapper** at [`pip/`](pip/). `pip install mcp-wallfacer`
  installs a pure-stdlib Python launcher. The first invocation
  downloads the matching binary into a per-user cache
  (`~/.cache/mcp-wallfacer` / `~/Library/Caches/mcp-wallfacer` /
  `%LOCALAPPDATA%\mcp-wallfacer`) and execs it. Subsequent calls reuse
  the cached binary.
* **GitHub Action** at [`action.yml`](action.yml). Composite action
  `uses: lacausecrypto/mcp-wallfacer@v0.4.1` that detects the runner
  platform, caches the binary under `runner.tool_cache`, and forwards
  inputs (`pack`, `pack-all`, `config`, `format`, `seed`, `cases`,
  `fail-on-finding`) to `wallfacer property`. SARIF / JSON outputs are
  exposed as action outputs for downstream `upload-sarif` /
  artefact-upload steps.
* [`docs/install.md`](docs/install.md) — operator-facing guide
  covering all five install paths (cargo, GitHub release, npm, pip,
  GitHub Action).
* [`.github/workflows/action-smoke.yml`](.github/workflows/action-smoke.yml)
  — CI smoke test that exercises the composite action against the
  example python_server on Linux + macOS.

### Notes

* The wrappers do **not** pin a specific binary version — they default
  to the matching `v<package version>` GitHub release, which means
  `npm install mcp-wallfacer@0.4.1` always downloads `v0.4.1`. Pass
  `WALLFACER_VERSION=v0.x.y` (npm + pip) or the action's `version`
  input to override.
* Neither wrapper requires a network connection at install time when
  `WALLFACER_SKIP_INSTALL=1` (npm) or `WALLFACER_CACHE_DIR=<dir>`
  pointing at a pre-populated cache (pip) — useful in container
  builds that vendor the binary themselves.
* The GitHub release v0.4.0 binaries are pulled by the wrappers, so
  v0.4.1's npm / pip / Action default to v0.4.1 binaries that this
  release also publishes.

## v0.4.0 — 2026-05-01

Phase L: **sequence-aware property testing**. v0.3 covered every tool
in isolation; v0.4 ships a multi-step DSL so wallfacer can express
invariants that depend on the *interaction* of several tools — which
is where most real-world MCP bugs hide (state leaks, session
fixation, broken pagination cursors). The wire format and CLI surface
are backwards-compatible: every v0.3 pack keeps parsing and running
unchanged.

### Highlights

* **`sequences:` block in the property DSL.** A sequence is a chain
  of `SequenceStep`s sharing a single MCP client. Steps can `bind`
  their `{input, response}` envelope under a name, and later steps
  reference it via `{{steps.<bind>.<jsonpath>}}` placeholders inside
  their `with:` arguments. Substitution is late-bound: a step's
  inputs can depend on the *response* of a previous step.
* **Two new embedded packs:** `stateful` (create/read/delete
  state-leak detection) and `auth-flow` (login/logout token
  revocation). Total embedded packs goes from 15 to 17.
* **`FindingKind::SequenceFailure { sequence, step_index, step_call }`**
  for the new finding class. Severity defaults to `High`. SARIF
  output, the JSON envelope, and the corpus writer all handle the
  new kind.
* **`apply.input: schema_valid`** (added in v0.3.3, now used by
  every `for_each_tool` template that doesn't supply its own
  `fixed:` block) — the runner pulls the per-case input from the
  live tool's `inputSchema` using `mutate::generate_payload(GenMode::Conform)`.
* **`docs/sequences.md`** walks the YAML shape, the substitution
  rules, the reconnect policy, and the two shipped packs.

### Added

* `wallfacer_core::property::dsl::{Sequence, SequenceStep, StepOutcome,
  SequenceFixture}` — public types backing the new DSL block.
* `wallfacer_core::run::sequence::{SequencePlan, SequenceReport,
  SkippedSequence, SequenceContext, evaluate_sequence_fixture,
  SequenceFixtureOutcome}` — runner + fixture-evaluator.
* `wallfacer_core::property::runner::evaluate_step_assertions(&[Assertion],
  input, response)` — extracted helper used by the sequence runner;
  the existing `evaluate(invariant, input, response)` now delegates
  to it.
* `PropertyPlan::defer_run_end` flag for chaining a property and a
  sequence sub-run through a single reporter without splitting the
  output stream. Default `false`; the CLI sets it to `true` when
  the loaded pack has both invariants and sequences.
* Embedded packs: `stateful.yaml`, `auth-flow.yaml` plus
  `EMBEDDED_PACKS` updated.
* `docs/sequences.md` — operator-facing reference.

### Changed

* `for_each_tool[*].apply` accepts an optional `input: schema_valid`
  field. When set, overrides `fixed`/`generate` and the runner
  derives the per-case input from the tool's declared schema.
* `tool-annotations` pack rewritten in v0.3.3 stays as is (envelope
  shape + open-world path leak); the redundant invariants on
  `read_only` / `idempotent` are gone.

### Reconnect semantics for sequences

Single-tool invariants reconnect aggressively after every transport
hang, protocol error, or assertion failure. Sequences depend on
per-connection state (auth tokens, in-memory bookkeeping, session
ids), so the sequence runner does **not** reconnect between steps —
a failing step marks the sequence failed, the rest of the steps are
skipped, but the client survives so subsequent sequences observe
whatever state the broken step left behind. See `docs/sequences.md`
for the full policy.

### Tests & quality

* New e2e test `sequence_catches_state_leak`: the `stateful` pack
  catches the leaky-`record_delete` bug planted in
  `examples/python_server`. `pack test --all` covers the four new
  sequence fixtures (2 in `stateful`, 2 in `auth-flow`).
* `cargo fmt`, `cargo clippy -D warnings`, `cargo test --workspace
  --locked`, `RUSTDOCFLAGS=-D warnings cargo doc --workspace
  --no-deps` all clean.

## v0.3.3 — 2026-05-01

Patch driven by a real-world test campaign against seven public MCP
servers (`mcp-belgium`, `mcp-sophon`, `@modelcontextprotocol/{server-everything,
server-filesystem, server-memory, server-sequential-thinking}`,
`@upstash/context7-mcp`). Every "finding" produced by the campaign turned
out to be a wallfacer bug, not a target bug — so this release fixes the
three classes that hid behind the noise.

### Fixed

* **`wallfacer doctor` now respects MCP `ServerCapabilities`.** Doctor
  used to call `resources/list` and `prompts/list` unconditionally, so
  any server that didn't declare those capabilities at init time
  bailed out with `MCP error -32601: method not found`. Doctor now
  checks `Client::server_capabilities()` and renders `n/a` for
  capabilities the server didn't advertise. Affected: every MCP server
  that exposes only tools (`mcp-sophon`, `@modelcontextprotocol/server-filesystem`,
  `@upstash/context7-mcp`, …).
* **Property runner skips invariants whose target tool the server
  doesn't advertise.** Pack defaults like `witness_tool: "echo"` used
  to drag the runner into a reconnect-on-`method-not-found` loop that
  looked like a hang to the operator (observed on `mcp-sophon` during
  the unicode pack). Missing tools are now reported via
  `Reporter::on_skipped` and surfaced under
  `PropertyReport::missing_tools` so the operator can either override
  the pack parameter or accept the gap.

### Added

* **`apply.input: schema_valid`** — new strategy on
  `for_each_tool.apply` blocks. When set, the runner generates the
  per-case input from the live tool's `inputSchema` using
  `mutate::generate_payload(GenMode::Conform)` instead of falling back
  to `fixed: {}`. This unblocks the entire class of `tool-annotations`
  invariants that used to fire on legitimate schema-validation errors
  (a tool requiring a `path` argument was getting called with `{}` and
  returning `isError: true`, which the invariant interpreted as a
  contract violation rather than a missing-argument rejection).
* `Client::server_capabilities()` returning a clone of the announced
  `ServerCapabilities`. `Client::list_resources` /
  `Client::list_prompts` short-circuit to `Ok(vec![])` when the
  corresponding capability isn't advertised.

### Changed

* **`tool-annotations` pack rewritten** to focus on the MCP wire-format
  contract instead of behavioural assumptions. Two invariants now:
  1. `envelope_well_formed.<tool>`: every response must include a
     `content` array (applies to every tool, including those returning
     `isError: true`).
  2. `open_world_no_internal_path_leak.<tool>`: openWorld-hinted tools
     must not echo `/Users/`, `/home/`, `C:\Users\` paths in their
     text content. Now safe against tools that return non-text content
     (image, blob): the regex check is wrapped in `any_of` with a
     fallback that matches when `content[0].text` isn't a string.
  The previous `read_only_call_does_not_set_isError` and
  `idempotent_call_yields_structured_response` invariants are removed
  — they required target-specific knowledge (which paths exist, what
  state mutates) that a generic pack can't have. Operators who want
  those checks should write per-server invariants in their own
  workspace `packs/`.
* `for_each_tool[*].where` is now optional. Templates that apply to
  every tool no longer need an empty `where: {}`.

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
