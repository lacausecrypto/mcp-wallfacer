# Real-world validation

Phase K — running wallfacer rule packs against production MCP servers
and reporting findings upstream.

This guide describes how to:

1. **Pick** a target MCP server (yours or an open-source one).
2. **Configure** wallfacer to talk to it.
3. **Run** the relevant packs in low-blast-radius mode.
4. **Triage** findings (real bug vs. false positive vs. pack
   parameter-tuning).
5. **Report** confirmed bugs to the upstream maintainer.

Wallfacer is **non-destructive by default** — the destructive-tool
detector blocks anything that looks like `delete_*` / `drop_*` /
`destroy_*` unless you explicitly opt in. Read the threat model in
[`security.md`](./security.md) before pointing it at production.

## Picking a target

Three categories work well for community validation:

- **Mainstream OSS servers**, e.g. `mcp-server-fetch`,
  `mcp-server-filesystem`, `mcp-server-git`, `mcp-server-postgres`.
  These have a maintainer to report to and a wide user base.
- **Your own MCP servers** (if you've built any). Run wallfacer locally
  before publishing.
- **A vendor's hosted MCP** (only if you have permission to test —
  pen-testing without authorization is illegal in most jurisdictions).

## Configuring the target

Spawn the server locally over stdio:

```bash
mkdir wallfacer-runs/mcp-server-fetch && cd wallfacer-runs/mcp-server-fetch
wallfacer init --stdio
```

Edit `wallfacer.toml` to point at the target's launch command:

```toml
[target]
kind = "stdio"
command = "uvx"          # or `npx -y`, `python3`, `cargo run --bin server`, ...
args = ["mcp-server-fetch"]
timeout_ms = 5000
```

For HTTP Streamable transports:

```toml
[target]
kind = "http"
url = "http://localhost:8000/mcp"

[target.headers]
Authorization = "Bearer ${WALLFACER_BEARER}"
```

Confirm the connection:

```bash
wallfacer doctor
```

## Picking packs to run

Use the matrix in the [main README](../README.md#when-to-use-which-pack).
For a fetch-style server (HTTP requests), the relevant packs are:

```bash
wallfacer property --pack secrets-leakage
wallfacer property --pack unicode
wallfacer property --pack large-payload
wallfacer property --pack error-shape
wallfacer property --pack tool-annotations
```

For a filesystem server, add:

```bash
wallfacer property --pack path-traversal
```

For a database bridge:

```bash
wallfacer property --pack injection-sql
```

For shell-out / process tools:

```bash
wallfacer property --pack injection-shell
```

Each pack will likely need parameter overrides matching the target's
tool names. Use `wallfacer pack params <name>` to list the parameters,
then either pass `--param key=value` flags or persist the overrides:

```toml
[packs.path-traversal]
read_file_tool = "fetch_file"

[packs.secrets-leakage]
witness_tool = "fetch"
witness_field = "url"
```

## Triage workflow

After each run wallfacer prints findings to stdout (Human / JSON /
SARIF) and writes them to `.wallfacer/corpus/`. For each finding:

1. **Reproduce locally** — `wallfacer replay <finding-id>` runs the
   exact tool call. Confirm the buggy behavior is deterministic.
2. **Classify**: real bug, pack-parameter mismatch, or pack false
   positive.
3. **Minimize** — `wallfacer corpus minimize <id> --replay` shrinks
   the input by re-driving it against the live target (delta-debug
   on object keys / string halving / array element drops). For
   `property_failure` findings, v0.8 auto-engages the per-invariant
   predicate so the shrinker re-evaluates the exact failing
   invariant on every trial; pass `--invariants <path>` when the
   invariant lives in a custom workspace pack.
4. **Document** — `wallfacer corpus show <id>` for the JSON record.

For pack false positives: open an issue against `mcp-wallfacer` with
the finding ID and a justification. We'll either narrow the pack or
add a parameter to gate it.

For real bugs: skip to "Reporting upstream".

## Reporting upstream

Use the template at [`docs/templates/upstream-report.md`](./templates/upstream-report.md)
when filing an issue against the MCP server. Include:

- The exact wallfacer command + tag (`wallfacer --version`).
- The pack name and invariant name.
- The reproducer — `wallfacer replay <id>` output, with secrets
  re-redacted before sharing.
- The expected vs. observed behavior.

If the bug is security-relevant (CVE-class), follow the upstream's
private security disclosure channel rather than a public issue.

## Wallfacer real-world tracking

We keep a list of confirmed real-world findings produced by wallfacer
packs at [`docs/real-world-findings.md`](./real-world-findings.md).
After confirming a bug upstream, file a PR adding a row.

## Continuous validation

`.github/workflows/real-world.yml` provides a scaffolded GitHub Actions
workflow you can adapt to run packs against external servers on a
schedule. It's intentionally not enabled by default — the targets, the
overrides, and the upstream reporting all need human curation.
