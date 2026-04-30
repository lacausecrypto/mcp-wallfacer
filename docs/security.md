# Security model — wallfacer

This document describes the security guarantees and limitations of
`mcp-wallfacer`, with a focus on what gets persisted on disk and shared in CI
artefacts.

Wallfacer is a *client* harness: it spawns or connects to an MCP server you
control, exercises it with generated payloads, and records findings. The
harness itself does not execute untrusted server output, but the data it
records (tool inputs, transport metadata, inferred schemas) can contain
secrets your server interacts with.

## Persistence locations

Wallfacer writes to the following paths under your repository root:

| Path | Content | Phase A protection |
|---|---|---|
| `.wallfacer/corpus/<tool>/<finding-id>.json` | Findings (crash, hang, schema violation, ...) with reproducer payload | Redacted + `0o600` on Unix |
| `.wallfacer/inferred_schemas/<tool>.json` | Inferred output schemas (shape only) | Default umask |
| `.wallfacer/.lock` | Cooperative lock between concurrent runs | Default umask |

## Redaction (Phase A4)

Before a finding lands on disk, it is filtered through
[`wallfacer_core::redact::Redact`](../crates/wallfacer-core/src/redact.rs).

What gets masked:

* **HTTP headers** named `Authorization`, `Proxy-Authorization`, `Cookie`,
  `Set-Cookie`, or any name containing `token`, `secret`, `password`,
  `bearer`, `api-key`, `api_key`, `apikey`, `private-key`, `private_key`
  (case-insensitive).
* **Stdio environment variables** matching the same markers (so a token
  passed as `API_TOKEN=...` does not leak via the stored target snapshot).
* **JSON payload fields** in the reproducer (`repro.tool_call`) whose key
  matches the same markers, plus the standalone word `auth` (so `auth_kind`
  matches but `author` does not).

Each match is replaced by the literal string `<redacted>`. The replacement is
**non-destructive**: the in-memory `Finding` is preserved untouched, only the
serialised form on disk is scrubbed. Replays from the corpus alone will see
placeholders; if you need to replay against real credentials, re-supply them
from your environment.

The `Finding::id` is computed from the **original** payload before
redaction. This keeps deduplication stable across runs even when secret
values would otherwise differ on each invocation.

### Redaction is not a sandbox

Redaction is best-effort and pattern-based. It will not catch:

* Secrets embedded in unstructured strings (e.g. an error message that
  echoes a token verbatim).
* Schemes that name secret fields with non-matching keys (`x_session`,
  `nonce`, ...).

If your server can echo secrets in tool responses or error messages, treat
the corpus directory as sensitive regardless.

## File permissions (Phase A5)

### Unix

Finding files are opened with `OpenOptions::mode(0o600)`, so they are
readable only by the owning user. If a file pre-exists with looser
permissions (e.g. from an older wallfacer version), permissions are tightened
to `0o600` after writing on a best-effort basis.

The directory `.wallfacer/` itself is created via `fs::create_dir_all` and
inherits the process umask. Operators on shared hosts should set a strict
umask (`umask 077`) before running wallfacer, or place the project in a
home directory that is not world-readable.

### Windows

Windows ACLs are not set by wallfacer. Files inherit ACLs from the parent
directory (`.wallfacer/corpus/`), which itself inherits from the workspace
root. On shared CI runners (e.g. self-hosted Windows agents), ensure the
workspace root is owned by the runner user and not readable by other
service accounts.

A native Windows ACL hardening pass is tracked in the v0.3 roadmap.

## Replay and unredaction (Phase F2)

`wallfacer replay <id>` replays a corpus finding against the configured
target. Because the persisted payload is redacted (Phase A4), the
command **locally** substitutes secrets back from environment variables:

* For each `<redacted>` value at JSON object key `K`, wallfacer reads
  `WALLFACER_REPLAY_<UPPER(K)>`.
* If set, the value is substituted into the call. If unset, the
  placeholder is left in place and a `note:` is printed to stderr listing
  the keys that need an env var.
* The substituted payload is **never logged**. `wallfacer replay
  --show-payload` opts into printing it to stderr (off by default).

This makes the corpus a safe artefact to share with reviewers: the
secrets to reproduce live only in the developer's shell.

## Threat model

Wallfacer assumes:

* The MCP server under test is **trusted code you control**. Wallfacer
  spawns it directly (stdio) or makes HTTP requests (Streamable HTTP).
* The host running wallfacer is **trusted**. Wallfacer does not isolate the
  child process (no seccomp, no nsjail).
* The corpus directory is **as sensitive as the secrets your server
  consumes**. Treat it like a credentials file: don't commit it,
  don't share it as a build artefact, and rotate any secret that appears in
  one.

Out of scope for v0.2:

* Sandboxing the child stdio process.
* Encrypting findings at rest.
* Authenticating CI artefact uploads.
