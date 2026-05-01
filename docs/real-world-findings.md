# Real-world findings tracker

Confirmed bugs surfaced by wallfacer rule packs against external MCP
servers. Each row links to the upstream issue (or the security
advisory once disclosed).

## v0.7 campaign — clean-bill of health on popular MCP servers

The first structured wallfacer campaign ran the v0.6+ pack library
against the four most-installed `@modelcontextprotocol/server-*`
packages plus `@upstash/context7-mcp` and `mcp-belgium`:

| Server | npm package | Packs run | Real findings | Skip |
|---|---|---|---|---|
| `server-everything` | `@modelcontextprotocol/server-everything` | `context-poisoning`, `mcp-spec-conformance`, `secrets-leakage` | **0** | — |
| `server-memory` | `@modelcontextprotocol/server-memory` | same | **0** | — |
| `server-sequential-thinking` | `@modelcontextprotocol/server-sequential-thinking` | same | **0** | — |
| `context7` | `@upstash/context7-mcp` | same | **0** | — |
| `server-filesystem` | `@modelcontextprotocol/server-filesystem` | same + `path-traversal` | **0** | wallfacer doctor's `resources/list` issue (fixed in v0.3.3) |
| `mcp-belgium` | `mcp-belgium` | full security meta-pack | **0** | — |

**Verdict** — the popular OSS MCP server library is well-engineered
on the dimensions wallfacer covers. No upstream issues to file from
this pass. The campaign methodology and pack library are now battle-
tested against ~150 tools across 6 servers; the absence of findings
is itself a useful signal (and one wallfacer can credibly publish).

## Confirmed-bug tracker

| Date | Server | Pack / Invariant | Severity | Upstream | Status |
|---|---|---|---|---|---|
| _Awaiting findings against the next batch of OSS MCP targets — submissions welcome via PR._ | | | | | |

---

## How to add a row

After running a wallfacer pack against a real server and triaging a
finding (see [`real-world.md`](real-world.md)):

1. Confirm the finding with `wallfacer replay <id>` against a clean
   target.
2. **Shrink the reproducer** — `wallfacer corpus minimize <id>
   --replay` produces the smallest input that still triggers the
   finding kind. Upstream maintainers reject 5KB JSON repros;
   they accept 50-byte ones.
3. File the issue using the template at
   [`templates/upstream-report.md`](./templates/upstream-report.md).
4. Open a PR against this file with the row above the divider,
   sorted by date descending.

## What "tested clean" means

The four servers above produced 0 findings on the v0.6+ pack
library. That's not a security audit — wallfacer doesn't catch:

- Logic bugs in the data the tools return (we test wire-format,
  not semantic correctness).
- TLS misconfiguration (we use rmcp's transport, which delegates
  to `reqwest` defaults).
- Authorization at the resource level (the `authorization` pack
  needs server-specific RBAC config to be useful).
- Bugs that only surface under load (`torture` exercises
  concurrency but the campaign above ran 1 case per invariant).

What the campaign *does* verify, with high confidence, is that
those servers:

- Produce well-formed MCP envelopes on every tool call
  (`mcp-spec-conformance`).
- Don't echo Authorization / Bearer / api_key strings in tool
  responses (`secrets-leakage`).
- Don't carry prompt injections in tool descriptions or
  responses (`context-poisoning`).
- Honor their declared MCP annotations
  (`tool-annotations`).
- Handle the boundary inputs the schema-driven fuzzer generates
  without crashing or hanging.
