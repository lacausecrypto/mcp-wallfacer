# Real-world findings tracker

Confirmed bugs surfaced by wallfacer rule packs against external MCP
servers. Each row links to the upstream issue (or the security
advisory once disclosed).

| Date | Server | Pack / Invariant | Severity | Upstream | Status |
|---|---|---|---|---|---|
| _Pending: Phase K v0.3 acceptance run scheduled by the project owner against their own MCP servers and a curated set of OSS targets._ | | | | | |

---

To add a row after filing an issue, follow [`real-world.md`](./real-world.md):

1. Confirm the finding with `wallfacer replay <id>` against a clean
   target.
2. File the issue using the template at
   [`templates/upstream-report.md`](./templates/upstream-report.md).
3. Open a PR against this file with the row above the divider, sorted
   by date descending.
