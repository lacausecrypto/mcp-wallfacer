# HTTP / SSE targets

wallfacer treats `stdio` and Streamable HTTP MCP servers identically.
Once `[target] kind = "http"` is set in `wallfacer.toml`, every
command — `doctor`, `fuzz`, `differential`, `property`, `torture`,
`ci`, `replay` — runs against the HTTP endpoint without code-path
divergence.

## Config

```toml
[target]
kind = "http"
url = "http://127.0.0.1:8000/mcp"
timeout_ms = 5000

# Optional headers — `${VAR}` is expanded against the process env at
# load time (added in v0.3.2). `$$` escapes a literal `$`.
[target.headers]
Authorization = "Bearer ${WALLFACER_BEARER}"
X-API-Key = "${MY_API_KEY}"
```

The runner uses [`rmcp`](https://docs.rs/rmcp)'s
`StreamableHttpClientTransport` under the hood, so any server that
speaks the official Streamable HTTP transport works — both the
`application/json` single-response variant and the `text/event-stream`
SSE variant.

## What's actually tested

- **Phase M acceptance suite** — `crates/mcp-wallfacer-cli/tests/e2e/http_target_runs_packs.rs`
  spawns `examples/python_server/server_http.py` (a stdlib-only HTTP
  fixture) on a free port and runs the `secrets-leakage` pack +
  `doctor` against it. The same findings surface over HTTP as over
  stdio.
- **Capability-aware doctor** — when the server declares only the
  `tools` capability (no `resources`, no `prompts`), `doctor` shows
  `n/a` for the missing entries instead of bailing out with `MCP
  error -32601: method not found` (the v0.3.3 fix; see
  `docs/capability-negotiation.md` if it exists, otherwise the
  CHANGELOG).
- **Env-var header expansion** — `${WALLFACER_BEARER}` and similar
  placeholders resolve against the process env when the config is
  loaded, so secrets stay in your shell rather than landing in the
  repo.

## Local fixture for Phase M

Pure-stdlib Python HTTP MCP fixture at
[`examples/python_server/server_http.py`](../examples/python_server/server_http.py):

```bash
cd examples/python_server
python3 server_http.py 0     # 0 = bind to OS-assigned free port; printed on stdout
```

Then point wallfacer at it:

```toml
[target]
kind = "http"
url = "http://127.0.0.1:<printed-port>/mcp"
timeout_ms = 10000
```

The fixture exposes the same buggy tool catalog as the stdio
`server.py`, so identical packs surface identical findings.

## Real-world targets known to work

Tested manually against:

- **`mcp-belgium`** — stdio + Streamable HTTP. 63 tools, all packs
  pass against either transport.
- **`@modelcontextprotocol/server-everything`** — stdio reference.
  HTTP variant via custom launch confirmed working with `doctor`.

The wallfacer CI gates the Python HTTP fixture; external servers
remain a manual smoke-test (per the methodology in
[`real-world.md`](real-world.md)).

## Known limitations

- **No SSE event stream pushed by the server is currently consumed
  by the test fixture.** The Phase M fixture replies with
  `Content-Type: application/json`, which `rmcp` accepts. Servers
  that *only* speak `text/event-stream` should still work because
  `rmcp` handles both content types — but this is exercised
  end-to-end only against external servers, not in our CI.
- **No HTTP-specific torture pack yet.** `wallfacer torture --mode
  parallel` and `--mode state-leak` work over HTTP but the
  destructive guard / cancellation paths haven't been hardened
  against HTTP-specific failure modes (mid-stream disconnects,
  proxy 502s, chunked transfer hiccups). Track that as a v0.4.3+
  follow-up.
