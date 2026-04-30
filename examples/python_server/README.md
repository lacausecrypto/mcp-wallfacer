# Example: six-bug Python MCP server

This directory hosts a deliberately-broken MCP server that emits one
distinct bug per `wallfacer` finding kind. It is the canonical demo:
running the four wallfacer modes against this directory produces every
finding kind the harness can report.

## Layout

| File | Purpose |
|---|---|
| `server.py` | The buggy server. Speaks JSON-RPC over stdio, no Python SDK needed. |
| `wallfacer.toml` | Points wallfacer at `python3 server.py`. |
| `invariants.yaml` | Property invariants for the `paginate` tool. |

## How each finding kind is triggered

| Tool | wallfacer command | `FindingKind` |
|---|---|---|
| `crashes_now` | `wallfacer fuzz` | `Crash` |
| `hangs_forever` | `wallfacer fuzz` | `Hang` |
| `wrong_id_type` | `wallfacer differential --learn` then `wallfacer differential` | `SchemaViolation` |
| `paginate` | `wallfacer property invariants.yaml` | `PropertyFailure` |
| `bad_protocol` | `wallfacer fuzz` | `ProtocolError` |
| `session_set` + `session_get` | `wallfacer torture --mode state-leak` | `StateLeak` |

## Running it

```bash
cd examples/python_server
wallfacer doctor
wallfacer fuzz --seed 0 --iterations 10 --include "crashes_now"
wallfacer fuzz --seed 0 --iterations 10 --include "hangs_forever"
wallfacer fuzz --seed 0 --iterations 10 --include "bad_protocol"
wallfacer differential --learn
wallfacer differential
wallfacer property invariants.yaml
wallfacer torture --mode state-leak
wallfacer corpus list
```

Each finding lands as a JSON file under `.wallfacer/corpus/`. To replay
one with the original payload:

```bash
wallfacer replay <finding-id>
```

## Why this is also a test fixture

`examples/python_server/server.py` doubles as the Phase F acceptance
fixture: the test
[`crates/mcp-wallfacer-cli/tests/e2e/example_six_kinds.rs`](../../crates/mcp-wallfacer-cli/tests/e2e/example_six_kinds.rs)
walks each command and asserts the corresponding finding kind appears.
