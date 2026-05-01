# Pack — `stateful`

> Multi-step sequences that probe create / read / delete state continuity.

**Tags:** `reliability`, `state`, `mcp-spec`
**Authors:** wallfacer-core

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `create_payload` | string | `{"event": "wf-stateful-probe"}` | JSON payload merged into the create_tool input. |
| `create_tool` | string | `bug_log` | Tool that creates a new resource and returns its identifier. |
| `delete_tool` | string | `delete_record` | Tool that deletes a resource by id. |
| `read_tool` | string | `list_active_users` | Tool that reads a resource by id (or returns isError for missing). |

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Stateful rule pack — create / read / delete cycles.
#
# Phase L: tests that mutating tools actually mutate, and that
# delete-class tools leave the server in a state where the matching
# read-class tool cannot resurrect the data.
#
# Single-tool packs can't catch state leaks. A `delete_user` tool that
# returns ok but leaves the row in the DB is a real-world bug only a
# multi-step harness can find.
#
# All sequence steps share one client connection, so the runner does
# not reconnect between steps. A `create` step's session id, in-memory
# bookkeeping, and any other per-connection state survives into later
# steps.
version: 3
metadata:
  name: stateful
  description: "Multi-step sequences that probe create / read / delete state continuity."
  authors: ["wallfacer-core"]
  tags: [reliability, state, mcp-spec]
  parameters:
    create_tool:
      description: "Tool that creates a new resource and returns its identifier."
      type: string
      default: "bug_log"
    read_tool:
      description: "Tool that reads a resource by id (or returns isError for missing)."
      type: string
      default: "list_active_users"
    delete_tool:
      description: "Tool that deletes a resource by id."
      type: string
      default: "delete_record"
    create_payload:
      description: "JSON payload merged into the create_tool input."
      type: string
      default: '{"event": "wf-stateful-probe"}'

invariants: []

sequences:
  - name: "stateful.delete_purges_subsequent_read"
    description: |
      Calls `create_tool`, captures its returned id, calls `delete_tool`
      with that id, then calls `read_tool` with the same id. The read
      MUST fail (isError=true) because the record was just deleted. A
      server that returns the deleted record on read has a state-leak
      bug.
    steps:
      - call: "{{create_tool}}"
        with: { event: "wf-stateful-probe" }
        bind: created
      - call: "{{delete_tool}}"
        with:
          id: "{{steps.created.response.structuredContent.id}}"
      - call: "{{read_tool}}"
        with:
          id: "{{steps.created.response.structuredContent.id}}"
        expect: error
    test_fixtures:
      - name: "passes when the read after delete returns isError"
        responses:
          - { isError: false, structuredContent: { id: 42 }, content: [] }
          - { isError: false, content: [] }
          - { isError: true, content: [{ type: "text", text: "not found" }] }
        expect: pass
      - name: "fails when the read after delete returns the resurrected record"
        responses:
          - { isError: false, structuredContent: { id: 42 }, content: [] }
          - { isError: false, content: [] }
          - { isError: false, structuredContent: { id: 42 }, content: [] }
        expect: fail
```
