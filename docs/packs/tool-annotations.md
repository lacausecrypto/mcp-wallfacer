# Pack — `tool-annotations`

> Verifies MCP tool annotations agree with observable runtime behaviour.

**Tags:** `security`, `annotations`, `mcp-spec`
**Authors:** wallfacer-core

## `for_each_tool` templates

### `tool-annotations.read_only_call_does_not_set_isError.{{tool_name}}`

- **Where:** annotations.readOnlyHint = `true`
- **Apply assertions:** matches_schema(`$.response`) + equals(path `$.response.isError` == literal `false`)
- **Test fixtures:** 2 (`pass`, `fail`)

### `tool-annotations.destructive_tool_returns_envelope_not_panic.{{tool_name}}`

- **Where:** annotations.destructiveHint = `true`
- **Apply assertions:** matches_schema(`$.response`)
- **Test fixtures:** 2 (`pass`, `fail`)

### `tool-annotations.idempotent_call_yields_structured_response.{{tool_name}}`

- **Where:** annotations.idempotentHint = `true`
- **Apply assertions:** matches_schema(`$.response`)
- **Test fixtures:** 2 (`pass`, `fail`)

### `tool-annotations.open_world_call_does_not_leak_internal_paths.{{tool_name}}`

- **Where:** annotations.openWorldHint = `true`
- **Apply assertions:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Tool-annotations rule pack.
#
# MCP 2025-06-18 introduced `tool.annotations.{readOnlyHint,
# destructiveHint, idempotentHint, openWorldHint}`. This pack iterates
# every tool the server declares and verifies the annotations are
# *truthful* — a `readOnlyHint: true` tool that mutates server state
# is a worse bug than no annotation at all because clients trust them.
#
# Phase I: uses `for_each_tool` to expand at run time against the live
# tool list. `wallfacer pack test` evaluates the apply template against
# a synthetic placeholder so the fixtures still gate CI quality.
version: 3
metadata:
  name: tool-annotations
  description: "Verifies MCP tool annotations agree with observable runtime behaviour."
  authors: ["wallfacer-core"]
  tags: [security, annotations, mcp-spec]

invariants: []

for_each_tool:
  - name: "tool-annotations.read_only_call_does_not_set_isError.{{tool_name}}"
    where:
      annotations:
        readOnlyHint: true
    apply:
      fixed: {}
      assert:
        # A read-only tool called with no arguments must produce a
        # well-formed envelope; if it crashes (isError=true) the
        # readOnlyHint claim is vacuous.
        - kind: matches_schema
          path: "$.response"
          schema:
            type: object
            required: [content]
        - kind: equals
          lhs: { path: "$.response.isError" }
          rhs: { value: false }
      test_fixtures:
        - name: "passes for healthy read-only call"
          response: { isError: false, content: [{ type: "text", text: "ok" }] }
          expect: pass
        - name: "fails when isError true on a read-only tool"
          response: { isError: true, content: [{ type: "text", text: "boom" }] }
          expect: fail

  - name: "tool-annotations.destructive_tool_returns_envelope_not_panic.{{tool_name}}"
    where:
      annotations:
        destructiveHint: true
    apply:
      fixed: {}
      assert:
        - kind: matches_schema
          path: "$.response"
          schema:
            type: object
            required: [content]
      test_fixtures:
        - name: "passes when envelope present"
          response: { content: [{ type: "text", text: "deleted 1 row" }] }
          expect: pass
        - name: "fails when content key missing"
          response: { isError: true }
          expect: fail

  - name: "tool-annotations.idempotent_call_yields_structured_response.{{tool_name}}"
    where:
      annotations:
        idempotentHint: true
    apply:
      fixed: {}
      assert:
        # Idempotent tools should expose `structuredContent` so clients
        # can compare two consecutive calls without parsing free text.
        - kind: matches_schema
          path: "$.response"
          schema:
            type: object
            required: [structuredContent]
      test_fixtures:
        - name: "passes when structured content returned"
          response: { structuredContent: { id: 1 }, content: [] }
          expect: pass
        - name: "fails when no structuredContent"
          response: { content: [{ type: "text", text: "ok" }] }
          expect: fail

  - name: "tool-annotations.open_world_call_does_not_leak_internal_paths.{{tool_name}}"
    where:
      annotations:
        openWorldHint: true
    apply:
      fixed: {}
      assert:
        # Open-world tools talk to remote services; the remote may emit
        # paths or stack traces. Reject those to keep the envelope
        # client-friendly.
        - kind: not
          assertion:
            kind: matches_regex
            path: "$.response.content[0].text"
            pattern: "(?:/Users/|/home/|C:\\\\\\\\Users)[^\\s]+"
      test_fixtures:
        - name: "passes when text is sanitised"
          response: { content: [{ type: "text", text: "service unavailable" }] }
          expect: pass
        - name: "fails when local path leaks"
          response:
            content:
              - { type: "text", text: "error at /home/server/app/main.py" }
          expect: fail
```
