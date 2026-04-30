# Pack — `idempotency`

> Probes idempotentHint=true tools for envelope stability.

**Tags:** `reliability`, `idempotency`, `mcp-spec`
**Authors:** wallfacer-core

## `for_each_tool` templates

### `idempotency.envelope_is_stable.{{tool_name}}`

- **Where:** annotations.idempotentHint = `true`
- **Apply assertions:** matches_schema(`$.response`) + is_type(`$.response.isError`, boolean)
- **Test fixtures:** 2 (`pass`, `fail`)

### `idempotency.structured_content_is_object.{{tool_name}}`

- **Where:** annotations.idempotentHint = `true`
- **Apply assertions:** any_of(2 child)
- **Test fixtures:** 3 (`pass`, `pass`, `fail`)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Idempotency rule pack.
#
# A tool annotated `idempotentHint: true` should produce the same
# response when called twice with the same input. This pack expands at
# run-time via `for_each_tool` and runs a single-call probe; the apply
# template asserts the envelope is well-formed and the response carries
# a structuredContent field so a downstream client can compare runs.
version: 3
metadata:
  name: idempotency
  description: "Probes idempotentHint=true tools for envelope stability."
  authors: ["wallfacer-core"]
  tags: [reliability, idempotency, mcp-spec]

invariants: []

for_each_tool:
  - name: "idempotency.envelope_is_stable.{{tool_name}}"
    where:
      annotations:
        idempotentHint: true
    apply:
      fixed: {}
      assert:
        - kind: matches_schema
          path: "$.response"
          schema:
            type: object
            required: [content]
        # The response must carry an explicit isError field — clients
        # branching on isError === true cannot tolerate "undefined".
        - kind: is_type
          path: "$.response.isError"
          type: boolean
      test_fixtures:
        - name: "passes when envelope has isError"
          response: { isError: false, content: [{ type: "text", text: "ok" }] }
          expect: pass
        - name: "fails when isError is a string"
          response: { isError: "false", content: [{ type: "text", text: "ok" }] }
          expect: fail

  - name: "idempotency.structured_content_is_object.{{tool_name}}"
    where:
      annotations:
        idempotentHint: true
    apply:
      fixed: {}
      assert:
        - kind: any_of
          assert:
            - kind: equals
              lhs: { path: "$.response.isError" }
              rhs: { value: true }
            - kind: is_type
              path: "$.response.structuredContent"
              type: object
      test_fixtures:
        - name: "passes when structuredContent is object"
          response: { isError: false, structuredContent: { ok: true } }
          expect: pass
        - name: "passes when isError true"
          response: { isError: true, content: [{ type: "text", text: "fail" }] }
          expect: pass
        - name: "fails when structuredContent is a string and not error"
          response: { isError: false, structuredContent: "scalar" }
          expect: fail
```
