# Pack — `mcp-spec-conformance`

> Validates the MCP protocol wire-format envelope on every tool response.

**Tags:** `security`, `mcp-spec`, `protocol`
**Authors:** wallfacer-core
**Extends:** [`idempotency`](./idempotency.md)

## `for_each_tool` templates

### `mcp-spec.envelope_has_content_array.{{tool_name}}`

- **Where:** every tool
- **Apply assertions:** matches_schema(`$.response`)
- **Test fixtures:** 3 (`pass`, `pass`, `fail`)

### `mcp-spec.is_error_is_boolean.{{tool_name}}`

- **Where:** every tool
- **Apply assertions:** any_of(2 child)
- **Test fixtures:** 4 (`pass`, `pass`, `pass`, `fail`)

### `mcp-spec.content_items_have_type.{{tool_name}}`

- **Where:** every tool
- **Apply assertions:** for_each(`$.response.content[*]`, 1 child)
- **Test fixtures:** 2 (`pass`, `fail`)

### `mcp-spec.structured_content_is_object_when_present.{{tool_name}}`

- **Where:** every tool
- **Apply assertions:** any_of(2 child)
- **Test fixtures:** 2 (`pass`, `pass`)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# MCP spec conformance rule pack — Phase S (v0.6).
#
# Validates the MCP wire-format itself, not the business logic of
# any specific tool. First public pack of its kind in the MCP
# ecosystem — distinct from "are this server's tools correct?"
# (which the rest of wallfacer's packs handle), this pack asks:
# "does this server speak MCP correctly?"
#
# Reference: MCP spec 2025-06-18, sections "Tools", "Error
# handling", "Capabilities".
#
# Scope of this pack (envelope-shape level):
#   - every tools/call response must include a `content` array
#     (spec: a tool result is `{content, isError?, structuredContent?}`)
#   - `isError` when present must be a boolean
#   - `structuredContent` when present must be an object
#   - `content` array entries must each be a typed block with at
#     least a `type` field
#   - tools annotated `idempotentHint: true` MUST keep their
#     envelope shape stable across two identical calls
#     (handled by the `idempotency` pack — referenced via extends).
#
# Out of scope (would need a dedicated runner): notification
# semantics, JSON-RPC 2.0 envelope (handled by rmcp before we see
# anything), capability negotiation outside listing.
version: 3
metadata:
  name: mcp-spec-conformance
  description: "Validates the MCP protocol wire-format envelope on every tool response."
  authors: ["wallfacer-core"]
  tags: [security, mcp-spec, protocol]
  extends: [idempotency]

invariants: []

for_each_tool:
  - name: "mcp-spec.envelope_has_content_array.{{tool_name}}"
    apply:
      input: schema_valid
      assert:
        # MCP 2025-06-18 §Tools: every tool result MUST include a
        # `content` array. This is true even when `isError: true`.
        - kind: matches_schema
          path: "$.response"
          schema:
            type: object
            required: [content]
            properties:
              content: { type: array }
      test_fixtures:
        - name: "passes when content array present"
          response: { content: [{ type: "text", text: "ok" }] }
          expect: pass
        - name: "passes for isError envelope with content"
          response: { content: [{ type: "text", text: "boom" }], isError: true }
          expect: pass
        - name: "fails when content key missing"
          response: { isError: true }
          expect: fail

  - name: "mcp-spec.is_error_is_boolean.{{tool_name}}"
    apply:
      input: schema_valid
      assert:
        # When present, `isError` must be a boolean. Servers that
        # send `"true"` (string) or `1` (integer) break clients.
        - kind: any_of
          assert:
            - kind: not
              assertion:
                kind: matches_regex
                path: "$.response.isError"
                pattern: ".*"
            - kind: is_type
              path: "$.response.isError"
              type: boolean
      test_fixtures:
        - name: "passes when isError absent"
          response: { content: [{ type: "text", text: "ok" }] }
          expect: pass
        - name: "passes when isError is true"
          response: { content: [], isError: true }
          expect: pass
        - name: "passes when isError is false"
          response: { content: [], isError: false }
          expect: pass
        - name: "fails when isError is a string"
          response: { content: [], isError: "true" }
          expect: fail

  - name: "mcp-spec.content_items_have_type.{{tool_name}}"
    apply:
      input: schema_valid
      assert:
        # Each entry in `content` MUST carry a `type` field. The
        # spec lists `text`, `image`, `audio`, `resource`,
        # `resource_link`. We only enforce presence — the union
        # itself is validated downstream.
        - kind: for_each
          path: "$.response.content[*]"
          assert:
            - kind: matches_schema
              path: "$.item"
              schema:
                type: object
                required: [type]
                properties:
                  type: { type: string }
      test_fixtures:
        - name: "passes when every item has type"
          response: { content: [{ type: "text", text: "ok" }, { type: "image", data: "..." }] }
          expect: pass
        - name: "fails when an item omits type"
          response: { content: [{ text: "missing type" }] }
          expect: fail

  - name: "mcp-spec.structured_content_is_object_when_present.{{tool_name}}"
    apply:
      input: schema_valid
      assert:
        # When present, `structuredContent` must be a JSON object
        # (the spec requires a JSON-Schema-compatible shape).
        - kind: any_of
          assert:
            - kind: not
              assertion:
                kind: matches_regex
                path: "$.response.structuredContent"
                pattern: ".*"
            - kind: is_type
              path: "$.response.structuredContent"
              type: object
      test_fixtures:
        - name: "passes when structuredContent absent"
          response: { content: [{ type: "text", text: "ok" }] }
          expect: pass
        - name: "passes when structuredContent is an object"
          response: { content: [], structuredContent: { id: 1 } }
          expect: pass
```
