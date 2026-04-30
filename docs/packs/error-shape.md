# Pack — `error-shape`

> Verifies the shape of error envelopes returned by tool calls.

**Tags:** `reliability`, `errors`
**Authors:** wallfacer-core

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `error_witness_tool` | string | `divide` | A tool that the witness payload reliably forces into the error path. |
| `unknown_tool_name` | string | `this_tool_does_not_exist` | A tool name that does NOT exist on the server. |

## Invariants

### `error.witness_returns_well_formed_envelope`

- **Tool:** `divide`
- **Inputs:** fixed (2 field(s))
- **Assertion summary:** matches_schema(`$.response`)
- **Test fixtures:** 2 (`pass`, `fail`)

### `error.unknown_tool_returns_envelope_not_panic`

- **Tool:** `this_tool_does_not_exist`
- **Inputs:** fixed (0 field(s))
- **Assertion summary:** equals(path `$.response.isError` == literal `true`)
- **Test fixtures:** 2 (`pass`, `fail`)

### `error.text_messages_never_carry_internal_paths`

- **Tool:** `divide`
- **Inputs:** fixed (2 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

### `error.text_messages_never_carry_stack_traces`

- **Tool:** `divide`
- **Inputs:** fixed (2 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Error-envelope rule pack.
#
# Validates that a server's error responses follow a predictable shape:
# `isError: true` with at least one human-readable text content. This
# matters for clients that branch on `isError` rather than attempting to
# parse free-form prose.
# Loadable via: `wallfacer property --pack error-shape`.
#
# Phase G — v3 with parameters: pick the witness tool that should
# fail (e.g. divide by zero) and the tool name that doesn't exist on
# your server.
#
#   [packs.error-shape]
#   error_witness_tool = "divide"
#   error_witness_input = { a = 1, b = 0 }
version: 3
metadata:
  name: error-shape
  description: "Verifies the shape of error envelopes returned by tool calls."
  authors: ["wallfacer-core"]
  tags: [reliability, errors]
  parameters:
    error_witness_tool:
      description: "A tool that the witness payload reliably forces into the error path."
      type: string
      default: "divide"
    unknown_tool_name:
      description: "A tool name that does NOT exist on the server."
      type: string
      default: "this_tool_does_not_exist"

invariants:
  - name: "error.witness_returns_well_formed_envelope"
    tool: "{{error_witness_tool}}"
    fixed:
      a: 1
      b: 0
    assert:
      - kind: matches_schema
        path: "$.response"
        schema:
          type: object
          required: [isError, content]
          properties:
            isError: { type: boolean, enum: [true] }
            content:
              type: array
              minItems: 1
              items:
                type: object
                required: [type, text]
                properties:
                  type: { type: string, enum: [text] }
                  text: { type: string, minLength: 1 }
    test_fixtures:
      - name: "passes with well-formed envelope"
        response:
          isError: true
          content:
            - { type: "text", text: "division by zero" }
        expect: pass
      - name: "fails when isError is false"
        response:
          isError: false
          content:
            - { type: "text", text: "ok" }
        expect: fail

  - name: "error.unknown_tool_returns_envelope_not_panic"
    tool: "{{unknown_tool_name}}"
    fixed: {}
    assert:
      - kind: equals
        lhs: { path: "$.response.isError" }
        rhs: { value: true }
    test_fixtures:
      - name: "passes when isError set"
        response: { isError: true }
        expect: pass
      - name: "fails when isError absent / false"
        response: { isError: false, content: [{ type: "text", text: "ok" }] }
        expect: fail

  - name: "error.text_messages_never_carry_internal_paths"
    tool: "{{error_witness_tool}}"
    fixed:
      a: 1
      b: 0
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "(?:/Users/|/home/|C:\\\\\\\\)"
    test_fixtures:
      - name: "passes with sanitized message"
        response: { content: [{ type: "text", text: "division by zero" }] }
        expect: pass
      - name: "fails when /Users/... leaks"
        response:
          content:
            - { type: "text", text: "panic at /Users/alice/server.py:42" }
        expect: fail

  - name: "error.text_messages_never_carry_stack_traces"
    tool: "{{error_witness_tool}}"
    fixed:
      a: 1
      b: 0
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "Traceback \\(most recent call last\\)|^\\s*at\\s+[A-Za-z0-9_<>$.]+\\("
    test_fixtures:
      - name: "passes with short message"
        response: { content: [{ type: "text", text: "division by zero" }] }
        expect: pass
      - name: "fails when Python traceback leaks"
        response:
          content:
            - { type: "text", text: "Traceback (most recent call last):\n  File \"server.py\", line 1" }
        expect: fail
```
