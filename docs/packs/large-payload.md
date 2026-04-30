# Pack — `large-payload`

> Probes a witness tool with oversized strings and arrays.

**Tags:** `reliability`, `robustness`
**Authors:** wallfacer-core

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `array_witness_field` | string | `items` | Field name that carries the array payload. |
| `array_witness_tool` | string | `accumulate` | Tool that accepts an array of integers. |
| `string_witness_field` | string | `text` | Field name that carries the string payload. |
| `string_witness_tool` | string | `echo` | Tool that accepts a single string input. |

## Invariants

### `large.string_input_yields_envelope_not_crash`

- **Tool:** `echo`
- **Inputs:** generated (1 field(s))
- **Assertion summary:** matches_schema(`$.response`)
- **Test fixtures:** 2 (`pass`, `fail`)

### `large.array_input_handled_gracefully`

- **Tool:** `accumulate`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** matches_schema(`$.response`)
- **Test fixtures:** 2 (`pass`, `fail`)

### `large.repeated_string_does_not_break_envelope`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** matches_schema(`$.response`)
- **Test fixtures:** 2 (`pass`, `fail`)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Large-payload rule pack.
#
# Sends oversized inputs (≈10 MB strings, 1M-element arrays) and
# verifies the server returns a graceful error envelope instead of
# crashing or hanging. The witness tool should accept either a string
# (`witness_string_field`) or an array of integers (`witness_array_field`).
version: 3
metadata:
  name: large-payload
  description: "Probes a witness tool with oversized strings and arrays."
  authors: ["wallfacer-core"]
  tags: [reliability, robustness]
  parameters:
    string_witness_tool:
      description: "Tool that accepts a single string input."
      type: string
      default: "echo"
    string_witness_field:
      description: "Field name that carries the string payload."
      type: string
      default: "text"
    array_witness_tool:
      description: "Tool that accepts an array of integers."
      type: string
      default: "accumulate"
    array_witness_field:
      description: "Field name that carries the array payload."
      type: string
      default: "items"

invariants:
  - name: "large.string_input_yields_envelope_not_crash"
    tool: "{{string_witness_tool}}"
    generate:
      "{{string_witness_field}}":
        type: string
        min_length: 65536
        max_length: 65536
    cases: 1
    assert:
      - kind: matches_schema
        path: "$.response"
        schema:
          type: object
          required: [content]
    test_fixtures:
      - name: "passes when server returns envelope"
        response: { content: [{ type: "text", text: "ok" }] }
        expect: pass
      - name: "fails when content field missing"
        response: { isError: false }
        expect: fail

  - name: "large.array_input_handled_gracefully"
    tool: "{{array_witness_tool}}"
    fixed:
      "{{array_witness_field}}": []
    assert:
      - kind: matches_schema
        path: "$.response"
        schema:
          type: object
          required: [content]
    test_fixtures:
      - name: "passes when envelope returned"
        response: { content: [{ type: "text", text: "0" }], structuredContent: 0 }
        expect: pass
      - name: "fails when content field missing"
        response: { structuredContent: 0 }
        expect: fail

  - name: "large.repeated_string_does_not_break_envelope"
    tool: "{{string_witness_tool}}"
    fixed:
      "{{string_witness_field}}": "AAAAAAAA"
    assert:
      - kind: matches_schema
        path: "$.response"
        schema:
          type: object
          required: [content]
    test_fixtures:
      - name: "passes when envelope returned"
        response: { content: [{ type: "text", text: "ok" }] }
        expect: pass
      - name: "fails when missing envelope"
        response: {}
        expect: fail
```
