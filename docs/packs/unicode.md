# Pack — `unicode`

> Stresses a string tool with adversarial unicode codepoints.

**Tags:** `reliability`, `unicode`
**Authors:** wallfacer-core

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `witness_field` | string | `text` | Name of the input field that carries the probe string. |
| `witness_tool` | string | `echo` | Tool that accepts a single string input and returns text content. |

## Invariants

### `unicode.rtl_override_does_not_crash_or_panic`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** matches_schema(`$.response`)
- **Test fixtures:** 3 (`pass`, `pass`, `fail`)

### `unicode.zero_width_joiner_handled`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** matches_schema(`$.response`)
- **Test fixtures:** 4 (`pass`, `pass`, `pass`, `fail`)

### `unicode.escape_sequence_for_null_byte_not_reflected_visibly`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

### `unicode.lone_surrogate_does_not_break_envelope`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** matches_schema(`$.response`)
- **Test fixtures:** 2 (`pass`, `fail`)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Unicode-handling rule pack.
#
# Probes a string-bridging tool with unicode trickery (RTL override,
# zero-width joiners, null bytes, surrogates) and asserts the server
# handles it: a crash, hang or protocol error is reported by the runner
# itself, and the invariants check the reply stays a well-formed
# envelope. Accepting or echoing the codepoints is not a failure: they
# are valid Unicode (ZWJ builds emoji sequences) and only come from the
# probe input, so flagging their presence would only detect reflection.
version: 3
metadata:
  name: unicode
  description: "Stresses a string tool with adversarial unicode codepoints."
  authors: ["wallfacer-core"]
  tags: [reliability, unicode]
  parameters:
    witness_tool:
      description: "Tool that accepts a single string input and returns text content."
      type: string
      default: "echo"
    witness_field:
      description: "Name of the input field that carries the probe string."
      type: string
      default: "text"

invariants:
  - name: "unicode.rtl_override_does_not_crash_or_panic"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "user‮evil"
    assert:
      - kind: matches_schema
        path: "$.response"
        schema:
          type: object
          required: [content]
          properties:
            content: { type: array }
            isError: { type: boolean }
    test_fixtures:
      - name: "passes when server flags the input"
        response: { isError: true, content: [{ type: "text", text: "rejected" }] }
        expect: pass
      - name: "passes when server accepts the RTL override"
        response: { isError: false, content: [{ type: "text", text: "ok" }] }
        expect: pass
      - name: "fails when the envelope loses its content"
        response: { isError: false }
        expect: fail

  - name: "unicode.zero_width_joiner_handled"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "alice‍bob"
    assert:
      - kind: matches_schema
        path: "$.response"
        schema:
          type: object
          required: [content]
          properties:
            content: { type: array }
            isError: { type: boolean }
    test_fixtures:
      - name: "passes when ZWJ rejected"
        response: { isError: true, content: [{ type: "text", text: "rejected" }] }
        expect: pass
      - name: "passes when ZWJ stripped"
        response: { isError: false, content: [{ type: "text", text: "alicebob" }] }
        expect: pass
      - name: "passes when ZWJ echoed back (search queries, echo tools)"
        response:
          isError: false
          content:
            - { type: "text", text: "No operations matched \"alice‍bob\"." }
        expect: pass
      - name: "fails when isError is not a boolean"
        response: { isError: "false", content: [{ type: "text", text: "ok" }] }
        expect: fail

  - name: "unicode.escape_sequence_for_null_byte_not_reflected_visibly"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "before-after"
    assert:
      # YAML can't carry literal NUL bytes through the source, so we
      # probe for tools that print the visible escape sequence `\x00`
      # back to the user (a sign the server is leaking its own internal
      # escaping rather than a true NUL byte).
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: '\\x[0-9A-Fa-f]{2}'
    test_fixtures:
      - name: "passes when text is clean"
        response: { content: [{ type: "text", text: "ok" }] }
        expect: pass
      - name: "fails when escape sequence echoed verbatim"
        response:
          content:
            - { type: "text", text: 'you said: before\x00after' }
        expect: fail

  - name: "unicode.lone_surrogate_does_not_break_envelope"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "valid"
    assert:
      - kind: matches_schema
        path: "$.response"
        schema:
          type: object
          required: [content]
          properties:
            content: { type: array }
    test_fixtures:
      - name: "passes when envelope shape preserved"
        response: { content: [{ type: "text", text: "ok" }] }
        expect: pass
      - name: "fails when content key absent"
        response: { isError: false }
        expect: fail
```
