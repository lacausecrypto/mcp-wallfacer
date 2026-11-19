# Pack — `secrets-leakage`

> Checks the server never discloses its environment, including by expanding env references in input.

**Tags:** `security`, `secrets`
**Authors:** wallfacer-core

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `canary_pattern` | string | `wfcanary_[0-9a-f]{32}` | Regex matching any wallfacer canary value. |
| `witness_field` | string | `text` | Name of the input field that carries the probe string. |
| `witness_tool` | string | `echo` | Tool that accepts a string field and returns text content. |

## Invariants

### `secrets.shell_env_reference_not_expanded`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 4 (`pass`, `pass`, `fail`, `fail`)

### `secrets.braced_env_reference_not_expanded`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

### `secrets.windows_env_reference_not_expanded`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

### `secrets.js_template_reference_not_evaluated`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Secrets-leakage rule pack.
#
# Wallfacer spawns stdio servers with a canary secret in their
# environment (`WALLFACER_CANARY_SECRET=wfcanary_<32 hex>`, random per
# run, never sent in any request). Every runner — fuzz, property,
# sequences — reports any response containing it as a `secret_leak`
# finding, whatever tool or input produced it.
#
# This pack adds targeted probes: inputs that *reference* the canary by
# name, so a server that expands environment references in user input
# (shell `$VAR`, `${VAR}`, Windows `%VAR%`, JavaScript template
# evaluation) discloses it. Echoing the reference back verbatim is not a
# leak: the name is not the secret. An error message that quotes the
# expanded value is a leak, so `isError` replies are checked too.
#
# HTTP targets are not spawned by wallfacer: no canary is planted and the
# probes cannot fire.
version: 3
metadata:
  name: secrets-leakage
  description: "Checks the server never discloses its environment, including by expanding env references in input."
  authors: ["wallfacer-core"]
  tags: [security, secrets]
  parameters:
    witness_tool:
      description: "Tool that accepts a string field and returns text content."
      type: string
      default: "echo"
    witness_field:
      description: "Name of the input field that carries the probe string."
      type: string
      default: "text"
    canary_pattern:
      description: "Regex matching any wallfacer canary value."
      type: string
      default: "wfcanary_[0-9a-f]{32}"

invariants:
  - name: "secrets.shell_env_reference_not_expanded"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "$WALLFACER_CANARY_SECRET"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "{{canary_pattern}}"
    test_fixtures:
      - name: "passes when the reference is echoed verbatim"
        response: { content: [{ type: "text", text: "you said: $WALLFACER_CANARY_SECRET" }] }
        expect: pass
      - name: "passes when the input is rejected"
        response: { isError: true, content: [{ type: "text", text: "invalid characters in input" }] }
        expect: pass
      - name: "fails when the reference is expanded"
        response: { content: [{ type: "text", text: "you said: wfcanary_0123456789abcdef0123456789abcdef" }] }
        expect: fail
      - name: "fails when an error quotes the expanded value"
        response: { isError: true, content: [{ type: "text", text: "no such file: wfcanary_0123456789abcdef0123456789abcdef" }] }
        expect: fail

  - name: "secrets.braced_env_reference_not_expanded"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "${WALLFACER_CANARY_SECRET}"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "{{canary_pattern}}"
    test_fixtures:
      - name: "passes when the reference is echoed verbatim"
        response: { content: [{ type: "text", text: "${WALLFACER_CANARY_SECRET}" }] }
        expect: pass
      - name: "fails when the reference is expanded"
        response: { content: [{ type: "text", text: "wfcanary_0123456789abcdef0123456789abcdef" }] }
        expect: fail

  - name: "secrets.windows_env_reference_not_expanded"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "%WALLFACER_CANARY_SECRET%"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "{{canary_pattern}}"
    test_fixtures:
      - name: "passes when the reference is echoed verbatim"
        response: { content: [{ type: "text", text: "%WALLFACER_CANARY_SECRET%" }] }
        expect: pass
      - name: "fails when the reference is expanded"
        response: { content: [{ type: "text", text: "wfcanary_0123456789abcdef0123456789abcdef" }] }
        expect: fail

  - name: "secrets.js_template_reference_not_evaluated"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "${process.env.WALLFACER_CANARY_SECRET}"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "{{canary_pattern}}"
    test_fixtures:
      - name: "passes when the template is echoed verbatim"
        response: { content: [{ type: "text", text: "${process.env.WALLFACER_CANARY_SECRET}" }] }
        expect: pass
      - name: "fails when the template is evaluated"
        response: { content: [{ type: "text", text: "wfcanary_0123456789abcdef0123456789abcdef" }] }
        expect: fail
```
