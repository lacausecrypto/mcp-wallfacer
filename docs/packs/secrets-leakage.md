# Pack — `secrets-leakage`

> Probes a witness tool to confirm secrets are not echoed in responses.

**Tags:** `security`, `secrets`
**Authors:** wallfacer-core

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `witness_field` | string | `text` | Name of the input field that carries the probe string. |
| `witness_tool` | string | `echo` | Tool that accepts a single string field (`text`/`message`) and returns text content. |

## Invariants

### `secrets.bearer_tokens_not_echoed`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

### `secrets.api_keys_not_echoed`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

### `secrets.private_paths_not_echoed`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

### `secrets.env_var_values_not_echoed`

- **Tool:** `echo`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Secrets-leakage rule pack.
#
# Probes a tool with payloads that look like secrets and asserts the
# response never echoes them back in plain text. Use a *witness* tool
# that takes a single string-like input — typically a generic
# string-processing endpoint your server exposes (echo, log_message,
# translate, ...).
version: 3
metadata:
  name: secrets-leakage
  description: "Probes a witness tool to confirm secrets are not echoed in responses."
  authors: ["wallfacer-core"]
  tags: [security, secrets]
  parameters:
    witness_tool:
      description: "Tool that accepts a single string field (`text`/`message`) and returns text content."
      type: string
      default: "echo"
    witness_field:
      description: "Name of the input field that carries the probe string."
      type: string
      default: "text"

invariants:
  - name: "secrets.bearer_tokens_not_echoed"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "Authorization: Bearer abcDEF123456_secret-token-xyz"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "Bearer\\s+[A-Za-z0-9._\\-]{16,}"
    test_fixtures:
      - name: "passes when token redacted/dropped"
        response: { content: [{ type: "text", text: "ok" }] }
        expect: pass
      - name: "fails when bearer is echoed verbatim"
        response: { content: [{ type: "text", text: "Bearer abcDEF123456_secret-token-xyz" }] }
        expect: fail

  - name: "secrets.api_keys_not_echoed"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "X-API-Key: wlf_demo_AAAA1111BBBB2222CCCC"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "(?i)wlf_demo_[A-Za-z0-9]{16,}"
    test_fixtures:
      - name: "passes when api key dropped"
        response: { content: [{ type: "text", text: "received" }] }
        expect: pass
      - name: "fails when api key reflected"
        response:
          content:
            - { type: "text", text: "you said: wlf_demo_AAAA1111BBBB2222CCCC" }
        expect: fail

  - name: "secrets.private_paths_not_echoed"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "/home/alice/.ssh/id_rsa"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "(?i)(?:/home/|/Users/|C:\\\\\\\\Users)[^\\s]+\\.(?:ssh|aws|env)"
    test_fixtures:
      - name: "passes when path scrubbed"
        response: { content: [{ type: "text", text: "received" }] }
        expect: pass
      - name: "fails when ssh key path leaks back"
        response:
          content:
            - { type: "text", text: "found at /home/alice/.ssh/id_rsa" }
        expect: fail

  - name: "secrets.env_var_values_not_echoed"
    tool: "{{witness_tool}}"
    fixed:
      "{{witness_field}}": "WALLFACER_REPLAY_PASSWORD=hunter2-supersecret"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "(?i)(?:password|secret|token)\\s*[=:]\\s*[A-Za-z0-9._\\-]{6,}"
    test_fixtures:
      - name: "passes when env value dropped"
        response: { content: [{ type: "text", text: "ok" }] }
        expect: pass
      - name: "fails when env reflected"
        response:
          content:
            - { type: "text", text: "WALLFACER_REPLAY_PASSWORD=hunter2-supersecret" }
        expect: fail
```
