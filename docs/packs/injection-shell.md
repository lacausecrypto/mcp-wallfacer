# Pack — `injection-shell`

> Probes a process-bridging tool with shell-injection payloads.

**Tags:** `security`, `command-injection`
**Authors:** wallfacer-core

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `canary_pattern` | string | `(?i)(?:uid=\d+\(\|root:.*:/bin/(?:ba)?sh\|gid=\d+)` | Regex matching the side-effect of a successful injection (whoami output, /etc/passwd content, ...). |
| `shell_field` | string | `command` | Field name carrying the command string. |
| `shell_tool` | string | `run_shell` | Tool that runs / shells out to a process. |

## Invariants

### `shell.semicolon_chain_does_not_execute_second_command`

- **Tool:** `run_shell`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

### `shell.ampersand_chain_does_not_execute_second_command`

- **Tool:** `run_shell`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

### `shell.backticks_are_quoted_or_rejected`

- **Tool:** `run_shell`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

### `shell.dollar_paren_does_not_expand`

- **Tool:** `run_shell`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** not(matches_regex(`$.response.content[0].text`))
- **Test fixtures:** 2 (`pass`, `fail`)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Shell-injection rule pack.
#
# Probes a process-bridging tool (any tool that ultimately spawns a
# subprocess) with classic shell-injection payloads. The tool should
# either reject the input or quote/escape it; the assertion checks the
# response cannot show output of an injected secondary command.
version: 3
metadata:
  name: injection-shell
  description: "Probes a process-bridging tool with shell-injection payloads."
  authors: ["wallfacer-core"]
  tags: [security, command-injection]
  parameters:
    shell_tool:
      description: "Tool that runs / shells out to a process."
      type: string
      default: "run_shell"
    shell_field:
      description: "Field name carrying the command string."
      type: string
      default: "command"
    canary_pattern:
      description: "Regex matching the side-effect of a successful injection (whoami output, /etc/passwd content, ...)."
      type: string
      default: "(?i)(?:uid=\\d+\\(|root:.*:/bin/(?:ba)?sh|gid=\\d+)"

invariants:
  - name: "shell.semicolon_chain_does_not_execute_second_command"
    tool: "{{shell_tool}}"
    fixed:
      "{{shell_field}}": "echo hello; whoami"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: '{{canary_pattern}}'
    test_fixtures:
      - name: "passes when only literal echo output returned"
        response: { content: [{ type: "text", text: "hello" }] }
        expect: pass
      - name: "fails when whoami output leaks"
        response:
          content:
            - { type: "text", text: "hello\nuid=0(root) gid=0(root)" }
        expect: fail

  - name: "shell.ampersand_chain_does_not_execute_second_command"
    tool: "{{shell_tool}}"
    fixed:
      "{{shell_field}}": "echo first && cat /etc/passwd"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: '{{canary_pattern}}'
    test_fixtures:
      - name: "passes when /etc/passwd not leaked"
        response: { content: [{ type: "text", text: "first" }] }
        expect: pass
      - name: "fails when /etc/passwd content leaks"
        response:
          content:
            - { type: "text", text: "first\nroot:x:0:0:root:/root:/bin/bash" }
        expect: fail

  - name: "shell.backticks_are_quoted_or_rejected"
    tool: "{{shell_tool}}"
    fixed:
      "{{shell_field}}": "echo `whoami`"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: '{{canary_pattern}}'
    test_fixtures:
      - name: "passes when backticks treated literally"
        response: { content: [{ type: "text", text: "`whoami`" }] }
        expect: pass
      - name: "fails when backticks expand to command output"
        response: { content: [{ type: "text", text: "uid=0(root)" }] }
        expect: fail

  - name: "shell.dollar_paren_does_not_expand"
    tool: "{{shell_tool}}"
    fixed:
      "{{shell_field}}": "echo $(id)"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: '{{canary_pattern}}'
    test_fixtures:
      - name: "passes when $(...) is treated literally"
        response: { content: [{ type: "text", text: "$(id)" }] }
        expect: pass
      - name: "fails when $(...) expands"
        response: { content: [{ type: "text", text: "uid=1000(alice) gid=1000(alice)" }] }
        expect: fail
```
