# Sequence DSL — multi-step invariants

Phase L (v0.4) added a `sequences:` block to the property DSL. A
sequence is a chain of tool calls executed against a single MCP
client; later steps can reference earlier ones via
`{{steps.<bind>.<jsonpath>}}` placeholders. The runner does **not**
reconnect between steps, so per-connection state — auth tokens,
in-memory bookkeeping, server-side session ids — survives the chain.

This is the only way wallfacer can express invariants that depend on
multi-tool interactions, which is where most real-world MCP bugs
hide:

- `create_X` → `delete_X` → `read_X` should produce a not-found.
  Servers that swallow the `delete_X` and still return the record
  on the post-delete `read_X` ship a state leak.
- `auth_login` → `protected_call` → `auth_logout` →
  `protected_call` should reject the second call. Servers that keep
  honoring the revoked token have a session-fixation bug.
- `paginate(cursor=null)` → `paginate(cursor=<from-page-1>)` →
  ... → `paginate(cursor=<exhausted>)` should converge. Servers that
  loop forever or return overlapping pages have a cursor bug.

## YAML shape

```yaml
version: 3
metadata:
  name: my-pack
  parameters:
    create_tool: { type: string, default: "create_record" }

invariants: []   # required, even when empty

sequences:
  - name: "stateful.create_then_delete_purges"
    description: |
      Optional human-readable description; surfaced by `pack show`
      and the human reporter.
    steps:
      - call: "{{create_tool}}"           # tool to invoke
        with: { name: "wf-probe" }         # input arguments
        bind: created                      # name this step's output
                                           # for later reference
      - call: delete_record
        with:
          id: "{{steps.created.response.structuredContent.id}}"
                                           # late-bound substitution
                                           # against a prior step
      - call: read_record
        with:
          id: "{{steps.created.response.structuredContent.id}}"
        expect: error                      # this read MUST fail
                                           # (record was just deleted)
        assert:                            # optional per-step
          - kind: equals                   # assertions, evaluated
            lhs: { path: "$.response.isError" }
            rhs: { value: true }
    test_fixtures:                         # offline fixtures for
      - name: "passes when delete really purges"
        responses:                         # one per step, in order
          - { isError: false, structuredContent: { id: 42 }, content: [] }
          - { isError: false, content: [] }
          - { isError: true, content: [{ type: "text", text: "not found" }] }
        expect: pass
      - name: "fails when delete is a no-op"
        responses:
          - { isError: false, structuredContent: { id: 42 }, content: [] }
          - { isError: false, content: [] }
          - { isError: false, structuredContent: { id: 42 }, content: [] }
        expect: fail
```

## Step contract

| Field | Required | Notes |
|---|---|---|
| `call` | yes | Tool name. Skipped if the server doesn't advertise it. |
| `with` | no | Input arguments. Defaults to `{}`. May contain step references. |
| `bind` | no | Names the step's `{input, response}` envelope for later reference. |
| `expect` | no | `ok` or `error`: a checked outcome; a mismatch fails the sequence. A JSON-RPC error reply counts as `error`; a crash, hang or protocol error never does. |
| `require` | no | Precondition assertions (same vocabulary as `assert`). When one fails, the sequence is reported *inconclusive* (skipped, no finding): what the rest of the sequence relies on does not hold. A precondition may itself be a rejection, e.g. "the server refuses an absolute path outside its root" before testing whether `../` escapes it. A `require` step always runs as written, never mutated from the corpus. |
| `assert` | no | Per-step assertions; same vocabulary as single-tool invariants. When the step has no `expect`, its assertions alone decide, so a check like "refused, or leaks nothing" passes on an `isError` reply. |

A step with none of `expect`, `require` or `assert` is a **setup**
step: it only has to succeed. If it returns `isError`, the sequence is
reported *inconclusive*, because the setup never happened. The same
applies when a later step references a value an earlier step didn't
return. Sequence fixtures assert this with `expect: inconclusive`.

### Precondition example

```yaml
steps:
  # Is there a root to escape at all? A server that serves an absolute
  # path outside it has full filesystem access by design.
  - call: read_file
    with: { path: "/etc/passwd" }
    require:
      - kind: any_of
        assert:
          - { kind: equals, lhs: { path: "$.response.isError" }, rhs: { value: true } }
          - kind: not
            assertion: { kind: matches_regex, path: "$.response.content[0].text", pattern: '(?m)^root:[^:\n]*:0:0:' }
  # Only then is a `../` leak a traversal.
  - call: read_file
    with: { path: "../../../../etc/passwd" }
    assert:
      - kind: any_of
        assert:
          - { kind: equals, lhs: { path: "$.response.isError" }, rhs: { value: true } }
          - kind: not
            assertion: { kind: matches_regex, path: "$.response.content[0].text", pattern: '(?m)^root:[^:\n]*:0:0:' }
```

## Destructive-tool guard

Sequences go through the same `[destructive]` / `[allow_destructive]`
guard as single-tool invariants. A sequence with a step calling a
blocked tool is skipped whole (reported under `skipped`), never
half-run.

## Substitution syntax

Inside `with:` (and only there), strings can reference earlier steps:

- `{{steps.<bind>.input.<path>}}` resolves to a value from the bound
  step's input object.
- `{{steps.<bind>.response.<path>}}` resolves to a value from the
  bound step's response envelope.
- `{{steps.<bind>}}` (no path) resolves to the entire `{input,
  response}` envelope.

Two substitution modes:

- **Single-placeholder strings** (`"{{steps.x.response.id}}"`)
  preserve the resolved value's JSON type. A numeric id stays a
  number; a nested object stays an object.
- **Mixed text** (`"Bearer {{steps.login.response.token}}"`)
  stringifies the resolved value into the surrounding text and
  returns a string. Use this for HTTP-header-style composition.

References to steps that haven't run yet, or paths that don't
resolve, make the sequence *inconclusive* at that step (in `pack test`
fixtures they are a structural error: the fixture itself is wrong).

## Reconnect policy

The runner holds a single `Client` for the duration of a sequence and
does not reconnect between steps, so authentication tokens, session ids
and any other per-connection state survive across the chain.

- A JSON-RPC error reply (`-32601 method not found`, `-32602`, …) is a
  rejection: the step sees it as an `isError: true` result.
- A hang, crash or protocol error fails the sequence at that step (a
  crash is never mistaken for the rejection an `expect: error` step
  wants).
- Any response containing wallfacer's canary secret (see
  [architecture](./architecture.md#canary-secret)) fails the sequence.

The single-tool property runner reconnects after each transport
failure. Sequences trade aggressive recovery for state continuity.

## Pack examples

The embedded `stateful` pack ships a generic create/read/delete
state-leak sequence; the `auth-flow` pack ships a login/logout
token-revocation sequence. Both expect the operator to override the
default tool names in `wallfacer.toml`:

```toml
[packs.stateful]
create_tool = "record_create"
delete_tool = "record_delete"
read_tool = "record_read"

[packs.auth-flow]
login_tool = "auth_login"
logout_tool = "auth_logout"
protected_tool = "protected_resource"
user = "wf-probe"
password = "${WALLFACER_AUTH_PASSWORD}"
```

Run them like any other pack:

```bash
wallfacer property --pack stateful
wallfacer property --pack auth-flow
```

## Findings

A failing sequence emits a single
`FindingKind::SequenceFailure { sequence, step_index, step_call }`
finding, with severity `High` by default. The corpus folder uses
the sequence name (sanitized) as the per-finding tool slot so a
sequence's findings cluster together under
`.wallfacer/corpus/<sequence_name>/`.
