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
| `expect` | no | `ok` (default) or `error`. Coarse outcome check. |
| `assert` | no | Per-step assertions; same vocabulary as single-tool invariants. |

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
resolve, surface as a structural error tagged on the step that
attempted the substitution.

## Reconnect policy

The runner holds a single `Client` for the duration of a sequence
and *does not* reconnect on:

- transport hangs (the step is marked `Hang`-class outcome and the
  sequence fails, but the connection stays alive in case the next
  sequence wants to observe whatever state was left behind),
- protocol-level errors (`-32601 method not found` on a step's
  call: same — sequence fails, connection survives),
- assertion failures.

The single-tool property runner reconnects aggressively after each
of these. Sequences trade aggressive recovery for state continuity.

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
