# Pack — `security`

> Meta-pack composing the security-oriented rule packs.

**Tags:** `security`, `meta`
**Authors:** wallfacer-core
**Extends:** [`auth`](./auth.md), [`authorization`](./authorization.md), [`path-traversal`](./path-traversal.md), [`injection-sql`](./injection-sql.md), [`injection-shell`](./injection-shell.md), [`prompt-injection`](./prompt-injection.md), [`secrets-leakage`](./secrets-leakage.md)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Security meta-pack.
#
# Purely a composition of the security-oriented packs shipped with
# wallfacer. Loading this pack pulls in every invariant from auth,
# authorization, path-traversal, injection-sql, injection-shell,
# prompt-injection, and secrets-leakage in one shot.
#
# Usage:
#   wallfacer property --pack security
#
# Override pack parameters as needed via wallfacer.toml or repeated
# `--param` flags; the overrides apply to every transitively-loaded
# pack.
version: 3
metadata:
  name: security
  description: "Meta-pack composing the security-oriented rule packs."
  authors: ["wallfacer-core"]
  tags: [security, meta]
  extends:
    - auth
    - authorization
    - path-traversal
    - injection-sql
    - injection-shell
    - prompt-injection
    - secrets-leakage

invariants: []
```
