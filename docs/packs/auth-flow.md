# Pack — `auth-flow`

> Multi-step sequences that probe login / logout token invalidation.

**Tags:** `security`, `auth`, `mcp-spec`
**Authors:** wallfacer-core

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `login_tool` | string | `auth_login` | Tool that performs login and returns a session token. |
| `logout_tool` | string | `auth_logout` | Tool that revokes a previously-issued session token. |
| `password` | string | `wallfacer-probe-password` | Password supplied to login_tool. Override locally; never commit secrets. |
| `protected_tool` | string | `protected_resource` | Tool that requires an authenticated session token. |
| `user` | string | `wallfacer-probe` | Username supplied to login_tool. |

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Auth-flow rule pack — login / logout token invalidation.
#
# Phase L: probes the standard OAuth-style flow that most authenticated
# MCP servers implement. After a logout the issued token MUST stop
# authenticating subsequent calls; a server that keeps honoring it is
# a real session-fixation / privilege-revocation bug.
#
# Override the four tool parameters in your `wallfacer.toml` to point
# at your server's actual auth tools, then run
# `wallfacer property --pack auth-flow` against it.
version: 3
metadata:
  name: auth-flow
  description: "Multi-step sequences that probe login / logout token invalidation."
  authors: ["wallfacer-core"]
  tags: [security, auth, mcp-spec]
  parameters:
    login_tool:
      description: "Tool that performs login and returns a session token."
      type: string
      default: "auth_login"
    logout_tool:
      description: "Tool that revokes a previously-issued session token."
      type: string
      default: "auth_logout"
    protected_tool:
      description: "Tool that requires an authenticated session token."
      type: string
      default: "protected_resource"
    user:
      description: "Username supplied to login_tool."
      type: string
      default: "wallfacer-probe"
    password:
      description: "Password supplied to login_tool. Override locally; never commit secrets."
      type: string
      default: "wallfacer-probe-password"

invariants: []

sequences:
  - name: "auth-flow.token_revoked_after_logout"
    description: |
      Login → call protected resource (must succeed) → logout → call
      protected resource again with the same token (MUST fail). A
      server that still honors the revoked token after logout has a
      session-fixation bug.
    steps:
      - call: "{{login_tool}}"
        with:
          user: "{{user}}"
          password: "{{password}}"
        bind: session
      - call: "{{protected_tool}}"
        with:
          token: "{{steps.session.response.structuredContent.token}}"
      - call: "{{logout_tool}}"
        with:
          token: "{{steps.session.response.structuredContent.token}}"
      - call: "{{protected_tool}}"
        with:
          token: "{{steps.session.response.structuredContent.token}}"
        expect: error
    test_fixtures:
      - name: "passes when post-logout call rejects the revoked token"
        responses:
          - { isError: false, structuredContent: { token: "tok-1" }, content: [] }
          - { isError: false, content: [{ type: "text", text: "ok" }] }
          - { isError: false, content: [] }
          - { isError: true, content: [{ type: "text", text: "unauthorized" }] }
        expect: pass
      - name: "fails when revoked token is still honored after logout"
        responses:
          - { isError: false, structuredContent: { token: "tok-1" }, content: [] }
          - { isError: false, content: [{ type: "text", text: "ok" }] }
          - { isError: false, content: [] }
          - { isError: false, content: [{ type: "text", text: "ok" }] }
        expect: fail
```
