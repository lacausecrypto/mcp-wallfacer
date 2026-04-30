# Wallfacer rule pack catalog

Auto-generated from the embedded YAML packs by `cargo run -p wallfacer-tools -- gen-pack-docs`. Edit a pack's YAML and re-run to refresh.

| Pack | Description |
|---|---|
| [`auth`](./auth.md) | Runtime checks for authentication and authorization contracts. |
| [`authorization`](./authorization.md) | Probes role-based access control on resource-listing and admin-call tools. |
| [`error-shape`](./error-shape.md) | Verifies the shape of error envelopes returned by tool calls. |
| [`idempotency`](./idempotency.md) | Probes idempotentHint=true tools for envelope stability. |
| [`injection-shell`](./injection-shell.md) | Probes a process-bridging tool with shell-injection payloads. |
| [`injection-sql`](./injection-sql.md) | Probes a DB-bridging tool with SQL-injection payloads. |
| [`large-payload`](./large-payload.md) | Probes a witness tool with oversized strings and arrays. |
| [`pagination`](./pagination.md) | Validates limit / cursor / page metadata semantics on list tools. |
| [`path-traversal`](./path-traversal.md) | Probes filesystem-bridging tools for path-traversal escapes. |
| [`prompt-injection`](./prompt-injection.md) | Probes an LLM-bridging tool for prompt-injection susceptibility. |
| [`rate-limit`](./rate-limit.md) | Validates rate-limit envelope shape and metadata for API-bridging tools. |
| [`secrets-leakage`](./secrets-leakage.md) | Probes a witness tool to confirm secrets are not echoed in responses. |
| [`security`](./security.md) | Meta-pack composing the security-oriented rule packs. |
| [`tool-annotations`](./tool-annotations.md) | Verifies MCP tool annotations agree with observable runtime behaviour. |
| [`unicode`](./unicode.md) | Stresses a string tool with adversarial unicode codepoints. |

