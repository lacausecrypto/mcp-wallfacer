# Wallfacer rule pack catalog

Auto-generated from the embedded YAML packs by `cargo run -p wallfacer-tools -- gen-pack-docs`. Edit a pack's YAML and re-run to refresh.

| Pack | Description |
|---|---|
| [`auth`](./auth.md) | Runtime checks for authentication and authorization contracts. |
| [`auth-flow`](./auth-flow.md) | Multi-step sequences that probe login / logout token invalidation. |
| [`authorization`](./authorization.md) | Probes role-based access control on resource-listing and admin-call tools. |
| [`context-poisoning`](./context-poisoning.md) | Detects MCP servers planting prompt injections in tool descriptions or call responses. |
| [`error-shape`](./error-shape.md) | Verifies the shape of error envelopes returned by tool calls. |
| [`idempotency`](./idempotency.md) | Probes idempotentHint=true tools for envelope stability. |
| [`injection-shell`](./injection-shell.md) | Probes a process-bridging tool with shell-injection payloads. |
| [`injection-sql`](./injection-sql.md) | Probes a DB-bridging tool with SQL-injection payloads. |
| [`large-payload`](./large-payload.md) | Probes a witness tool with oversized strings and arrays. |
| [`mcp-spec-conformance`](./mcp-spec-conformance.md) | Validates the MCP protocol wire-format envelope on every tool response. |
| [`pagination`](./pagination.md) | Validates limit / cursor / page metadata semantics on list tools. |
| [`path-traversal`](./path-traversal.md) | Probes filesystem-bridging tools for path-traversal escapes. |
| [`prompt-injection`](./prompt-injection.md) | Probes an LLM-bridging tool for prompt-injection susceptibility. |
| [`prompt-injection-v2`](./prompt-injection-v2.md) | Grammar-expanded prompt-injection variants: jailbreaks, multilingual, encoded payloads, formatting tricks. |
| [`rate-limit`](./rate-limit.md) | Validates rate-limit envelope shape and metadata for API-bridging tools. |
| [`secrets-leakage`](./secrets-leakage.md) | Probes a witness tool to confirm secrets are not echoed in responses. |
| [`security`](./security.md) | Meta-pack composing the security-oriented rule packs. |
| [`stateful`](./stateful.md) | Multi-step sequences that probe create / read / delete state continuity. |
| [`tool-annotations`](./tool-annotations.md) | Verifies MCP tool annotations agree with envelope-shape contracts. |
| [`unicode`](./unicode.md) | Stresses a string tool with adversarial unicode codepoints. |

