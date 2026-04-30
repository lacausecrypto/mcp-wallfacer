# Pack — `rate-limit`

> Validates rate-limit envelope shape and metadata for API-bridging tools.

**Tags:** `reliability`, `api`
**Authors:** wallfacer-core

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `quota_tool` | string | `rate_limit_status` | Tool that returns current rate-limit quotas. |

## Invariants

### `rate.quota_response_carries_numeric_remaining`

- **Tool:** `rate_limit_status`
- **Inputs:** fixed (0 field(s))
- **Assertion summary:** matches_schema(`$.response.structuredContent`)
- **Test fixtures:** 3 (`pass`, `fail`, `fail`)

### `rate.remaining_does_not_exceed_limit`

- **Tool:** `rate_limit_status`
- **Inputs:** fixed (0 field(s))
- **Assertion summary:** at_most(`$.response.structuredContent.remaining`)
- **Test fixtures:** 2 (`pass`, `fail`)

### `rate.error_envelope_includes_retry_after`

- **Tool:** `rate_limit_status`
- **Inputs:** fixed (1 field(s))
- **Assertion summary:** any_of(2 child)
- **Test fixtures:** 3 (`pass`, `pass`, `fail`)

## Source

Raw YAML, embedded into the binary at compile time:

```yaml
# Rate-limit rule pack.
#
# Verifies the shape of rate-limit responses and metadata exposed by an
# API-bridging tool. Skip this pack on servers that don't surface
# rate-limit info.
version: 3
metadata:
  name: rate-limit
  description: "Validates rate-limit envelope shape and metadata for API-bridging tools."
  authors: ["wallfacer-core"]
  tags: [reliability, api]
  parameters:
    quota_tool:
      description: "Tool that returns current rate-limit quotas."
      type: string
      default: "rate_limit_status"

invariants:
  - name: "rate.quota_response_carries_numeric_remaining"
    tool: "{{quota_tool}}"
    fixed: {}
    assert:
      - kind: matches_schema
        path: "$.response.structuredContent"
        schema:
          type: object
          required: [limit, remaining]
          properties:
            limit: { type: integer, minimum: 0 }
            remaining: { type: integer, minimum: 0 }
            reset:
              oneOf:
                - { type: integer }
                - { type: string }
    test_fixtures:
      - name: "passes with well-formed quota response"
        response:
          structuredContent:
            limit: 1000
            remaining: 999
            reset: 1700000000
        expect: pass
      - name: "fails when remaining is missing"
        response:
          structuredContent:
            limit: 1000
        expect: fail
      - name: "fails when remaining is a string"
        response:
          structuredContent:
            limit: 1000
            remaining: "many"
        expect: fail

  - name: "rate.remaining_does_not_exceed_limit"
    tool: "{{quota_tool}}"
    fixed: {}
    assert:
      - kind: at_most
        path: "$.response.structuredContent.remaining"
        value: { path: "$.response.structuredContent.limit" }
    test_fixtures:
      - name: "passes when remaining < limit"
        response:
          structuredContent: { limit: 100, remaining: 42 }
        expect: pass
      - name: "fails when remaining > limit"
        response:
          structuredContent: { limit: 100, remaining: 1000 }
        expect: fail

  - name: "rate.error_envelope_includes_retry_after"
    tool: "{{quota_tool}}"
    fixed: { force_429: true }
    assert:
      - kind: any_of
        assert:
          - kind: equals
            lhs: { path: "$.response.isError" }
            rhs: { value: false }
          - kind: matches_schema
            path: "$.response.structuredContent"
            schema:
              type: object
              required: [retry_after]
              properties:
                retry_after: { type: integer, minimum: 0 }
    test_fixtures:
      - name: "passes when no error returned"
        response: { isError: false, structuredContent: { limit: 100, remaining: 50 } }
        expect: pass
      - name: "passes when error includes retry_after"
        response:
          isError: true
          structuredContent: { retry_after: 30 }
        expect: pass
      - name: "fails when error lacks retry_after"
        response:
          isError: true
          structuredContent: { reason: "rate limited" }
        expect: fail
```
