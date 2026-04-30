# Upstream issue template — wallfacer finding

Use this template when reporting a confirmed real-world finding from
wallfacer to the upstream MCP server's maintainer. **Re-redact any
secrets** before sharing — the corpus contains them in
`<redacted>` form, but values you supplied via
`WALLFACER_REPLAY_<KEY>` env vars during local replay are not.

---

## Title

`<short, server-side framing — e.g. "fetch tool echoes Authorization header in error message">`

## Severity

`<low | medium | high | critical>` — match the wallfacer Severity if
unsure.

## Reproduction

* MCP server: `<package@version>` (commit `<sha>` if known)
* Reproduced with: `wallfacer <version>`, pack
  `<pack name>`, invariant `<auth.unauthenticated_requests_are_rejected>`
* Reproduction steps:

  ```bash
  # 1. Spawn the server
  uvx <package> &
  # 2. Run the pack against it
  wallfacer property --pack <pack> --seed 42
  # 3. Confirm the finding ID
  wallfacer corpus list
  # 4. Replay
  wallfacer replay <finding-id>
  ```

## Expected behavior

`<one paragraph>`

## Observed behavior

`<one paragraph>` plus relevant excerpt from the corpus finding (run
`wallfacer corpus show <id>`).

## Wallfacer finding excerpt

```json
<paste the redacted Finding JSON here, scrubbing any leaked
secrets a second time before sending>
```

## Suggested fix

`<optional — link to the responsible code path if known>`

## Disclosure

If this is security-sensitive (auth bypass, secret exfiltration,
arbitrary command execution, etc.), please confirm a private channel
before public disclosure. Otherwise this issue can be public.

---

*Wallfacer is a runtime validation harness for MCP servers. The
finding above was produced by automated pack runs; we replicated
the bug manually before filing this issue.*
