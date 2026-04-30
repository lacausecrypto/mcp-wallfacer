# mcp-wallfacer

[![Crates.io](https://img.shields.io/crates/v/mcp-wallfacer?style=plastic)](https://crates.io/crates/mcp-wallfacer)
[![All-time downloads](https://img.shields.io/crates/d/mcp-wallfacer?style=plastic&label=downloads)](https://crates.io/crates/mcp-wallfacer)
[![Docs.rs](https://img.shields.io/docsrs/mcp-wallfacer?style=plastic)](https://docs.rs/mcp-wallfacer)
[![CI](https://img.shields.io/github/actions/workflow/status/lacausecrypto/mcp-wallfacer/ci.yml?branch=main&style=plastic&label=ci)](https://github.com/lacausecrypto/mcp-wallfacer/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/mcp-wallfacer?style=plastic)](https://github.com/lacausecrypto/mcp-wallfacer#license)

`mcp-wallfacer` is a dynamic validation harness for MCP servers. It connects to a server over stdio or Streamable HTTP, exercises tools with generated inputs, checks declared response schemas and invariants, and stores reproducible findings in `.wallfacer/corpus/`.

It is intended for MCP server authors before publication and in CI. It complements static scanners such as Snyk Agent Scan, Cisco MCP Scanner, and Enkrypt-style checks by validating runtime behavior instead of inspecting source code or tool descriptions.

## Install

Requires Rust 1.88 or newer. The original 1.83 target is not compatible with the current official `rmcp` SDK, which uses Rust features stabilized after 1.83.

```bash
cargo install mcp-wallfacer
```

The crates.io package is `mcp-wallfacer`; the installed binary is `wallfacer`.

## Quickstart

```bash
wallfacer init
wallfacer doctor
wallfacer fuzz --seed 42 --iterations 200
wallfacer differential --learn
wallfacer differential
wallfacer property tests/invariants.yaml
wallfacer torture --concurrency 100
wallfacer ci --format sarif > wallfacer.sarif
```

Findings are serialized as JSON under `.wallfacer/corpus/<tool>/<finding_id>.json` with the seed and exact tool call needed for reproduction.

## Commands

- `init`: create `wallfacer.toml`, optionally with CI workflow template.
- `doctor`: connect and list tools, resources, and prompts.
- `fuzz`: generate adversarial tool inputs and detect crashes, hangs, and protocol errors.
- `differential`: compare runtime responses with declared or learned output schemas.
- `property`: evaluate YAML invariants over generated or fixed cases.
- `torture`: run concurrency and state-boundary checks.
- `corpus`: list, show, replay, and minimize stored findings.
- `ci`: run a short CI-oriented pass and emit human, JSON, or SARIF output.

## Configuration

```toml
[target]
kind = "stdio"
command = "python3"
args = ["server.py"]
timeout_ms = 5000

[output]
corpus_dir = ".wallfacer/corpus"

[allow_destructive]
tools = []
```

HTTP targets use:

```toml
[target]
kind = "http"
url = "http://localhost:8000/mcp"
headers = { Authorization = "Bearer xxx" }
```

## Roadmap

- v0.2: richer property DSL and regression comparison between server versions.
- v0.3: rule packs for common MCP security and reliability issues.
- v0.4: shared corpus workflows and reporting.
