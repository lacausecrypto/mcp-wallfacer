"""HTTP MCP fixture that injects production-like faults.

Phase W (v0.7) — extends the JSON-only fixture from
`server_http.py` with deterministic, seed-driven fault injection so
the wallfacer test suite can exercise the runner's behaviour
against the failure modes a real reverse-proxied MCP server
faces:

- 502 Bad Gateway (CDN / nginx upstream failure)
- 504 Gateway Timeout
- Empty connection (FIN before headers)
- Mid-body FIN (write half a JSON response, close)
- Slow response (sleep before sending)

CLI:
  python3 server_http_faulty.py <port> [--fault-mode MODE] [--fault-rate RATE]

`--fault-mode` is one of: `502`, `504`, `fin-empty`, `fin-mid`,
`slow`, `none` (default `none` — behaves like `server_http.py`).
`--fault-rate` is the probability `0.0..=1.0` that any given
request hits the configured fault. Default `1.0` (always faulty)
when a mode is set.

The fault injection is **deterministic per-request when a seed is
set**: pass `--seed N` to make decisions reproducible, otherwise
the OS RNG is used. This matters for CI gates that need stable
runs.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

# Reuse the in-process tool catalog + dispatch from the stdio
# fixture so a non-faulty request still goes through the same
# bug zoo.
import asyncio
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from server import TOOLS, call_tool  # noqa: E402


FAULT_MODES = ("none", "502", "504", "fin-empty", "fin-mid", "slow")
RNG: random.Random = random.Random()
FAULT_MODE: str = "none"
FAULT_RATE: float = 1.0


def make_response(request_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def make_error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


async def dispatch(message: Dict[str, Any]) -> Dict[str, Any]:
    request_id = message.get("id")
    method = message.get("method", "")
    params = message.get("params") or {}
    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "wallfacer-http-faulty", "version": "0.7.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            result = await call_tool(params.get("name", ""), params.get("arguments") or {})
        elif method == "notifications/initialized":
            return None  # type: ignore[return-value]
        else:
            return make_error(request_id, -32601, f"method not found: {method}")
    except Exception as err:  # noqa: BLE001
        return make_error(request_id, -32603, f"internal error: {err}")
    return make_response(request_id, result)


def _should_inject() -> bool:
    if FAULT_MODE == "none":
        return False
    return RNG.random() < FAULT_RATE


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def do_POST(self) -> None:  # noqa: N802
        # Always read the body so the client sees its request was
        # received (otherwise some HTTP libraries hang on the
        # write side waiting for backpressure).
        length = int(self.headers.get("Content-Length", "0"))
        body_bytes = self.rfile.read(length) if length else b""

        # Skip fault injection for the initialize handshake — we
        # need the rmcp client to *complete* the handshake before
        # the test can drive subsequent calls into faults.
        try:
            message = json.loads(body_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        # We *only* fault `tools/call`. The handshake
        # (`initialize` + `notifications/initialized`) and tool
        # discovery (`tools/list`) need to succeed for a wallfacer
        # run to even begin — faulting them turns every test into
        # a "couldn't connect" run-level failure rather than the
        # per-call ProtocolError we want to exercise. Production
        # reverse-proxies are far more likely to crap out on the
        # POST /mcp body of a real tool call than on the cold-
        # path discovery anyway.
        method = message.get("method", "")
        fault_eligible = method == "tools/call"

        if fault_eligible and _should_inject():
            inject(self, message)
            return

        loop = asyncio.new_event_loop()
        try:
            response = loop.run_until_complete(dispatch(message))
        finally:
            loop.close()

        if response is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        body = json.dumps(response, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def inject(handler: BaseHTTPRequestHandler, _message: Dict[str, Any]) -> None:
    """Apply the configured fault, then return without writing
    a normal response. Each branch closes the wfile / connection
    in the way that mode demands."""
    if FAULT_MODE == "502":
        handler.send_response(502)
        handler.send_header("Content-Type", "text/plain")
        handler.send_header("Content-Length", "11")
        handler.end_headers()
        handler.wfile.write(b"bad gateway")
    elif FAULT_MODE == "504":
        handler.send_response(504)
        handler.send_header("Content-Type", "text/plain")
        handler.send_header("Content-Length", "15")
        handler.end_headers()
        handler.wfile.write(b"gateway timeout")
    elif FAULT_MODE == "fin-empty":
        # Close the connection without writing any HTTP headers.
        # The client should observe an EOF / connection-reset.
        try:
            handler.wfile.close()
            handler.rfile.close()
            handler.connection.close()
        except OSError:
            pass
    elif FAULT_MODE == "fin-mid":
        # Start a 200 response, write half the body, then close.
        partial = b'{"jsonrpc":"2.0","id":1,"res'  # truncated mid-key
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        # Lie about Content-Length so the client expects more
        # bytes than we deliver — that is the actual fault.
        handler.send_header("Content-Length", str(len(partial) + 50))
        handler.end_headers()
        handler.wfile.write(partial)
        try:
            handler.wfile.flush()
            handler.connection.close()
        except OSError:
            pass
    elif FAULT_MODE == "slow":
        # Sleep long enough that any reasonable client timeout
        # fires, then send a normal response.
        time.sleep(30)
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", "0")
        handler.end_headers()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    parser.add_argument("--fault-mode", choices=FAULT_MODES, default="none")
    parser.add_argument("--fault-rate", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    global FAULT_MODE, FAULT_RATE, RNG
    FAULT_MODE = args.fault_mode
    FAULT_RATE = max(0.0, min(1.0, args.fault_rate))
    if args.seed is not None:
        RNG = random.Random(args.seed)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(server.server_address[1], flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
