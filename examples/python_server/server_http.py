"""Minimal HTTP MCP fixture for Phase M acceptance testing.

Serves the same buggy tools as `server.py` but over Streamable HTTP
on a single `POST /mcp` endpoint. Pure Python stdlib (no FastAPI /
uvicorn dep), so the e2e test can spawn it with just `python3
server_http.py <port>` after `pip install` of nothing.

Spec compliance — we implement only what the rmcp client requires:
- Accept `POST /mcp` with `Content-Type: application/json`
- Parse the JSON-RPC body
- Dispatch to the same `call_tool` / tool list as the stdio server
- Reply with `Content-Type: application/json` and a single JSON-RPC
  response (no SSE, no batching, no session)

This is enough to pass the rmcp `streamable_http_client_reqwest`
content-negotiation path. If wallfacer's HTTP transport ever needs
SSE for our use case, the runner / test will surface it and we can
extend this fixture.
"""

from __future__ import annotations

import asyncio
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

# Import the existing tool catalog + dispatch from the stdio fixture
# so HTTP and stdio share the same buggy behaviour. The CI test
# expects identical findings across the two transports.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from server import TOOLS, call_tool  # noqa: E402  intentional: shared catalog


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
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {"name": "wallfacer-http-fixture", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            result = await call_tool(params.get("name", ""), params.get("arguments") or {})
        elif method == "notifications/initialized":
            # Notifications carry no `id`; respond with 202 by returning
            # None at the HTTP layer.
            return None  # type: ignore[return-value]
        else:
            return make_error(request_id, -32601, f"method not found: {method}")
    except Exception as err:  # noqa: BLE001 — surface every failure cleanly.
        return make_error(request_id, -32603, f"internal error: {err}")
    return make_response(request_id, result)


class Handler(BaseHTTPRequestHandler):
    # Silence the per-request access log that would interleave with
    # wallfacer's stderr in CI.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def do_POST(self) -> None:  # noqa: N802 — stdlib API name.
        length = int(self.headers.get("Content-Length", "0"))
        body_bytes = self.rfile.read(length) if length else b""
        try:
            message = json.loads(body_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "invalid JSON"}')
            return

        loop = asyncio.new_event_loop()
        try:
            response = loop.run_until_complete(dispatch(message))
        finally:
            loop.close()

        if response is None:
            # A notification we acknowledge without a body.
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


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    actual_port = server.server_address[1]
    # Print the bound port to stdout so the spawning process can pick
    # it up without parsing log noise. This lets the e2e test pass
    # `port=0` and learn the OS-assigned port back.
    print(actual_port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
