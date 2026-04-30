"""Six-bug MCP-like stdio server, one bug per `wallfacer` finding kind.

Run via: `wallfacer fuzz`, `wallfacer differential --learn && wallfacer
differential`, `wallfacer property invariants.yaml`, and
`wallfacer torture --mode state-leak`. The README in this directory
describes which command surfaces which bug.

Implementation note: this fixture speaks just enough JSON-RPC over stdio
to interoperate with rmcp's stdio transport without depending on a Python
SDK runtime.
"""

import asyncio
import json
import os
import sys
from typing import Any, Dict, List


SESSIONS: Dict[str, Any] = {}
WRITE_LOCK = asyncio.Lock()


def object_schema(properties: Dict[str, Any], required: List[str] = None) -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required if required is not None else list(properties),
        "additionalProperties": False,
    }


# Each tool intentionally exercises a different `FindingKind`. The mapping
# is documented in this file's README.
TOOLS = [
    # FindingKind::Crash — server exits the process when any args are sent.
    {
        "name": "crashes_now",
        "description": "BUG: terminates the process on any call.",
        "inputSchema": object_schema({}, []),
    },
    # FindingKind::Hang — server never responds.
    {
        "name": "hangs_forever",
        "description": "BUG: awaits an infinite sleep.",
        "inputSchema": object_schema({}, []),
    },
    # FindingKind::SchemaViolation — declares an integer id, returns a string.
    {
        "name": "wrong_id_type",
        "description": "BUG: returns id as a string despite output schema saying integer.",
        "inputSchema": object_schema({}),
        "outputSchema": object_schema(
            {"id": {"type": "integer"}, "name": {"type": "string"}}
        ),
    },
    # FindingKind::PropertyFailure — paginate returns limit+1 items every other call.
    {
        "name": "paginate",
        "description": "BUG: occasionally returns one too many items.",
        "inputSchema": object_schema(
            {"limit": {"type": "integer", "minimum": 1, "maximum": 50}}
        ),
        "outputSchema": object_schema(
            {"items": {"type": "array", "items": {"type": "integer"}, "maxItems": 50}}
        ),
    },
    # FindingKind::ProtocolError — server emits non-JSON before its response.
    {
        "name": "bad_protocol",
        "description": "BUG: writes a non-JSON-RPC line to stdout.",
        "inputSchema": object_schema({}, []),
    },
    # FindingKind::StateLeak — session_get reads global session state seeded
    # by a previous call.
    {
        "name": "session_set",
        "description": "Sets a global session value (used to seed the leak probe).",
        "inputSchema": object_schema(
            {"key": {"type": "string"}, "value": {"type": "string"}}
        ),
    },
    {
        "name": "session_get",
        "description": "BUG: reads global shared session state.",
        "inputSchema": object_schema({"key": {"type": "string"}}),
    },
]


PAGINATE_TOGGLE = 0


async def send(message: Dict[str, Any]) -> None:
    async with WRITE_LOCK:
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def text_result(text: str, is_error: bool = False) -> Dict[str, Any]:
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }


def structured_result(value: Any, is_error: bool = False) -> Dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(value)}],
        "structuredContent": value,
        "isError": is_error,
    }


async def call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    global PAGINATE_TOGGLE

    if name == "crashes_now":
        os._exit(1)
    if name == "hangs_forever":
        while True:
            await asyncio.sleep(3600)
    if name == "wrong_id_type":
        return structured_result({"id": "string!", "name": "alice"})
    if name == "paginate":
        limit = int(args.get("limit", 1))
        PAGINATE_TOGGLE += 1
        count = limit + 1 if PAGINATE_TOGGLE % 2 else limit
        return structured_result({"items": list(range(count))})
    if name == "bad_protocol":
        # Raises so the framework's catch-all writes a JSON-RPC error
        # envelope; rmcp surfaces that as `CallOutcome::ProtocolError` and
        # wallfacer records a `FindingKind::ProtocolError`.
        raise RuntimeError("malformed by design")
    if name == "session_set":
        SESSIONS[str(args["key"])] = args.get("value")
        return structured_result({"ok": True})
    if name == "session_get":
        return structured_result({"value": SESSIONS.get(str(args["key"]))})
    return text_result(f"unknown tool: {name}", is_error=True)


async def handle_request(message: Dict[str, Any]) -> None:
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}
    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
                },
                "serverInfo": {"name": "wallfacer-example-server", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "resources/list":
            result = {"resources": []}
        elif method == "prompts/list":
            result = {"prompts": []}
        elif method == "tools/call":
            result = await call_tool(params.get("name", ""), params.get("arguments") or {})
        else:
            await send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
            )
            return
        await send({"jsonrpc": "2.0", "id": request_id, "result": result})
    except Exception as exc:
        await send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": str(exc)},
            }
        )


async def main() -> None:
    while True:
        line = await asyncio.to_thread(sys.stdin.buffer.readline)
        if not line:
            break
        try:
            message = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            continue
        if "id" in message:
            asyncio.create_task(handle_request(message))


if __name__ == "__main__":
    asyncio.run(main())
