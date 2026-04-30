"""Buggy MCP-like stdio server with intentional bugs for wallfacer e2e tests.

This fixture implements the subset of MCP needed by wallfacer's tests without
depending on a specific Python SDK runtime. Do not fix the intentional bugs.
"""

import asyncio
import json
import os
import sys
from typing import Any, Dict, List


sys.setrecursionlimit(10_000)

COUNTER = 0
SESSIONS: Dict[str, Any] = {}
STATUS_TOGGLE = 0
PAGINATE_TOGGLE = 0
WRITE_LOCK = asyncio.Lock()


def object_schema(properties: Dict[str, Any], required: List[str] = None) -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or list(properties),
        "additionalProperties": False,
    }


TOOLS = [
    {
        "name": "echo",
        "description": "Sane: returns input verbatim.",
        "inputSchema": object_schema({"text": {"type": "string"}}),
    },
    {
        "name": "add",
        "description": "Sane: adds two integers.",
        "inputSchema": object_schema(
            {"a": {"type": "integer"}, "b": {"type": "integer"}}
        ),
    },
    {
        "name": "divide",
        "description": "BUG: exits the process when b is zero.",
        "inputSchema": object_schema(
            {"a": {"type": "integer"}, "b": {"type": "integer"}}
        ),
    },
    {
        "name": "slice",
        "description": "BUG: never responds when n is negative.",
        "inputSchema": object_schema(
            {"s": {"type": "string"}, "n": {"type": "integer"}}
        ),
    },
    {
        "name": "parse_json",
        "description": "BUG: writes invalid protocol output for large strings.",
        "inputSchema": object_schema({"blob": {"type": "string"}}),
    },
    {
        "name": "accumulate",
        "description": "BUG: exits the process for very large arrays.",
        "inputSchema": object_schema(
            {"items": {"type": "array", "items": {"type": "integer"}}}
        ),
    },
    {
        "name": "lookup_user",
        "description": "BUG: returns id as a string even though schema says integer.",
        "inputSchema": object_schema({"id": {"type": "integer"}}),
        "outputSchema": object_schema(
            {"id": {"type": "integer"}, "name": {"type": "string"}}
        ),
    },
    {
        "name": "get_status",
        "description": "BUG: alternates between status and state keys.",
        "inputSchema": object_schema({}, []),
        "outputSchema": object_schema({"status": {"type": "string"}}),
    },
    {
        "name": "paginate",
        "description": "BUG: sometimes returns limit + 1 items.",
        "inputSchema": object_schema(
            {"page": {"type": "integer"}, "limit": {"type": "integer", "minimum": 1}}
        ),
        "outputSchema": object_schema(
            {"items": {"type": "array", "items": {"type": "integer"}}}
        ),
    },
    {
        "name": "counter_inc",
        "description": "BUG: non-atomic counter increment.",
        "inputSchema": object_schema({}, []),
    },
    {
        "name": "counter_get",
        "description": "Sane: returns the counter.",
        "inputSchema": object_schema({}, []),
    },
    {
        "name": "session_set",
        "description": "BUG: writes to global shared session state.",
        "inputSchema": object_schema(
            {"key": {"type": "string"}, "value": {"type": "string"}}
        ),
    },
    {
        "name": "session_get",
        "description": "BUG: reads global shared session state.",
        "inputSchema": object_schema({"key": {"type": "string"}}),
    },
    {
        "name": "slow_op",
        "description": "Sane: sleeps for delay_ms.",
        "inputSchema": object_schema({"delay_ms": {"type": "integer", "minimum": 0}}),
    },
]


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
    global COUNTER, STATUS_TOGGLE, PAGINATE_TOGGLE

    if name == "echo":
        return text_result(str(args.get("text", "")))
    if name == "add":
        return structured_result(int(args["a"]) + int(args["b"]))
    if name == "divide":
        if int(args["b"]) == 0:
            os._exit(1)
        return structured_result(int(args["a"]) / int(args["b"]))
    if name == "slice":
        if int(args["n"]) < 0:
            while True:
                await asyncio.sleep(3600)
        return text_result(str(args["s"])[: int(args["n"])])
    if name == "parse_json":
        blob = str(args.get("blob", ""))
        if len(blob) > 100_000:
            async with WRITE_LOCK:
                sys.stdout.write("this is not json\n")
                sys.stdout.flush()
            while True:
                await asyncio.sleep(3600)
        return structured_result(json.loads(blob))
    if name == "accumulate":
        items = list(args.get("items", []))
        if len(items) > 1_000_000:
            os._exit(1)
        return structured_result(sum(int(item) for item in items))
    if name == "lookup_user":
        return structured_result({"id": "string!", "name": f"user-{args['id']}"})
    if name == "get_status":
        STATUS_TOGGLE += 1
        if STATUS_TOGGLE % 2 == 0:
            return structured_result({"status": "ok"})
        return structured_result({"state": "ok"})
    if name == "paginate":
        limit = int(args["limit"])
        PAGINATE_TOGGLE += 1
        count = limit + 1 if PAGINATE_TOGGLE % 2 else limit
        return structured_result({"items": list(range(count))})
    if name == "counter_inc":
        tmp = COUNTER
        await asyncio.sleep(0.001)
        COUNTER = tmp + 1
        return structured_result({"counter": COUNTER})
    if name == "counter_get":
        return structured_result({"counter": COUNTER})
    if name == "session_set":
        SESSIONS[str(args["key"])] = args.get("value")
        return structured_result({"ok": True})
    if name == "session_get":
        return structured_result({"value": SESSIONS.get(str(args["key"]))})
    if name == "slow_op":
        await asyncio.sleep(int(args["delay_ms"]) / 1000)
        return structured_result({"ok": True})

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
                "serverInfo": {"name": "buggy-server", "version": "0.1.0"},
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
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=32 * 1024 * 1024)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        line = await reader.readline()
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
