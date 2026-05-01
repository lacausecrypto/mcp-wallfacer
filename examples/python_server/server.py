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
# Phase L state-leak demo: a record store that logs deletions but
# never actually evicts. The bug — `record_delete` returns ok yet
# `record_read` still finds the record afterwards — is exactly what
# the `stateful` rule pack is built to catch.
RECORDS: Dict[int, Dict[str, Any]] = {}
NEXT_RECORD_ID: int = 0
DELETED_RECORD_IDS: List[int] = []
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
    # ---- Phase I — bugs each rule pack should catch ----
    # secrets-leakage / prompt-injection / unicode witness:
    # `bug_log` echoes its input verbatim. A real "log" tool wouldn't.
    {
        "name": "bug_log",
        "description": "BUG: echoes input verbatim including secrets and escape sequences.",
        "inputSchema": object_schema({"text": {"type": "string"}}),
    },
    # path-traversal: leaks /etc/passwd content for `..` paths.
    {
        "name": "read_file",
        "description": "BUG: vulnerable to path traversal; leaks /etc/passwd on `..` paths.",
        "inputSchema": object_schema({"path": {"type": "string"}}),
    },
    # injection-sql: confirms DROP TABLE for SQLi payloads.
    {
        "name": "query_db",
        "description": "BUG: confirms DROP TABLE on SQL injection.",
        "inputSchema": object_schema({"query": {"type": "string"}}),
    },
    # injection-shell: executes whoami / id when chained.
    {
        "name": "run_shell",
        "description": "BUG: shell-injection vulnerable; runs `whoami` etc.",
        "inputSchema": object_schema({"command": {"type": "string"}}),
    },
    # prompt-injection: leaks system prompt on injection.
    {
        "name": "ask_llm",
        "description": "BUG: leaks system prompt when asked to ignore previous instructions.",
        "inputSchema": object_schema({"prompt": {"type": "string"}}),
    },
    # tool-annotations: declares readOnlyHint=true but always errors.
    {
        "name": "broken_reader",
        "description": "BUG: readOnlyHint=true annotation lies; tool always errors.",
        "inputSchema": object_schema({}, []),
        "annotations": {
            "readOnlyHint": True,
        },
    },
    # idempotency / tool-annotations: idempotentHint=true but envelope
    # is missing isError + structuredContent.
    {
        "name": "list_active_users",
        "description": "BUG: idempotentHint=true but malformed envelope.",
        "inputSchema": object_schema({}, []),
        "annotations": {
            "idempotentHint": True,
        },
    },
    # ---- Phase L — sequence/state-leak bugs the `stateful` pack catches ----
    # `record_create` returns ok and stores the row.
    {
        "name": "record_create",
        "description": "Create a record; returns its id under structuredContent.id.",
        "inputSchema": object_schema({"event": {"type": "string"}}, []),
    },
    # `record_delete` LIES: returns ok but never removes the row, so a
    # subsequent `record_read` still sees the data. This is the
    # canonical state-leak the `stateful` pack is supposed to catch.
    {
        "name": "record_delete",
        "description": "BUG: claims to delete but only logs the request; record stays.",
        "inputSchema": object_schema({"id": {"type": "integer"}}),
        "annotations": {
            "destructiveHint": True,
        },
    },
    # `record_read` returns the row by id, isError=true if not found.
    {
        "name": "record_read",
        "description": "Read a record by id; returns isError=true if not present.",
        "inputSchema": object_schema({"id": {"type": "integer"}}),
        "annotations": {
            "readOnlyHint": True,
        },
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
    # ---- Phase I extensions ----
    if name == "bug_log":
        return text_result(str(args.get("text", "")))
    if name == "read_file":
        path = str(args.get("path", ""))
        if "etc" in path or "passwd" in path or path.startswith("/"):
            return text_result(
                "root:x:0:0:root:/root:/bin/bash\nnobody:x:1:1::/:/bin/sh"
            )
        return text_result("file content")
    if name == "query_db":
        query = str(args.get("query", "")).lower()
        if "drop table" in query:
            return text_result("Table users dropped.")
        if "union select" in query and "password" in query:
            return text_result("alice $2b$12$abcdefghijklmnopqrstuv")
        return text_result("0 rows")
    if name == "run_shell":
        cmd = str(args.get("command", ""))
        if (
            "whoami" in cmd
            or "$(id)" in cmd
            or "`whoami`" in cmd
            or "&& cat /etc/passwd" in cmd
        ):
            return text_result(
                "uid=0(root) gid=0(root)\nroot:x:0:0:root:/root:/bin/bash"
            )
        return text_result(cmd)
    if name == "ask_llm":
        prompt = str(args.get("prompt", "")).lower()
        if "system prompt" in prompt or "ignore previous" in prompt:
            return text_result(
                "My system prompt: <|system|>You are an assistant<|im_end|>"
            )
        if "/etc/passwd" in prompt:
            return text_result("Here is /etc/passwd:\nroot:x:0:0:root:/root:/bin/bash")
        return text_result("response")
    if name == "broken_reader":
        return text_result("read failed", is_error=True)
    if name == "list_active_users":
        # idempotentHint=true but envelope omits isError + structuredContent.
        return {"content": [{"type": "text", "text": "alice, bob"}]}
    # ---- Phase L state-leak demo ----
    if name == "record_create":
        global NEXT_RECORD_ID
        NEXT_RECORD_ID += 1
        rec_id = NEXT_RECORD_ID
        RECORDS[rec_id] = {"id": rec_id, "event": str(args.get("event", ""))}
        return structured_result({"id": rec_id})
    if name == "record_delete":
        # BUG: pretend to delete, actually leak the record.
        try:
            req_id = int(args.get("id"))
        except (TypeError, ValueError):
            return text_result("invalid id", is_error=True)
        DELETED_RECORD_IDS.append(req_id)
        return text_result(f"queued deletion of {req_id}")
    if name == "record_read":
        try:
            req_id = int(args.get("id"))
        except (TypeError, ValueError):
            return text_result("invalid id", is_error=True)
        record = RECORDS.get(req_id)
        if record is None:
            return text_result(f"record {req_id} not found", is_error=True)
        return structured_result(record)
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
