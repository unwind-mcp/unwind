
import json, sys, os

# Track what actually gets executed upstream (to verify ghost interception)
EXECUTION_LOG = []

TOOLS = [
    {"name": "fs_read", "description": "Read a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "fs_write", "description": "Write a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}},
    {"name": "fs_delete", "description": "Delete a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "fetch_web", "description": "Fetch a URL", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},
    {"name": "send_email", "description": "Send an email", "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}},
    {"name": "bash_exec", "description": "Execute a bash command", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}},
]

def respond(id, result):
    msg = json.dumps({"jsonrpc": "2.0", "id": id, "result": result})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()

def error(id, code, message):
    msg = json.dumps({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue

    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params", {})

    if method == "initialize":
        respond(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-upstream-ghost", "version": "1.0.0"},
        })
    elif method == "tools/list":
        respond(req_id, {"tools": TOOLS})
    elif method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})
        EXECUTION_LOG.append({"tool": tool_name, "args": args})
        if tool_name == "fs_read":
            path = args.get("path", "?")
            respond(req_id, {"content": [{"type": "text", "text": f"Real content of {path}"}]})
        elif tool_name == "fs_write":
            respond(req_id, {"content": [{"type": "text", "text": f"Wrote to {args.get('path', '?')}"}]})
        elif tool_name == "fs_delete":
            respond(req_id, {"content": [{"type": "text", "text": f"Deleted {args.get('path', '?')}"}]})
        elif tool_name == "fetch_web":
            respond(req_id, {"content": [{"type": "text", "text": f"Fetched {args.get('url', '?')}"}]})
        elif tool_name == "send_email":
            respond(req_id, {"content": [{"type": "text", "text": f"Sent to {args.get('to', '?')}"}]})
        elif tool_name == "bash_exec":
            respond(req_id, {"content": [{"type": "text", "text": f"Executed: {args.get('command', '?')}"}]})
        else:
            error(req_id, -32601, f"Unknown tool: {tool_name}")
    elif method == "notifications/initialized":
        pass
    else:
        if req_id is not None:
            error(req_id, -32601, f"Method not found: {method}")
