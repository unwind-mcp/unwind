"""Minimal stdio MCP server used by the proxy tests.

Mimics the tool names, annotations and output formats of
@modelcontextprotocol/server-filesystem for one root directory. Its write
tools really write, so tests can prove Ghost Mode never forwards them.
"""

import json
import os
import sys

ROOT = sys.argv[1]

READ = {"readOnlyHint": True}
WRITE = {"readOnlyHint": False}
TOOLS = {
    "read_text_file": READ, "read_multiple_files": READ, "list_directory": READ,
    "directory_tree": READ, "search_files": READ, "get_file_info": READ,
    "write_file": WRITE, "edit_file": WRITE, "move_file": WRITE,
    "create_directory": WRITE,
    "mystery_tool": {},  # no hints: Ghost Mode must block it
}


def text(t, error=False):
    r = {"content": [{"type": "text", "text": t}]}
    if error:
        r["isError"] = True
    return r


def call(name, a):
    p = a.get("path")
    try:
        if name == "read_text_file":
            with open(p) as f:
                return text(f.read())
        if name == "read_multiple_files":
            out = []
            for q in a["paths"]:
                try:
                    with open(q) as f:
                        out.append(f"{q}:\n{f.read()}\n")
                except OSError as e:
                    out.append(f"{q}: Error - {e}")
            return text("\n---\n".join(out))
        if name == "list_directory":
            return text("\n".join(
                f"[{'DIR' if os.path.isdir(os.path.join(p, n)) else 'FILE'}] {n}"
                for n in sorted(os.listdir(p))))
        if name == "directory_tree":
            def tree(d):
                return [{"name": n, "type": "directory", "children": tree(os.path.join(d, n))}
                        if os.path.isdir(os.path.join(d, n)) else {"name": n, "type": "file"}
                        for n in sorted(os.listdir(d))]
            return text(json.dumps(tree(p), indent=2))
        if name == "search_files":
            hits = [os.path.join(d, n) for d, ds, fs in os.walk(p) for n in ds + fs
                    if a["pattern"].lower() in n.lower()]
            return text("\n".join(hits) if hits else "No matches found")
        if name == "get_file_info":
            st = os.stat(p)
            return text(f"size: {st.st_size}\nisDirectory: {str(os.path.isdir(p)).lower()}")
        if name == "write_file":
            with open(p, "w") as f:
                f.write(a["content"])
            return text(f"Successfully wrote to {p}")
        if name == "edit_file":
            with open(p, "a") as f:
                f.write("REAL EDIT")
            return text("edited")
        if name == "move_file":
            os.rename(a["source"], a["destination"])
            return text("moved")
        if name == "create_directory":
            os.makedirs(p, exist_ok=True)
            return text("created")
        if name == "mystery_tool":
            with open(os.path.join(ROOT, "MYSTERY_RAN"), "w") as f:
                f.write("x")
            return text("mystery done")
    except OSError as e:
        return text(f"ENOENT: {e}", error=True)
    return text(f"Unknown tool {name}", error=True)


for line in sys.stdin:
    msg = json.loads(line)
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        continue
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fake", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": n, "inputSchema": {"type": "object"}, "annotations": an}
                            for n, an in TOOLS.items()]}
    elif method == "tools/call":
        result = call(msg["params"]["name"], msg["params"].get("arguments", {}))
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
    sys.stdout.flush()
