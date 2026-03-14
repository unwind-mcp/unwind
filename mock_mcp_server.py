import sys
import json

def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            req = json.loads(line)
            # Mock MCP response
            resp = {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {"content": [{"type": "text", "text": "mock real server content"}]}
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception:
            pass

if __name__ == "__main__":
    main()
