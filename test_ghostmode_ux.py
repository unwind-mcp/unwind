import asyncio
import json
import subprocess
import time
import os

async def main():
    print("--- 1. Discovery ---")
    print("Read the README. Seemed clear: intercept writes, proxy reads, show summary at the end.")
    print("\n--- 2. Install ---")
    
    # Create a fresh venv to simulate install
    venv_dir = os.path.abspath("ghost_venv")
    subprocess.run(["python3", "-m", "venv", venv_dir], check=True)
    pip_exe = os.path.join(venv_dir, "bin", "pip")
    ghostmode_exe = os.path.join(venv_dir, "bin", "ghostmode")
    
    # Install from local directory
    res = subprocess.run([pip_exe, "install", "./ghostmode"], capture_output=True, text=True)
    if res.returncode == 0:
        print("Install successful.")
    else:
        print(f"Install failed: {res.stderr}")
        return

    print("\n--- 3. First run ---")
    # Start ghostmode wrapping our mock server
    mock_server_cmd = [os.path.join(venv_dir, "bin", "python"), "mock_mcp_server.py"]
    
    # Use Popen to interact via stdin/stdout
    process = subprocess.Popen(
        [ghostmode_exe, "--", *mock_server_cmd],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Read the startup banner from stderr (ghostmode logs to stderr usually, or stdout if it prints banner there)
    # The banner might be printed immediately. Let's wait a tiny bit.
    time.sleep(1)

    print("\n--- 4. Test reads ---")
    read_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "fs_read",
            "arguments": {"path": "/tmp/test.txt"}
        }
    }
    process.stdin.write(json.dumps(read_req) + "\n")
    process.stdin.flush()
    
    # Read response
    resp_line = process.stdout.readline()
    print(f"Read Response: {resp_line.strip()}")

    print("\n--- 5. Test writes ---")
    write_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "fs_write",
            "arguments": {"path": "/tmp/test.txt", "content": "GHOST MODE DATA"}
        }
    }
    process.stdin.write(json.dumps(write_req) + "\n")
    process.stdin.flush()
    
    resp_line2 = process.stdout.readline()
    print(f"Write Response: {resp_line2.strip()}")

    print("\n--- 6. Shadow VFS consistency ---")
    read_req_2 = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "fs_read",
            "arguments": {"path": "/tmp/test.txt"}
        }
    }
    process.stdin.write(json.dumps(read_req_2) + "\n")
    process.stdin.flush()
    
    resp_line3 = process.stdout.readline()
    print(f"Read-back Response: {resp_line3.strip()}")

    print("\n--- 7. Session summary ---")
    # Send SIGINT to trigger summary
    process.send_signal(subprocess.signal.SIGINT)
    
    # Wait for process to finish and collect stderr (where the summary usually prints)
    stdout, stderr = process.communicate()
    
    print("=== GHOSTMODE STDERR (Summary) ===")
    print(stderr)
    print("==================================")
    
if __name__ == "__main__":
    asyncio.run(main())
