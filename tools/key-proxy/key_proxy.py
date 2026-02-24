#!/usr/bin/env python3
"""UNWIND Key Proxy — keeps API keys off the Pi.

Runs on your Mac. The Pi's SENTINEL (OpenClaw/Codex) sends requests
here instead of directly to OpenAI. This proxy:

1. Holds the real OpenAI API key (never leaves your Mac)
2. Validates requests from the Pi using a shared proxy token
3. Forwards to OpenAI and returns the response
4. Logs every request (tool name, model, token count, timestamp)
5. Rate-limits to prevent runaway costs

This is the "Steinberger Sentinel Pattern" applied to our own setup —
the same principle as UNWIND's sidecar, dogfooded on our own infra.

Usage (on your Mac):
    export OPENAI_API_KEY="sk-..."
    export PROXY_TOKEN="some-shared-secret"
    python3 key_proxy.py

Then on the Pi, set SENTINEL's base URL to:
    http://<your-mac-ip>:9200/v1

And set the API key to the PROXY_TOKEN value (not the real OpenAI key).
"""

import hashlib
import hmac
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from flask import Flask, request, Response, jsonify
except ImportError:
    print("Flask not installed. Run: pip3 install flask requests")
    sys.exit(1)

try:
    import requests as http_requests
except ImportError:
    print("requests not installed. Run: pip3 install flask requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
PROXY_TOKEN = os.environ.get("PROXY_TOKEN", "")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com")
LISTEN_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")  # Needs to be reachable from Pi
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "9200"))
LOG_DIR = Path(os.environ.get("PROXY_LOG_DIR", "~/.unwind/proxy-logs")).expanduser()

# Rate limiting
MAX_REQUESTS_PER_MINUTE = int(os.environ.get("PROXY_RATE_LIMIT", "30"))
MAX_REQUESTS_PER_HOUR = int(os.environ.get("PROXY_HOURLY_LIMIT", "500"))

# Allowed source IPs (Pi's IP + localhost)
ALLOWED_IPS = set(
    os.environ.get("PROXY_ALLOWED_IPS", "192.168.0.171,127.0.0.1,::1").split(",")
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [key-proxy] %(levelname)s %(message)s",
)
logger = logging.getLogger("key-proxy")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Rate limiting state
_request_timestamps: list[float] = []
_audit_log: list[dict] = []


def _check_rate_limit() -> str | None:
    """Check rate limits. Returns error message if exceeded, None if OK."""
    now = time.time()

    # Clean old timestamps
    cutoff_minute = now - 60
    cutoff_hour = now - 3600
    _request_timestamps[:] = [t for t in _request_timestamps if t > cutoff_hour]

    # Per-minute check
    recent_minute = sum(1 for t in _request_timestamps if t > cutoff_minute)
    if recent_minute >= MAX_REQUESTS_PER_MINUTE:
        return f"Rate limit: {MAX_REQUESTS_PER_MINUTE}/min exceeded ({recent_minute} in last 60s)"

    # Per-hour check
    if len(_request_timestamps) >= MAX_REQUESTS_PER_HOUR:
        return f"Rate limit: {MAX_REQUESTS_PER_HOUR}/hr exceeded ({len(_request_timestamps)} in last hour)"

    _request_timestamps.append(now)
    return None


def _log_request(method: str, path: str, status: int, details: dict):
    """Log a proxied request to file and memory."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "path": path,
        "status": status,
        **details,
    }
    _audit_log.append(entry)
    logger.info(
        "%s %s → %d | %s",
        method, path, status,
        json.dumps({k: v for k, v in details.items() if k != "response_body"}),
    )

    # Write to daily log file
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = LOG_DIR / f"proxy-{today}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as exc:
        logger.warning("Failed to write log file: %s", exc)


def _check_auth() -> str | None:
    """Validate proxy token. Returns error message if invalid."""
    if not PROXY_TOKEN:
        return None  # No token configured = dev mode (not recommended)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return "Missing or malformed Authorization header"

    provided = auth_header[7:]
    if not hmac.compare_digest(provided, PROXY_TOKEN):
        return "Invalid proxy token"

    return None


def _check_source_ip() -> str | None:
    """Validate source IP is in allowlist."""
    client_ip = request.remote_addr or ""
    if client_ip not in ALLOWED_IPS:
        return f"Source IP {client_ip} not in allowlist"
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/v1/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy_openai(subpath):
    """Forward requests to OpenAI API with real key substitution."""

    # --- Source IP check ---
    ip_error = _check_source_ip()
    if ip_error:
        _log_request(request.method, f"/v1/{subpath}", 403, {"error": ip_error})
        return jsonify({"error": ip_error}), 403

    # --- Auth check ---
    auth_error = _check_auth()
    if auth_error:
        _log_request(request.method, f"/v1/{subpath}", 401, {"error": auth_error})
        return jsonify({"error": auth_error}), 401

    # --- Rate limit check ---
    rate_error = _check_rate_limit()
    if rate_error:
        _log_request(request.method, f"/v1/{subpath}", 429, {"error": rate_error})
        return jsonify({"error": rate_error}), 429

    # --- Check we have a real key ---
    if not OPENAI_API_KEY:
        _log_request(request.method, f"/v1/{subpath}", 500, {"error": "No OPENAI_API_KEY configured"})
        return jsonify({"error": "Proxy misconfigured: no upstream API key"}), 500

    # --- Extract request details for logging ---
    log_details: dict = {"source_ip": request.remote_addr}
    try:
        if request.is_json:
            body = request.get_json(silent=True) or {}
            log_details["model"] = body.get("model", "")
            log_details["stream"] = body.get("stream", False)
        else:
            body = None
    except Exception:
        body = None

    # --- Forward to OpenAI ---
    target_url = f"{OPENAI_BASE_URL}/v1/{subpath}"

    # Build headers — swap proxy token for real API key
    forward_headers = {}
    for key, value in request.headers:
        key_lower = key.lower()
        if key_lower in ("host", "content-length", "transfer-encoding"):
            continue
        if key_lower == "authorization":
            # Swap: Pi's proxy token → real OpenAI key
            forward_headers["Authorization"] = f"Bearer {OPENAI_API_KEY}"
        else:
            forward_headers[key] = value

    if "Authorization" not in forward_headers:
        forward_headers["Authorization"] = f"Bearer {OPENAI_API_KEY}"

    try:
        upstream_resp = http_requests.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            data=request.get_data(),
            stream=log_details.get("stream", False),
            timeout=120,
        )
    except http_requests.RequestException as exc:
        _log_request(request.method, f"/v1/{subpath}", 502, {
            **log_details, "error": str(exc),
        })
        return jsonify({"error": f"Upstream error: {exc}"}), 502

    # --- Stream handling ---
    if log_details.get("stream"):
        def stream_response():
            for chunk in upstream_resp.iter_content(chunk_size=None):
                yield chunk

        _log_request(request.method, f"/v1/{subpath}", upstream_resp.status_code, {
            **log_details, "streamed": True,
        })
        return Response(
            stream_response(),
            status=upstream_resp.status_code,
            headers=dict(upstream_resp.headers),
            content_type=upstream_resp.headers.get("content-type"),
        )

    # --- Non-stream response ---
    _log_request(request.method, f"/v1/{subpath}", upstream_resp.status_code, log_details)

    # Return response with original headers
    response_headers = {}
    for key, value in upstream_resp.headers.items():
        if key.lower() not in ("content-encoding", "transfer-encoding", "content-length"):
            response_headers[key] = value

    return Response(
        upstream_resp.content,
        status=upstream_resp.status_code,
        headers=response_headers,
        content_type=upstream_resp.headers.get("content-type"),
    )


@app.route("/proxy/status", methods=["GET"])
def proxy_status():
    """Proxy health and stats — Mac-side only."""
    ip_error = _check_source_ip()
    if ip_error:
        return jsonify({"error": ip_error}), 403

    now = time.time()
    recent_minute = sum(1 for t in _request_timestamps if t > now - 60)
    recent_hour = sum(1 for t in _request_timestamps if t > now - 3600)

    return jsonify({
        "status": "up",
        "requests_last_minute": recent_minute,
        "requests_last_hour": recent_hour,
        "rate_limit_per_minute": MAX_REQUESTS_PER_MINUTE,
        "rate_limit_per_hour": MAX_REQUESTS_PER_HOUR,
        "allowed_ips": sorted(ALLOWED_IPS),
        "upstream": OPENAI_BASE_URL,
        "key_configured": bool(OPENAI_API_KEY),
        "auth_required": bool(PROXY_TOKEN),
        "total_logged": len(_audit_log),
    })


@app.route("/proxy/log", methods=["GET"])
def proxy_log():
    """Return recent audit log entries — Mac-side only."""
    ip_error = _check_source_ip()
    if ip_error:
        return jsonify({"error": ip_error}), 403

    limit = request.args.get("limit", 50, type=int)
    return jsonify({"entries": _audit_log[-limit:]})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not OPENAI_API_KEY:
        logger.error("OPENAI_API_KEY not set. Export it before running.")
        logger.error("  export OPENAI_API_KEY='sk-...'")
        sys.exit(1)

    if not PROXY_TOKEN:
        logger.warning(
            "PROXY_TOKEN not set — proxy will accept unauthenticated requests. "
            "This is fine for local testing but NOT for production."
        )

    logger.info("Starting UNWIND Key Proxy on %s:%d", LISTEN_HOST, LISTEN_PORT)
    logger.info("Upstream: %s", OPENAI_BASE_URL)
    logger.info("Allowed IPs: %s", sorted(ALLOWED_IPS))
    logger.info("Rate limits: %d/min, %d/hr", MAX_REQUESTS_PER_MINUTE, MAX_REQUESTS_PER_HOUR)
    logger.info("Logs: %s", LOG_DIR)

    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
