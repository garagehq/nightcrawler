"""Real command executor — runs actual shell commands via subprocess.

Replaces mock_kali_server for live operation. The scope proxy at :8800 has
already validated the command before it reaches here. Pure subprocess, no Kali
chroot required — so this is also the executor used by the non-rooted Termux
"lite" build (just install the CLI tools via `pkg`).

Serves two wire contracts against the same executor:
  * POST /execute      -> {status, output, return_code}          (legacy)
  * POST /api/command  -> {stdout, stderr, return_code, success, timed_out}
    This mirrors the `mcp-kali-server` package, so `scope_proxy.py` (which
    forwards to /api/command and translates that shape) works unchanged and the
    Kali chroot MCP server can be swapped out for this file.
"""

import argparse
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

MAX_OUTPUT = 8192
CMD_TIMEOUT = 300


def _run_command(command):
    """Run a shell command. Returns (stdout, stderr, return_code, timed_out).

    stdout is truncated to MAX_OUTPUT; a raised exception is surfaced as stderr
    with return_code -1 so callers never see an unhandled error.
    """
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=CMD_TIMEOUT,
        )
        stdout = result.stdout or ""
        if len(stdout) > MAX_OUTPUT:
            stdout = (stdout[:MAX_OUTPUT] +
                      f"\n... [truncated at {MAX_OUTPUT} bytes, total {len(stdout)}]")
        return stdout, (result.stderr or ""), result.returncode, False
    except subprocess.TimeoutExpired as e:
        partial = e.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        return partial[:MAX_OUTPUT], f"Timeout after {CMD_TIMEOUT}s", -1, True
    except Exception as e:  # noqa: BLE001 — surface any exec error to the caller
        return "", str(e), -1, False


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "kali-executor"})


@app.route("/execute", methods=["POST"])
def execute():
    data = request.json or {}
    command = data.get("command", "").strip()

    if not command:
        return jsonify({"status": "error", "error": "Empty command",
                        "output": "", "return_code": -1}), 400

    stdout, stderr, return_code, timed_out = _run_command(command)
    output = stdout
    if stderr:
        output += ("\n" + stderr) if output else stderr
    result = {
        "status": "success" if return_code == 0 else "error",
        "output": output,
        "return_code": return_code,
    }
    if timed_out:
        result["error"] = f"Timeout after {CMD_TIMEOUT}s"
    return jsonify(result)


@app.route("/api/command", methods=["POST"])
def api_command():
    """mcp-kali-server-compatible endpoint (what scope_proxy.py forwards to)."""
    data = request.json or {}
    command = data.get("command", "").strip()

    if not command:
        return jsonify({"stdout": "", "stderr": "Empty command",
                        "return_code": -1, "success": False,
                        "timed_out": False}), 400

    stdout, stderr, return_code, timed_out = _run_command(command)
    return jsonify({
        "stdout": stdout,
        "stderr": stderr,
        "return_code": return_code,
        "success": (return_code == 0) and not timed_out,
        "timed_out": timed_out,
    })


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kali Command Executor")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--max-output", type=int, default=8192)
    args = parser.parse_args()

    CMD_TIMEOUT = args.timeout
    MAX_OUTPUT = args.max_output

    app.run(host="127.0.0.1", port=args.port, debug=False)
