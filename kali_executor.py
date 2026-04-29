"""Real command executor — runs actual shell commands on Kali.

Replaces mock_kali_server for live operation. The scope proxy at :8800
has already validated the command before it reaches here.
"""

import argparse
import subprocess
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

MAX_OUTPUT = 8192
CMD_TIMEOUT = 300


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

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT,
        )
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr if output else result.stderr

        # Truncate large output
        if len(output) > MAX_OUTPUT:
            output = output[:MAX_OUTPUT] + f"\n... [truncated at {MAX_OUTPUT} bytes, total {len(output)}]"

        return jsonify({
            "status": "success" if result.returncode == 0 else "error",
            "output": output,
            "return_code": result.returncode,
        })

    except subprocess.TimeoutExpired as e:
        partial = ""
        if e.stdout:
            partial = e.stdout if isinstance(e.stdout, str) else e.stdout.decode("utf-8", errors="replace")
        return jsonify({
            "status": "error",
            "output": partial[:MAX_OUTPUT],
            "error": f"Timeout after {CMD_TIMEOUT}s",
            "return_code": -1,
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "output": "",
            "error": str(e),
            "return_code": -1,
        }), 500


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kali Command Executor")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--max-output", type=int, default=8192)
    args = parser.parse_args()

    CMD_TIMEOUT = args.timeout
    MAX_OUTPUT = args.max_output

    app.run(host="127.0.0.1", port=args.port, debug=False)
