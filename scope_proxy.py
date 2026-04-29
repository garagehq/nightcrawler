"""
Scope Enforcement Proxy for Nightcrawler.
Sits between the agent and kali-server-mcp, validating every command.
"""

import argparse
import json
import yaml
from flask import Flask, request, jsonify
import requests

from proxy.scope import ScopeValidator
from proxy.command_filter import check_command
from proxy.rate_limiter import RateLimiter
from proxy.logger import AuditLogger

app = Flask(__name__)

# Globals initialized in main()
scope_validator = None
rate_limiter = None
audit_logger = None
upstream_url = None
dry_run = False


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "nightcrawler-scope-proxy"})


@app.route("/execute", methods=["POST"])
def execute():
    """Proxy endpoint — agent sends commands here."""
    data = request.json or {}
    command = data.get("command", "").strip()

    if not command:
        return jsonify({"status": "error", "error": "Empty command"}), 400

    # 1. Check destructive patterns
    allowed, reason = check_command(command)
    if not allowed:
        audit_logger.log_command(command, False, reason)
        return jsonify({
            "status": "blocked", "error": reason, "command": command
        }), 403

    # 2. Check scope (IPs, ports)
    allowed, reason = scope_validator.validate(command)
    if not allowed:
        audit_logger.log_command(command, False, reason)
        return jsonify({
            "status": "blocked", "error": reason, "command": command
        }), 403

    # 3. Rate limit + jitter
    rate_limiter.wait_if_needed(command)

    # 4. Forward to upstream (kali-server-mcp) or dry-run
    if dry_run:
        result = {"status": "success", "output": f"[DRY RUN] Would execute: {command}",
                  "return_code": 0}
        audit_logger.log_command(command, True, "OK (dry-run)", "success")
        return jsonify(result)

    try:
        resp = requests.post(
            f"{upstream_url}/api/command",
            json={"command": command},
            timeout=300
        )
        raw = resp.json()
        # Translate kali-server-mcp response to our format
        output = raw.get("stdout", "")
        if raw.get("stderr"):
            output += ("\n" + raw["stderr"]) if output else raw["stderr"]
        result = {
            "status": "success" if raw.get("success") else "error",
            "output": output,
            "return_code": raw.get("return_code", -1),
        }
        if raw.get("timed_out"):
            result["status"] = "error"
            result["error"] = "Command timed out"

        audit_logger.log_command(command, True, "OK",
                                 result.get("status", "unknown"))
        return jsonify(result)
    except Exception as e:
        audit_logger.log_command(command, True, "OK", "error")
        return jsonify({"status": "error", "error": str(e), "output": ""}), 500


def main():
    global scope_validator, rate_limiter, audit_logger, upstream_url, dry_run

    parser = argparse.ArgumentParser(description="Nightcrawler Scope Proxy")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--upstream", default="http://127.0.0.1:5000")
    parser.add_argument("--port", type=int, default=8800)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    mission = config["mission"]
    stealth = config["stealth"]
    log_dir = config.get("logging", {}).get("dir", "logs")

    # Auto-detect network scope from wlan0 if config says "auto"
    scope_networks = mission["scope"]["networks"]
    excluded_hosts = mission["scope"].get("excluded_hosts", [])
    if scope_networks == ["auto"] or "auto" in scope_networks:
        import subprocess, re
        try:
            result = subprocess.run(["ip", "-4", "addr", "show", "wlan0"],
                                    capture_output=True, text=True, timeout=5)
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)
            if match:
                our_ip = match.group(1)
                prefix_len = match.group(2)
                octets = our_ip.split(".")
                scope_networks = [f"{octets[0]}.{octets[1]}.{octets[2]}.0/{prefix_len}"]
                print(f"[SCOPE] Auto-detected network: {scope_networks[0]} (our IP: {our_ip})")
            else:
                scope_networks = ["192.168.0.0/24"]
                our_ip = "unknown"
        except Exception:
            scope_networks = ["192.168.0.0/24"]
            our_ip = "unknown"
    else:
        our_ip = None

    if excluded_hosts == ["auto"] or "auto" in excluded_hosts:
        import subprocess
        excluded_hosts = []
        try:
            # Auto-exclude gateway (.1) and self
            octets = scope_networks[0].split("/")[0].rsplit(".", 1)[0]
            excluded_hosts.append(f"{octets}.1")  # gateway
            if our_ip and our_ip != "unknown":
                excluded_hosts.append(our_ip)  # self
            else:
                result = subprocess.run(["ip", "-4", "addr", "show", "wlan0"],
                                        capture_output=True, text=True, timeout=5)
                import re
                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    excluded_hosts.append(match.group(1))
            print(f"[SCOPE] Auto-excluded hosts: {excluded_hosts}")
        except Exception:
            pass

    scope_validator = ScopeValidator(
        networks=scope_networks,
        excluded_hosts=excluded_hosts,
        excluded_ports=mission["scope"].get("excluded_ports", []),
    )
    rate_limiter = RateLimiter(
        scan_rate_per_min=stealth["scan_rate_per_min"],
        cred_rate_per_min=stealth["cred_spray_rate_per_min"],
        jitter_range_ms=stealth["jitter_range_ms"],
    )
    audit_logger = AuditLogger(log_dir)
    upstream_url = args.upstream
    dry_run = args.dry_run or config.get("dry_run", {}).get("enabled", False)

    audit_logger.log_event("proxy_start", {
        "upstream": upstream_url,
        "port": args.port,
        "dry_run": dry_run,
        "scope_networks": mission["scope"]["networks"],
    })

    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
