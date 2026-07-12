#!/usr/bin/env python3
"""Prompt format-compliance eval for the local reasoning model.

Rebuilds the system prompt exactly as agent/loop.py does (system.md +
phase context, placeholders filled) and asks the live llama-server for the
next command across recon/enumerate/exploit scenarios. Scores each sample for:

  1. format     — contains REASONING: and COMMAND:
  2. no_placeholder — no literal <ip>/<port>/<target>/bare IP token in COMMAND
  3. real_ip     — COMMAND contains a real dotted-quad IP
  4. in_scope    — that IP is inside the test scope (192.168.1.0/24)

A sample is "good" only if all four hold. Prints per-phase and overall rates
and exits non-zero if overall compliance is below THRESHOLD.

The 1.2B model follows examples, not instructions (see CLAUDE.md), so this is
an integration test against the running model, not a unit test.

Usage: python3 tests/test_prompt_compliance.py [samples_per_scenario] [threshold]
"""
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from agent.loop import AgentLoop
    _parse_command = AgentLoop._parse_command
except Exception:  # pragma: no cover - agent deps unavailable
    _parse_command = None

LLM_URL = os.environ.get("NC_LLM_URL", "http://127.0.0.1:8080/v1/chat/completions")
PROMPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts")
SCOPE = "192.168.1.0/24"
EXCLUDED = "192.168.1.1"

PLACEHOLDER_RE = re.compile(r"<\s*(ip|port|ports|target|bssid|ch|client_mac|essid|password)\s*>", re.I)
# bare uppercase template tokens the exploit prompt historically used
BARE_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9/])(IP|IP_OF_INTEREST|DISCOVERED_HOST|CLIENT_MAC)(?![A-Za-z0-9])")
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def load(name):
    with open(os.path.join(PROMPTS, name)) as f:
        return f.read()


def build_system(phase_file):
    """Mirror agent/loop.py _load_system_prompt().format(...)."""
    return load("system.md").format(
        scope_networks=SCOPE,
        excluded_hosts=EXCLUDED,
        phase_context=load(phase_file),
    )


SCENARIOS = [
    ("recon", "phase1_recon.md",
     "Live hosts: 192.168.1.22, 192.168.1.80, 192.168.1.100. "
     "Suggested target: 192.168.1.80 (no ports known yet). Produce the next command."),
    ("enumerate", "phase2_enumerate.md",
     "HOST MEMORY 192.168.1.80: open ports 22, 80. "
     "Suggested target: 192.168.1.80. Produce the next command."),
    ("enumerate-smb", "phase2_enumerate.md",
     "HOST MEMORY 192.168.1.42: open ports 139, 445. "
     "Suggested target: 192.168.1.42. Produce the next command."),
    ("exploit", "phase3_exploit.md",
     "HOST MEMORY 192.168.1.42: SMB shares accessible: backup. "
     "Suggested target: 192.168.1.42. Produce the next command."),
    ("exploit-ssh", "phase3_exploit.md",
     "HOST MEMORY 192.168.1.100: open port 22, OpenSSH 8.4. "
     "Suggested target: 192.168.1.100. Produce the next command."),
]


def call(system, user):
    payload = json.dumps({
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
        "max_tokens": 200,
    }).encode()
    req = urllib.request.Request(LLM_URL, data=payload,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)["choices"][0]["message"]["content"]


def grade(text):
    """Grade what the AGENT actually extracts end-to-end.

    Uses the real _parse_command (which recovers bare commands the model emits
    without the COMMAND: wrapper) when available, else falls back to a local
    regex. A sample is good if a command is extracted with a real in-scope IP
    and no leftover placeholder token.
    """
    up = text.upper()
    fmt = "REASONING:" in up and "COMMAND:" in up
    if _parse_command is not None:
        cmd = _parse_command(text) or ""
    else:
        m = re.search(r"COMMAND:\s*(.+)", text, re.I | re.S)
        cmd = m.group(1).splitlines()[0].strip() if m else ""
    extracted = bool(cmd)
    placeholder = bool(PLACEHOLDER_RE.search(cmd) or BARE_TOKEN_RE.search(cmd))
    ips = IP_RE.findall(cmd)
    real_ip = len(ips) > 0
    in_scope = any(ip.startswith("192.168.1.") for ip in ips)
    good = extracted and not placeholder and real_ip and in_scope
    return {"good": good, "fmt": fmt, "extracted": extracted,
            "placeholder": placeholder, "real_ip": real_ip,
            "in_scope": in_scope, "cmd": cmd}


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 0.80
    total_good = total = 0
    print(f"Prompt compliance eval: {n} samples/scenario, threshold {threshold:.0%}\n")
    for label, phase_file, user in SCENARIOS:
        system = build_system(phase_file)
        good = 0
        fails = []
        for _ in range(n):
            try:
                out = call(system, user)
            except Exception as e:
                fails.append(f"<ERR {e}>")
                continue
            g = grade(out)
            good += g["good"]
            if not g["good"]:
                why = [k for k in ("extracted", "real_ip", "in_scope")
                       if not g[k]]
                if g["placeholder"]:
                    why.append("placeholder")
                shown = g["cmd"] if g["cmd"] else out.replace(chr(10), " ")
                fails.append(f"[{','.join(why)}] {shown[:70]}")
        total_good += good
        total += n
        status = "PASS" if good / n >= threshold else "FAIL"
        print(f"  {label:16s} {good}/{n}  {status}")
        for f in fails[:3]:
            print(f"      x {f}")
    rate = total_good / total if total else 0
    print(f"\nOVERALL: {total_good}/{total} = {rate:.0%}  "
          f"({'PASS' if rate >= threshold else 'FAIL'})")
    return 0 if rate >= threshold else 1


if __name__ == "__main__":
    sys.exit(main())
