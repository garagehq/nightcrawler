#!/usr/bin/env python3
"""Unit tests for command extraction in agent/loop.py.

Fast + deterministic (no model). Covers the bare-command recovery fallback
added for the LFM2.5-1.2B model, which reliably emits valid commands but
frequently drops the "COMMAND:" wrapper.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.loop import AgentLoop  # noqa: E402

pc = AgentLoop._parse_command
pr = AgentLoop._parse_reasoning

CASES_CMD = [
    # (model_output, expected_command)
    # Well-formed (regression: must still work)
    ("REASONING: scan host.\nCOMMAND: nmap -sV -T2 192.168.1.80",
     "nmap -sV -T2 192.168.1.80"),
    # Markdown-wrapped COMMAND (regression)
    ("REASONING: probe.\nCOMMAND: `curl -s -I http://192.168.1.63/`",
     "curl -s -I http://192.168.1.63/"),
    # Bare command, no wrapper — the dominant real failure mode
    ("nmap -sS -T2 --top-ports 100 192.168.1.80",
     "nmap -sS -T2 --top-ports 100 192.168.1.80"),
    # Bare command with a stray leading blank / prompt char
    ("$ smbclient -N -L //192.168.1.42/",
     "smbclient -N -L //192.168.1.42/"),
    # Bare command preceded by a non-command chatter line
    ("Okay, let me look.\ncurl -s -I http://192.168.1.90/",
     "curl -s -I http://192.168.1.90/"),
    # impacket dashed tool name
    ("impacket-samrdump 192.168.1.42", "impacket-samrdump 192.168.1.42"),
]

CASES_NONE = [
    "",                       # empty
    "hmm not sure what to do next",   # pure chatter, no tool
    "REASONING: SSH open, SMB open, thinking...",  # reasoning only, no command
]


def run():
    failures = []
    for out, expected in CASES_CMD:
        got = pc(out)
        if got != expected:
            failures.append(f"parse_command({out!r}) = {got!r}, want {expected!r}")
    for out in CASES_NONE:
        got = pc(out)
        if got is not None:
            failures.append(f"parse_command({out!r}) = {got!r}, want None")

    # A bare command must NOT also be surfaced as reasoning
    r = pr("nmap -sS -T2 --top-ports 100 192.168.1.80")
    if r is not None:
        failures.append(f"parse_reasoning(bare cmd) = {r!r}, want None")
    # Real reasoning is still extracted
    r2 = pr("REASONING: scan the host\nCOMMAND: nmap -sV -T2 192.168.1.5")
    if r2 != "scan the host":
        failures.append(f"parse_reasoning(good) = {r2!r}, want 'scan the host'")

    if failures:
        print(f"FAIL ({len(failures)}):")
        for f in failures:
            print("  x", f)
        return 1
    print(f"PASS: {len(CASES_CMD) + len(CASES_NONE) + 2} command-parsing cases")
    return 0


if __name__ == "__main__":
    sys.exit(run())
