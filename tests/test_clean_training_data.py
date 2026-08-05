"""Regression tests for the training-data cleanup tool filters.

Verifies that the `loud_nmap` filter catches nmap scans without a stealth
timing template (-T0/-T1/-T2) even when the command starts with `sudo`
(which the agent's bare-command recovery emits as `sudo nmap ...`).
The old `cmd.startswith("nmap")` check let `sudo nmap ...` slip through,
polluting the finetune set with non-stealth scanning examples.
"""

import importlib.util
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

spec = importlib.util.spec_from_file_location(
    "clean_training_data",
    os.path.join(PROJECT_ROOT, "tools", "clean_training_data.py"),
)
ctd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ctd)


def _record(command, output="host 10.0.0.5 up with real output data here"):
    return {
        "command": command,
        "command_output": output,
        "system_prompt": "You are a stealth pentest agent.",
        "messages": [],
        "assistant_response": "REASONING: scan\nCOMMAND: %s" % command,
    }


def test_loud_nmap_sudo_is_rejected():
    """sudo nmap without stealth timing must be filtered as loud."""
    d = _record("sudo nmap -sS -p 22 10.0.0.5")
    assert ctd.reject_reason(d, {}) == "loud_nmap"


def test_loud_nmap_plain_is_rejected():
    d = _record("nmap -sS 10.0.0.5")
    assert ctd.reject_reason(d, {}) == "loud_nmap"


def test_stealth_sudo_nmap_is_kept():
    d = _record("sudo nmap -sS -T2 -p 22 10.0.0.5")
    assert ctd.reject_reason(d, {}) is None


def test_stealth_nmap_is_kept():
    d = _record("nmap -sT -T2 --top-ports 100 10.0.0.5")
    assert ctd.reject_reason(d, {}) is None


def test_non_nmap_tool_is_not_flagged_loud():
    d = _record("sudo nxc smb 10.0.0.5 -u admin -p admin")
    assert ctd.reject_reason(d, {}) is None