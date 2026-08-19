# AGENTS.md — Pipeline Context for nightcrawler

## Project Overview
Autonomous mobile penetration testing agent running on smartphones with local AI inference and web dashboard.

**Repository**: `garagehq/nightcrawler`
**Language**: python
**Framework**: flask
**Subtype**: python_web
**Docker Image**: `python:3.12-slim` — use this for all testing


## Build & Run
- **Install deps**: `pip install  pytest 2>&1 | tail -3; pip install  flask httpx pyyaml requests 2>&1 | tail -5 || true`


## Testing
- **Has existing tests**: yes
- **Test directory**: `tests/`
- **Test framework**: pytest
- **Test command**: `pytest`
- **Pipeline test runner**: `pytest`
- **Testable components** (partial scope): agent.output_parser, agent.cve_db, agent.structured_log, agent.offline_manager, kali_executor, webui.server, config_loader


## File Structure
**Source files:**
- `main.py`
- `scripts/generate-report.py`
- `webui/server.py`
- `webui/__init__.py`
- `simulation/__init__.py`
- `simulation/runner.py`
- `agent/loop.py`
- `agent/net_detect.py`
- `agent/report_generator.py`
- `agent/structured_log.py`
- `agent/context.py`
- `agent/mission_log.py`
- `agent/llm_client.py`
- `agent/__init__.py`
- `agent/watchdog.py`
- `agent/output_parser.py`
- `agent/cover_traffic.py`
- `agent/host_memory.py`
- `agent/planner.py`
- `agent/attack_planner.py`
**Test files:**
- `simulation/mock_kali_server.py`


## Key Source Code
Snippets from main source files (first 40 lines each):
```

--- main.py ---
#!/usr/bin/env python3
"""Nightcrawler — Mobile Autonomous Pentest Agent entry point."""

import asyncio
import os
import signal
import subprocess
import sys
import yaml


def _kill_existing_agents():
    """Kill any other main.py instances to prevent duplicate agents."""
    my_pid = os.getpid()
    try:
        result = subprocess.run(
            ["pgrep", "-f", "python3 main.py"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.strip().split("\n"):
            pid = int(line.strip()) if line.strip() else 0
            if pid and pid != my_pid:
                os.kill(pid, signal.SIGKILL)
    except Exception:
        pass

from agent.llm_client import LLMClient
from agent.loop import AgentLoop
from agent.planner import Phase
from ui.colors import C
from ui.terminal import TerminalUI


def check_network_connectivity() -> bool:
    """Check if we already have network connectivity."""
    # Method 1: default route
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip():
            return True
    except Exception:
        pass

    # Method 2: check if wlan0 has an IP
    try:
        result = subprocess.run(
            ["ip", "addr", "show", "wlan0"],
            capture_output=True, text=True, timeout=5,
        )
        if "inet " in result.stdout:
            return True
    except Exception:
        pass

    # Method 3: can we reach the LLM? (shared network namespace)
    try:
        import httpx
        r = httpx.get("http://127.0.0.1:8080/health", timeout=3)
        if r.status_code == 200:
            return True
    except Exception:
        pass

    # Method 4: can we ping the gateway?
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "192.168.1.1"],
            capture_output=True, text=True, timeout=5,
        )
    
```


## CI Gotchas
(none yet — will be populated if CI fails)


## Pipeline History
- *2026-08-19* — Scout: python/flask, scope=partial

- *2026-08-19* — Implement: Here'\''s a summary of what was accomplished:

## Summary

### Tests Passed: 75/75 (100%)

### Changes 

## Known Issues
(none yet)


## Notes
- This file is auto-read by Qwen Code as project context (like CLAUDE.md)
- Updated by each pipeline phase with learnings, CI fixes, and gotchas
- DO NOT delete this file — it helps the pipeline avoid repeating mistakes

