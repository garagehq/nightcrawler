<<<<<<< Updated upstream
=======
# Pipeline Context (AGENTS.md)

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

- *2026-08-19* — Implement: Here'\''\'\'''\''s a summary of what was accomplished:

## Summary

### Tests Passed: 75/75 (100%)

### Changes 

## Known Issues
(none yet)


## Notes
- This file is auto-read by Qwen Code as project context (like CLAUDE.md)
- Updated by each pipeline phase with learnings, CI fixes, and gotchas
- DO NOT delete this file — it helps the pipeline avoid repeating mistakes


---

# Pipeline Context (AGENTS.md)

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

## Known Issues
(none yet)

## Notes
- This file is auto-read by Qwen Code as project context (like CLAUDE.md)
- Updated by each pipeline phase with learnings, CI fixes, and gotchas
- DO NOT delete this file — it helps the pipeline avoid repeating mistakes


---

>>>>>>> Stashed changes
# Nightcrawler - Mobile Autonomous Pentest Agent

## Project
Nightcrawler is an autonomous penetration testing agent running on a OnePlus 8 with Kali NetHunter. It uses a local LFM2.5-1.2B-Instruct-Heretic model as its reasoning engine and a real command executor as its tool interface, with a scope enforcement proxy as the safety layer.

- GitHub: github.com/garagehq/nightcrawler
- Install: `/opt/nightcrawler/` (production), `/root/nightcrawler/` (dev)
- Architecture doc: `docs/ARCHITECTURE.md`
- Feature reference: `docs/FEATURES.md`
- Thor deferred features: `docs/THOR_DEFERRED.md`

## CRITICAL: llama-server Rules
- **NEVER start a second llama-server process** — always `pgrep llama-server` first
- **Context window: 8192 tokens** — do not increase without explicit user approval
- Dual/triple llama-server caused OOM (observed 2026-03-20 and 2026-03-21 with the older 3GB Qwen model; LFM2.5-1.2B is ~1.3GB but the never-run-two rule still applies)
- Auto-starts 5 min after boot via Magisk watchdog (30s health check, 20 min crash cooldown)
- **Watchdog uses PID file** (`/data/local/tmp/var/run/llama-server.pid`) + process count verification — fixed 2026-03-21
- Every ~2h (random 1.75-2.5h): scheduled restart (SIGKILL, process count verify)
- **Kali can now SSH to Android**: `ssh -p 9022 shell@127.0.0.1 "command"`
- Start from Kali: `ssh -p 9022 shell@127.0.0.1 "bash /data/local/nhsystem/kalifs/root/nightcrawler/scripts/start-llm.sh"`
- Kill from Kali: `ssh -p 9022 shell@127.0.0.1 "pkill -9 -f llama-server"`
- Health check: `curl -s http://127.0.0.1:8080/health`
- Watchdog logs: `/data/local/tmp/var/log/llama-watchdog.log`
- Emergency reboot from Kali: `echo b > /proc/sysrq-trigger`

## Device Info
- Phone: OnePlus 8 (kebab), Snapdragon 865, Adreno 650 GPU
- Kernel: 4.19.297-perf-g8228d522e928-dirty (custom-built from Nameless AOSP `thirteen` branch, MAC80211+WireGuard+nftables)
- Kernel source: https://github.com/garagehq/kernel_oneplus_sm8250_nethunter
- RAM: 12GB (shared between CPU and GPU)
- GPU Driver: Qualcomm v819.2, Compiler E031.50.02.00 (Magisk module)
- Chroot: Kali Linux at /data/local/nhsystem/kalifs
- Termux: installed (used for OpenCL GPU builds)

## Two Worlds: Kali Chroot vs Android
The phone has two separate execution environments sharing the same kernel + network:

| | Kali Chroot | Android |
|---|---|---|
| libc | glibc | bionic |
| Home | `/root/` | `/data/data/com.termux/files/home/` |
| SSH port | 22 | 9022 |
| Project path | `/root/nightcrawler/` | `/data/local/nhsystem/kalifs/root/nightcrawler/` |
| GPU binaries | **CANNOT run** (bionic-linked) | llama-server, OpenCL |

**Key rules:**
<<<<<<< Updated upstream
- Binaries from one world can't run in the other (glibc vs bionic)
=======
- Binaries from one world can'\''\'\'''\''t run in the other (glibc vs bionic)
>>>>>>> Stashed changes
- **Only way to execute Android-side from Kali**: `ssh -p 9022 shell@127.0.0.1 "command"`
- `nsenter` does NOT work — SSH is the only bridge
- `/vendor` must be mounted in chroot for OpenCL libs (`ls /vendor/lib64/libOpenCL.so`)
- `/data` is shared — Kali can see Termux files at `/data/data/com.termux/files/home/`
- Port 9022 dies first under OOM (Android sshd is heavier). Port 22 (Kali) usually survives
<<<<<<< Updated upstream
- If 9022 is down but 22 is up: can kill processes from Kali but can't start Android-side processes
=======
- If 9022 is down but 22 is up: can kill processes from Kali but can'\''\'\'''\''t start Android-side processes
>>>>>>> Stashed changes
- Emergency reboot when Android SSH is dead: `echo b > /proc/sysrq-trigger`
- RAM budget: llama-server ~3.2GB + Android ~3-4GB = ~7GB used, leaving ~4-5GB for agent + tools

## SSH Access
```bash
ssh -p 9022 shell@127.0.0.1      # Android shell (from Kali chroot)
ssh -p 9022 shell@<tailscale-ip> # Android shell (from Tailscale)
ssh -p 8022 root@<tailscale-ip>  # Kali root shell (was port 22)
```

## Service Ports
| Port | Service | Description |
|------|---------|-------------|
| 8022 | SSH     | Kali root shell (was 22, hardened) |
| 9022 | SSH     | Android shell (Magisk) |
| 5000 | kali-server-mcp | Official Kali MCP server (shlex, no shell=True) |
| 8080 | llama-server | LFM2.5-1.2B-Instruct-Heretic Q8_0 (Heretic-abliterated) via llama.cpp (ctx=8192) |
| 8800 | scope-proxy | Scope enforcement + rate limit + audit |
| 8888 | web UI | Dashboard (Tailscale IP only, HTTPS) |

**Security**: llama-server, kali-mcp, scope-proxy bound to 127.0.0.1 only.
SSH (both Android 9022 and Kali 8022) bound to 127.0.0.1 + Tailscale IP only — invisible on target network.
Android SSH: pubkey-only (password auth disabled).
WebUI on 0.0.0.0 but stealth-filtered (rejects target network, spoofs nginx).

## Nightcrawler Stack
```
Agent (main.py) → LLM (llama.cpp :8080) → REASONING + COMMAND
    ↓
Scope Proxy (:8800) → validates IPs, ports, destructive cmds → /api/command
    ↓
kali-server-mcp (:5000) → shlex.split + subprocess (official Kali package)
    ↓
Kali Linux tools (nmap, curl, smbclient, nxc, gobuster, dig, ...)
```

## Running
```bash
# Start all services manually (after llama-server is healthy)
kali-server-mcp --port 5000 &
python3 scope_proxy.py --config config.yaml --port 8800 --upstream http://127.0.0.1:5000 &
bash scripts/webui-daemon.sh start
python3 main.py &

# Or use the 36h tmux launcher
bash scripts/run-36h.sh

# Dry-run (mock kali server, no real commands)
NC_DRY_RUN=1 python3 main.py
```

**Note**: `main.py` auto-starts the webui daemon if not running. The agent and
webui are separate processes — the agent writes state to SQLite via
`agent/ui_bridge.py`, the webui reads it. This prevents the webui from blocking
during long LLM/nmap calls.

## GPU Inference (OpenCL)
llama.cpp compiled in Termux with Adreno-optimized OpenCL kernels. Runs as root on Android side (not in chroot). From Kali chroot, agent reaches it at http://127.0.0.1:8080 (shared network namespace).

### Key constraints
- **GPU power governor override** — Android throttles GPU ~6x on battery (587→305MHz GPU clock). Fixed with `scripts/gpu-governor.sh` — forces `performance` governor via sysfs, auto-reverts to `msm-adreno-tz` at ≤15% battery. Runs as part of Magisk watchdog block. Logs: `/data/local/tmp/var/log/gpu-governor.log`
- **Context: 8192 tokens** — do not change without user approval
- First run after reboot: ~3 min kernel JIT (cached after)
- Q8_0 is fastest on GPU. Never use Q4_K_M on GPU (10x slower)
- 4B Q8_0 fails: exceeds 1GB per-allocation limit. Use Q4_0 for 4B.

## Performance
Production model is **LFM2.5-1.2B-Instruct-Heretic** (top row). The Qwen rows
are legacy alternatives kept for reference.

| Model | Quant | Backend | Prompt | Generation |
|-------|-------|---------|--------|------------|
| **LFM2.5-1.2B-Instruct-Heretic** | Q8_0 | **OpenCL GPU** | **115 t/s** | **13 t/s** |
| Qwen3.5-0.8B | Q8_0 | OpenCL GPU | 30.5 t/s | 6.3 t/s |
| Qwen3.5-4B | Q4_0 | OpenCL GPU | 10.1 t/s | 2.0 t/s |

## Data Storage
- **SQLite DB**: `logs/nightcrawler.db` — primary store (WAL mode, MAC-keyed hosts, multi-network)
- **Host memories**: `host_memories` in SQLite state — auto-generated observations + analyst edits
- **JSON compat**: `logs/findings.json`, `logs/timeline.jsonl`, `logs/commands.jsonl`
- **Prompts**: `prompts/*.md` — hot-reloadable, edit to tune model behavior
- **Export for Thor**: `GET /api/export/<network>` — full JSON dump per network (includes memories)
- **Memory export**: `GET /api/hosts/memories/export` — all host observations for Thor

## kali-server-mcp vs kali_executor.py
Switched from custom `kali_executor.py` to the official `kali-server-mcp` package:
- **API**: `POST /api/command` (not `/execute`) — proxy translates the response format
- **Execution**: Uses `shlex.split` (not `shell=True`) — eliminates `/bin/sh` backtick errors
- **Response**: Returns `{stdout, stderr, return_code, success, timed_out}`
- **Proxy translation**: Maps to `{status, output, return_code}` for the agent
- `kali_executor.py` still exists as a fallback but is not used in production

## Memory System (Host + Network)
The agent auto-generates observations and injects them into the system prompt.
Context resets after each command — memories provide persistent knowledge.

### Host Memory (per-host)
- **Auto-extracted**: HTTP servers, SSH versions, SMB shares, filtered ports
- **Status**: unknown → interesting → compromised (or dead-end)
- **Tags**: auto-generated (pi-hole, ssh, smb, dns)
- **Injected**: HOST MEMORY section in system prompt (max 200 tokens)
- **Editable**: Click host → MEMORY section → add observations, set status
- **API**: `GET/PATCH /api/hosts/<mac>/memory`, `GET /api/hosts/memories/export`

### Network Memory (per-network)
- **Scanned IPs**: tracks which IPs have been probed (prevents re-scanning)
- **Observations**: auto + analyst (e.g., "Network has Pi-hole at .2")
- **Injected**: NETWORK CONTEXT section in system prompt (max 100 tokens)
- **Editable**: Click network ✎ → OBSERVATIONS section + add input
- **API**: `GET /api/networks/<id>/memory`, `PATCH /api/networks/<id>`

### Context Reset Strategy
Context is cleared after each successful command. The system prompt is rebuilt
fresh each turn with: phase prompt + host memory + network memory + C2 controls.
This prevents context pollution while maintaining persistent knowledge.

After each command, a random live host is suggested for the next turn:
- 70% chance: host with known open ports (productive)
- 30% chance: any random host (discovery)
- Excludes: dead-end hosts, last 3 probed IPs, excluded hosts

**Exception: Multi-turn mode** — high-priority hosts with confirmed access
get 2-3 consecutive commands without context reset. Playbook steps are fed
as specific next-step commands. Context is preserved between turns.

## Auto-Blacklist Self
On startup, the agent auto-blacklists all `excluded_hosts` from config.yaml
(gateway + self IP) with a `self-` MAC prefix. These show on the web UI as
blacklisted and are included in Thor exports. This prevents the agent from
scanning its own kali-mcp-server or the gateway — critical when Thor is in
<<<<<<< Updated upstream
the pipeline so it doesn't red-team itself.
=======
the pipeline so it doesn'\''\'\'''\''t red-team itself.
>>>>>>> Stashed changes

## C2 Interactive Features (Web UI)
The web UI at `:8888` has full C2 controls:
- **⭐ Star hosts**: Prioritize scanning for N iterations (PRIORITY TARGET in prompt)
- **⛔ Blacklist hosts**: Skip entirely (BLACKLIST in prompt, strikethrough in UI)
- **✎ Network edit**: Custom names and notes per network
- **Host notes → LLM**: Analyst notes injected as ANALYST NOTES in system prompt
- **Pause/Resume**: Toggle agent operation
- **Force phase**: RECON/ENUMERATE/EXPLOIT buttons
- **Command injection**: Manual command text input
- **Tool preferences**: Enable/disable specific tools
- **Kill switch**: Emergency stop
- **Config panel**: Live temperature/max_tokens editing
- **Command search**: Search history by keyword

## Red Team Strategy (Patient Rotation)
The agent operates like a stealthy adversary with infinite time:
- **Rotate hosts** — never hit the same host twice in a row
- **One small action per turn** — single curl, single dig, single port check
- **Build knowledge slowly** — host memory accumulates across many visits over hours
- **Spread activity** — no single host sees a burst of traffic
- **Exploitation only when ready** — after many low-profile touches build context naturally
- This is NOT "recon all → enumerate all → exploit all" (too rigid)
- This is NOT "find host → enumerate everything → exploit immediately" (too loud)
- The phase system (RECON/ENUMERATE/EXPLOIT) tracks overall mission progress,
  but the agent acts per-host based on accumulated knowledge

### Random Host Selection (weighted)
After each command, the agent suggests a random next target:
- **70% chance**: host with known open ports (productive)
- **30% chance**: any random host (discovery)
- **Excludes**: dead-end hosts (from memory), last 3 probed IPs, excluded hosts
- Prevents sequential scanning patterns (.6,.7,.8,.9) that look like a scanner
- Dead-end hosts are auto-marked when timeouts/down responses are detected

**Exception: Multi-turn mode** — high-priority hosts with confirmed access
get 2-3 consecutive commands without context reset. Playbook steps are fed
as specific next-step commands. Context is preserved between turns.

### Smart Targeting (exploit phase)
In EXPLOIT phase, host selection is priority-weighted:
- **60%**: high-priority (confirmed access — shares, Pi-hole, Samba, dnsmasq)
- **30%**: medium (has ports but untested)
- **10%**: low (3+ failed attacks)
- **0%**: exhausted (5+ failed attacks — skipped entirely)
- Priority recalculated every turn from live host memory
- Failed cred attacks auto-deprioritize hosts over time
- Confirmed access (SMB shares, DNS responding) keeps hosts high-priority

## Training Data Capture
Successful interactions are captured for model finetuning:
- **Location**: `training_data/` (20GB budget, auto-rotation)
- **Format**: JSONL with ChatML, per-day per-phase files
- **Captures**: system prompt + messages + response + command output
- **Only successes** — no garbage, errors, or refusals
- **Stats**: `GET /api/training/stats`
- **Export**: `GET /api/training/export/{chatml|jsonl|conversations}`
- Expected impact: format compliance from ~50% to 85%+ with finetuning

## Claude Code Cron Monitor
The project uses a Claude Code cron job (every 5 minutes) that autonomously
monitors the agent, fixes bugs, and logs observations. This is a key part of
the development workflow — the cron catches issues faster than a human can.

### Cron Prompt Template
```
You are the Nightcrawler autonomous pentest agent monitor. Check in every 5 minutes.

1. Run: bash /root/nightcrawler/scripts/health-check.sh
2. Read last 15 lines of logs/health.log
3. Check recent commands: tail -10 logs/timeline.jsonl (parse for errors)
4. Check agent RSS — restart if >200MB
5. Check pgrep -c llama-server — if >1, LOG CRITICAL (never fix yourself)
6. Check training stats via /api/training/stats
7. Check host rotation: are recent commands targeting different hosts?
8. Check for dumb mistakes: fake paths, nmap -T3+, scanning dead hosts
9. If agent stuck >15min, restart with clean context

PIPELINE QUALITY CHECKS:
- Commands with fake paths = validation bug
- nmap -T3+ = stealth violation
- Same host repeated = rotation broken
- Dead-end hosts being scanned = skip logic broken
- Empty curl not generating notes = learning bug

Fix code if needed, restart service, append to finetuning log.
```

### What the cron tracks each checkin:
- Service health (5 services + llama-server count)
- Agent RSS (memory leak detection, threshold 200MB)
- llama-server RSS (KV cache growth, warn at >5GB)
- Duplicate process detection and cleanup (root cause of memory leaks)
- Timeline freshness (stale = auto-restart after 30min)
- Command quality (stealth, rotation, validation)
- Training data accumulation
- Host rotation diversity (unique hosts / total commands)
- Pipeline violations (fake paths, stealth, dead hosts)

### Known memory behavior:
- llama-server KV cache grows ~200MB/hour (3.4→5.3GB over ~8h observed 2026-03-21)
- Magisk watchdog restarts llama-server every ~2h (random 1.75-2.5h, changed 2026-03-22)
- Restart drops RSS from ~5GB to ~3.4GB, frees ~2GB system memory
- Agent survives llama-server restart via error retry logic (hits errors for ~3min during JIT warmup)
- Android apps respawn and consume ~1.5GB (Google services, keyboard, etc.)
- Agent RSS stays stable at ~50MB — no Python-side leak
- System memory can drop to ~750MB under pressure (Android kills apps to compensate)
- The health check tracks llama-server RSS and warns at >5GB

### Cron prompt (copy-paste ready): `docs/cron-monitor-prompt.md`
### Cron context file: `docs/cron-context.md`
### Finetuning log: `nightcrawler-finetuning-logs.md` (gitignored, runtime data)

## Key Architecture Decisions
- **Few-shot prompting** is essential — the 1.2B model follows examples, not instructions
- **Phase-aware seed**: RECON uses nmap, ENUMERATE uses service probes, EXPLOIT uses 50/50 cred-test/enumerate
- **Garbage detection** with 5-streak context reset prevents model spiral (all rejection paths, including validation)
- **Varied reset examples**: port-matched SSH/DNS/HTTP/nmap examples prevent tool fixation
- **Direct playbook execution**: bypass the LLM for multi-step attack chains — the 1.2B model generates similar-but-wrong commands instead of following steps exactly
<<<<<<< Updated upstream
- **Let commands fail naturally**: don't silently reject — real error feedback teaches the model
=======
- **Let commands fail naturally**: don'\''\'\'''\''t silently reject — real error feedback teaches the model
>>>>>>> Stashed changes
- **Duplicate command detection** forces tool/target diversification
- **Patient host rotation** — spread activity across network, one action per host per turn
- **Same-host enforcement** — rejects commands targeting the same IP as the previous turn
- **Time-based stuck detection** — 5min without a command = force context reset (safety net)
- **Target IP required** — network tools (nmap, curl, dig, etc.) must include an IP address
- **Port dedup** — nmap -p lists cleaned of duplicates before execution
- **SQLite backend** (not JSON files) for memory efficiency and concurrent access
- **MAC-keyed hosts** survive DHCP changes, tagged by network_id (gateway MAC hash)
- **Network discrimination**: Same CIDR on different routers = separate data
- **kali-server-mcp** eliminates shell interpretation errors vs subprocess shell=True
- **Host memory** — auto-generated observations prevent repeating dead-end approaches
- **Agent RSS stays ~35-50MB** — no memory leak when not restarting repeatedly
- Repeated agent restarts DO leak memory (Python process accumulation) — avoid
- **No _execute retries for app errors** — only transport errors retry (prevents 3x audit entries)

## Exploit Toolkit (phase 3)
The EXPLOIT phase mixes credential testing with continued enumeration (50/50).
Available tools verified on Kali NetHunter:
- **CVE lookup**: `searchsploit [service] [version]` — offline exploit-db
- **Vuln scanning**: `nmap --script=smb-vuln*`, `--script=vulners`, `--script=http-vuln*`
- **Credential testing**: `nxc ssh/smb/telnet/vnc/ftp/mysql` with defaults + wordlists
- **SMB deep enum**: `enum4linux -a`, `impacket-samrdump`, `impacket-rpcdump`
- **Web probing**: `gobuster`, `dirb`, `curl robots.txt/.env/server-status`
- **Post-exploit**: `impacket-secretsdump` (if admin access gained)
- Phase auto-triggers when: hosts >= 10 AND ports >= 15 (or creds/vulns found)
- Context hints randomly suggest exploit OR enumerate tools each turn
- Prompt is hot-reloadable: edit `prompts/phase3_exploit.md`

### Exploit Pipeline v5 (updated 2026-03-22)
- **CVE DB**: 24,956 entries in `data/cve_exploits.json` — replaces searchsploit
- **Playbooks**: **27 multi-step attack chains** in `data/playbooks.json` — **direct execution bypassing LLM**
  - 11 original (SMB, Pi-hole, DNS, Samba, HTTP, VNC, SSH, Telnet, FTP, Redis, MySQL)
  - 16 new general-purpose (post-auth SSH, SNMP, NFS, LDAP, SMTP, WordPress, MSSQL, MongoDB, RDP, IPMI, Docker, PostgreSQL, Tomcat, Jenkins, phpMyAdmin, Joomla)
  - All safe: detection/enumeration/credential-testing only — nothing that crashes hosts
  - Template variables: `{ip}`, `{share}`, `{user}`, `{password}` (creds from DB)
- **Direct playbook execution**: playbook steps execute through scope proxy, 2-3 seconds apart, bypassing LLM completely. Tagged `[PLAYBOOK]` in feed. The 1.2B model was generating similar-but-wrong commands instead of following playbook steps — direct execution fixes this.
- **Output parser**: `agent/output_parser.py` — extracts CVEs, files, hostnames, creds from output
- **Attack planner**: `agent/attack_planner.py` — strategic directives every ~50 commands
- **Smart targeting**: priority-weighted host selection, failure memory, tried-action dedup
- **Exploit chains**: vuln DB tracks the command sequence that found each finding
- **Report generation**: `/api/report` endpoint + REPORT button in web UI
- **Failed cred filtering**: hints AND playbook steps skip already-failed credentials per-password
- **VNC failure detection**: handles empty nxc vnc output (writes to stderr) — treats empty as failure
- **Untried tool boost**: impacket/nikto/gobuster get 80% probability when never tried
- **Playbook completion**: persisted in SQLite, marked done on queue empty
- **Auto-tagging**: nmap output auto-tags hosts for 15+ service types to trigger playbooks
- **Varied context reset**: on 5-streak, injects port-matched examples (SSH/DNS/HTTP) to break tool fixation
- **Installed packages**: `snmp` + `onesixtyone` for SNMP playbooks
- **Passive capture**: background tcpdump for mDNS/NBNS/DHCP/ARP — zero stealth cost host discovery
- **Credential spray**: harvests usernames from samrdump/RID brute/DNS, sprays against SSH/telnet
- **HTTP content analysis**: parses curl responses for login forms, frameworks, internal IPs, comments
- **Network topology**: groups hosts by service, builds attack narratives, risk-scores hosts
- **ARP scan + banner grab**: discovers hidden hosts, fingerprints unknown services
- **Finetuning eval**: format compliance stats, tool coverage analysis
- See `docs/FEATURES.md` for full details

## Cross-Process State (agent ↔ webui)
The agent and webui daemon are separate processes. State is shared via:
- **SQLite**: `agent_ui_state` key in state table (phase, mode, uptime, stats)
- **update_state()** in agent loop persists to SQLite each iteration
- **api_state()** in webui reads from SQLite + disk findings
- This was added 2026-03-21 to fix the UI showing stale phase after EXPLOIT transition

## Pipeline Validation (agent/loop.py)
Commands pass through 5 validation gates before execution:
1. **Dead-end skip**: hosts marked dead-end in host_memory are skipped
2. **Same-host enforcement**: rejects if target IP == last executed IP
3. **_is_valid_command()**: rejects fake paths, placeholders, -T3+, missing target IP
4. **_is_duplicate()**: exact match against last 5 commands
5. **_dedup_ports()**: cleans duplicate ports in nmap -p lists

All rejection paths increment `garbage_streak`. At streak 5, a shared
`_reset_context_with_fewshot()` fires — clears context, injects a
<<<<<<< Updated upstream
**port-matched example** (SSH/DNS/HTTP/nmap variants based on target host's actual ports)
=======
**port-matched example** (SSH/DNS/HTTP/nmap variants based on target host'\''\'\'''\''s actual ports)
>>>>>>> Stashed changes
on a random host, clears dedup window + last IP.
Time-based stuck detection (5min) is a backstop that catches any stuck
pattern regardless of which gate is involved.

<<<<<<< Updated upstream
**Key lesson (2026-03-22)**: Don't silently reject commands from the 1.2B model.
The smbclient port validation (rejecting smbclient on hosts without port 445)
caused an infinite rejection loop — the model couldn't learn from silent rejections
=======
**Key lesson (2026-03-22)**: Don'\''\'\'''\''t silently reject commands from the 1.2B model.
The smbclient port validation (rejecting smbclient on hosts without port 445)
caused an infinite rejection loop — the model couldn'\''\'\'''\''t learn from silent rejections
>>>>>>> Stashed changes
and kept regenerating the same command. Letting commands fail naturally through
the executor gives the model real feedback ("Connection refused") and it adapts.
Silent rejection loops are worse than wasted turns.

## LFM2.5-1.2B Model Behavior Notes (LFM2.5-1.2B-Instruct-Heretic Q8_0)
- **Heretic-abliterated** — no safety refusals (verified: complies with port scans, SMB enum, credential attacks, web probes), no re-prompting needed
- ~50% command success rate (inherent limit of 1.2B parameters)
- Produces garbage/number sequences ~25% of turns
<<<<<<< Updated upstream
- **Format compliance**: zero-shot format compliance is weak (echoes placeholders, garbled syntax), but GOOD with few-shot prompting — the agent's actual prompting style produces clean "REASONING:/COMMAND:" output
=======
- **Format compliance**: zero-shot format compliance is weak (echoes placeholders, garbled syntax), but GOOD with few-shot prompting — the agent'\''\'\'''\''s actual prompting style produces clean "REASONING:/COMMAND:" output
>>>>>>> Stashed changes
- Follows few-shot examples more than system prompt instructions (even more true for this 1.2B model than for the old 2B)
- Smaller than the old 2B model but ~2.6x faster generation (13 vs 4.8 t/s), so more retries/throughput offset any per-response quality difference
- **Stuck loops**: model fixates on reasoning (e.g., "SSH open, SMB open") without producing COMMAND — or repeats the same command. Fixed with 5-streak reset + 5min time-based backstop.
- **Tool fixation**: model learns "exploit = smbclient" and generates smbclient for ALL hosts regardless of open ports. Silent command rejection makes this WORSE (infinite loop). Solution: let commands fail naturally + varied port-matched reset examples.
<<<<<<< Updated upstream
- **Can't follow multi-step playbooks**: model generates similar-but-wrong commands instead of exact playbook steps. Solution: direct playbook execution bypassing LLM entirely.
=======
- **Can'\''\'\'''\''t follow multi-step playbooks**: model generates similar-but-wrong commands instead of exact playbook steps. Solution: direct playbook execution bypassing LLM entirely.
>>>>>>> Stashed changes
- Verbose reasoning eats tokens — "10 words max" in system prompt helps
- Temperature 0.2 gives best format compliance
- max_tokens 200 balances completeness vs garbage
- Stealth: system prompt enforces -T2 for nmap (never -T4/-T5)
- **Ignores host suggestions** — model often follows up on last-seen host instead of suggested target. Same-host enforcement now forces rotation.

## Dynamic Network Detection (`agent/net_detect.py`)
- `config.yaml` uses `networks: ["auto"]` and `excluded_hosts: ["auto"]`
- Auto-detects subnet, prefix, our IP, gateway from `wlan0` interface
- Supports 192.168.x, 10.x, 172.16-31.x — any private network
- 60-second cache for performance
- All components use `net_detect` instead of hardcoded IPs
- Scope proxy auto-configures from wlan0, auto-excludes gateway + self IP

## Seed Sweep & Host Discovery
- `nmap -sn` at agent startup, upserts ALL discovered hosts to SQLite DB
- Periodic re-sweep every ~200 commands to discover new hosts that joined
- Passive capture (tcpdump) every ~50 commands for mDNS/NBNS/DHCP/ARP
- All discovered hosts immediately persisted with correct `network_id`

## Per-Network Feed & Pagination
- Feed entries tagged with `network_id` when created via `push_feed()`
<<<<<<< Updated upstream
- Switching networks shows only that network's feed entries
=======
- Switching networks shows only that network'\''\'\'''\''s feed entries
>>>>>>> Stashed changes
- Displays last 200 entries, count shows "200+" when more exist
- Reverse pagination: scrolling to top loads 100 more older entries
- Network deletion clears feed entries for that network

## Network Deletion
- `DELETE /api/networks/<id>` — triple-confirmation UI
- Auto-kills running agent, pauses watchdog (pause file), cleans all data
- Deletes: hosts, vulns, creds, commands, feed entries, network record
- 2-minute delayed agent restart after deletion
- Toast notifications: success, watchdog pause, restart warning

## Development Notes
- Agent auto-detects network: resumes at correct phase based on existing findings
- Startup phase detection: EXPLOIT if hosts>=10 + ports>=15, ENUMERATE if hosts>=3, else RECON
- Thor (AGX 128GB) is optional — agent operates fully standalone
- Web UI binds to Tailscale IP only (not exposed on target network)
- All commands audited to SQLite + commands.jsonl regardless of allow/block
- Health check monitors: services, agent RSS, dual llama-server, stale timeline, disk, memory
- Exploit phase throughput: ~2-3 cmd/cycle (vs 4 in enumerate) due to longer prompt context
- Time-based stuck detection fires ~2-3 times per hour in exploit phase (self-healing)
- Training capture: 700+ examples across recon/enumerate/exploit phases

## Boot Sequence (Magisk service.sh + watchdog_block.sh)
All services auto-start after reboot. **Do NOT manually start services — wait 10 min.**

1. +10s: Android SSH (9022)
2. +12s: Mount /vendor in Kali chroot
3. +14s: Kali SSH (8022) — binds real /dev /proc /sys (+ devpts) into the chroot,
   then starts sshd + a **persistent keepalive** loop that revives it if it dies
4. +14s: SSH firewall (iptables: localhost + Tailscale only)
5. +2min: **Early offline detection** — checks USB adapter + WiFi, creates pause files if needed, clears stale pause files from previous boot if online
6. +3min: GPU governor daemon starts (forces performance mode, checks battery every 60s)
7. +5min: llama-server watchdog starts (checks pause file before first start, 20min crash cooldown)
8. +8min: **Kali services auto-start** (via `scripts/autostart.sh` run in chroot):
   - **Online** (WiFi connected, no USB adapter): all services + agent + agent-watchdog
   - **Offline** (USB WiFi adapter detected): webui + mcp + proxy only (no agent, no llama)
   - **Disconnected** (no WiFi, no USB adapter): webui only
9. Every ~2h (random 1.75-2.5h): llama-server scheduled restart (PID file, SIGKILL, process count verify)

**After reboot**: everything comes up automatically within 10 min.
- Boot scripts: `scripts/service.sh` (Magisk) → `scripts/watchdog_block.sh` → `scripts/autostart.sh`
- `watchdog_block.sh` is copied to `/data/local/tmp/watchdog_block.sh` and sourced by Magisk service.sh
- `autostart.sh` runs inside the Kali chroot via bash (not busybox sh — busybox subshells silently fail)
- Log: `/data/local/tmp/var/log/nightcrawler-autostart.log`

If the webui auto-starts with a USB adapter plugged in, the `/api/offline/state` poll will
auto-detect the adapter, load the driver (8821cu/8188eu), and enter offline mode.

## Magisk Modules
| Module | Purpose |
|--------|---------|
| openssh (v9.9p2) | Persistent SSH on ports 9022 + 22 |
| adreno-650_819v2 | GPU driver v819.2 (E031.50) |
| nethunter (v1.4.0) | Kali chroot + tools |
| tailscaled | Tailscale VPN |

## Web UI
- URL: https://<tailscale-hostname>:8888 (self-signed cert)
- Daemon: `bash scripts/webui-daemon.sh {start|stop|status|restart}`
- Features: clickable host cards, port details, scan history, network selector, Thor export
- Reads from SQLite + JSON files (survives agent crashes)
- **Stealth**: spoofs nginx headers, rejects target-network connections (returns empty 404)
- **Report**: REPORT button generates downloadable pentest report with vulns + remediation
- **Separate process**: agent communicates via SQLite (`agent/ui_bridge.py`), webui reads

## Agent Watchdog (`scripts/agent-watchdog.sh`)
- Monitors agent log file modification time every 60s
<<<<<<< Updated upstream
- If log hasn't been updated in 40 min → agent is hung → kills and restarts
=======
- If log hasn'\''\'\'''\''t been updated in 40 min → agent is hung → kills and restarts
>>>>>>> Stashed changes
- Also restarts if agent process is not running at all
- Runs as a separate process alongside the agent (not inside it)
- Logs to `/tmp/nc-agent-watchdog.log`
- Auto-started in tmux via `scripts/run-36h.sh` (window 4: watchdog)
- **Does NOT replace the cron monitor** — the cron does diagnosis + code fixes, the watchdog just handles process-level hangs

## Offline Mode (WiFi Attack Pipeline)
Pwnagotchi-inspired autonomous WiFi breach mode. When device has no WiFi or user
enters offline mode, the UI transforms to show WiFi scanning/capture/cracking.

### Architecture
- **External USB WiFi adapter** (wlan1) for monitor mode — internal QCA6390 cannot do monitor mode
- Internal wlan0 stays connected (Tailscale/SSH stay up during scanning)
- Pipeline: scan (manual) → select target/ROE (manual) → capture (auto) → crack (auto) → connect (auto)
- Fully autonomous after target selection — retries capture if connect fails
- Capture: alternating 13.5min cycles — odd=hcxdumptool PMKID (RT3572), even=airodump+deauth
- Semi-stealthy deauth: 3 frames, targeted, 90s cooldown, 5 per cycle, broadcast fallback
- Cracking: aircrack-ng CPU at ~290k keys/sec with wifite.txt+rockyou.txt (14.5M passwords)
- Hash conversion: hcxdumptool pcapng → hcxpcapngtool 22000 → hcxhash2cap pcap → aircrack-ng
- **Persistence**: cracked passwords survive page refresh, reboots, mode transitions
- Previously cracked networks auto-resume (skip capture, jump to CONNECTING)
- Connect via Android shell (`cmd wifi connect-network` via SSH), NOT chroot wpa_supplicant
- Manual offline/online toggle button in control bar
- Auto-detects adapter unplug → transitions back to online mode, restarts services
- 5-min grace period after connect before USB adapter re-triggers offline mode
- State machine in `agent/offline_manager.py`, persisted to SQLite
- Simulation mode (`NC_OFFLINE_SIM=1` or `/api/offline/simulate`) for testing

### Key Files
- `agent/offline_manager.py` — pipeline state machine, subprocess management
- `webui/server.py` — 14 `/api/offline/*` endpoints
- `webui/templates/index.html` — offline UI panels (amber theme, Pwnagotchi face)
- `logs/offline.log` — persistent file log for debugging (survives crashes)
- `tests/test_offline_api.py` — 60 API tests
- `tests/test_offline_ui.py` — 38 Playwright UI tests

### USB WiFi Adapter Requirement
- **Custom kernel v4** (4.19.297-perf-g8228d522e928-dirty) built from Nameless AOSP source with MAC80211=y
- Kernel source: https://github.com/garagehq/kernel_oneplus_sm8250_nethunter
- Stock kernel (4.19.157-perf+) has no MAC80211 — custom kernel required
- MODULE_SIG and MODVERSIONS both disabled for easy module loading
- Boot backup at `/sdcard/nightcrawler-kernels/boot-backup-20260324.img`
- **Primary adapter: Ralink RT3572 (148f:3572)** — full injection + PMKID capture via hcxdumptool
  - Driver: `rt2800usb.ko` (+ rt2x00lib, rt2x00usb, rt2800lib) — built on-device from kernel source tree
  - Requires firmware: `firmware-misc-nonfree` package (provides `rt2870.bin`)
  - Monitor mode + packet injection confirmed, PMKID capture in ~60s
  - 2.4GHz + 5GHz capable
- **Secondary adapter: Edimax AC600 (7392:d811, RTL8821CU)** — NOT RTL8811AU as commonly listed
  - Driver: `8821cu.ko` (morrownr fork, compiled on-device)
  - 55 networks discovered in 15s, monitor mode + basic deauth injection
  - 2.4GHz + 5GHz capable, but no PMKID support (hcxdumptool fails)
- Also works: Edimax N150 (7392:b811, RTL8188EUS) — `8188eu.ko`, 28 networks in 15s
- Modules at `kernels/modules/` in repo, also at `/sdcard/nightcrawler-kernels/modules_v5/`
- Load RT3572: `insmod rt2x00lib.ko && insmod rt2x00usb.ko && insmod rt2800lib.ko && insmod rt2800usb.ko` (from `kernels/modules/`)
- Load RTL8821CU: `insmod /root/nightcrawler/kernels/modules/8821cu.ko`
- Kernel headers at `/lib/modules/$(uname -r)/build/` for on-device compilation

### Offline Mode Auto-Detection
- `/api/offline/state` checks `is_wifi_connected()` — if wlan0 has no IP, auto-enters offline mode
- Also auto-detects USB adapter plug-in → loads driver → enters offline mode
- Once offline, stays offline until pipeline completes (connect auto-transitions to online)
- Agent + llama-server always killed in offline mode to free RAM
- Both watchdogs paused via `/tmp/nc-agent-pause` and `/data/local/tmp/nc-llama-pause`

### Watchdog Pause Files
- `/tmp/nc-agent-pause` — pauses agent-watchdog.sh (checked every 60s)
- `/data/local/tmp/nc-llama-pause` — pauses llama-watchdog.sh (checked every 30s)
- Created by `force_offline()`, removed by `force_online()` / `connect()`

## IMPORTANT: Always Restart Agent After Code Changes
After modifying agent/loop.py, agent/*.py, or main.py:
1. `pkill -9 -f "python3 main.py"`
2. `nohup python3 main.py >> /tmp/nc-agent.log 2>&1 &`
3. Verify: `sleep 3 && kill -0 $(pgrep -f "python3 main.py") && echo OK`
The agent does NOT hot-reload Python code. Forgetting to restart is the #1 cause
of "agent down" during development. The WebUI daemon also needs restart for
server.py changes: `bash scripts/webui-daemon.sh restart`

## IMPORTANT: Clean Up Test Artifacts
After ANY testing that creates data in the DB (test networks, test hosts, demo data):
<<<<<<< Updated upstream
- **Delete test networks**: `DELETE FROM networks WHERE network_id NOT IN ('<real_id>')`
- **Delete test hosts**: `DELETE FROM hosts WHERE network NOT IN (SELECT network_id FROM networks)`
- **Delete test memories**: Check `host_memories` state for test MAC addresses
- **Verify**: `python3 -c "from agent.db import *; init_db('logs'); print(get_networks()); print(len(get_hosts()))"`
=======
- **Delete test networks**: `DELETE FROM networks WHERE network_id NOT IN ('\''\'\'''\''<real_id>'\''\'\'''\'')`
- **Delete test hosts**: `DELETE FROM hosts WHERE network NOT IN (SELECT network_id FROM networks)`
- **Delete test memories**: Check `host_memories` state for test MAC addresses
- **Verify**: `python3 -c "from agent.db import *; init_db('\''\'\'''\''logs'\''\'\'''\''); print(get_networks()); print(len(get_hosts()))"`
>>>>>>> Stashed changes
- Never leave fake data (HomeWifi, ClientOffice, FF:EE:DD:CC:BB:AA, etc.) in production DB

## Known Issues
- **Kali SSH (8022) dies unless /dev is bind-mounted (2026-07-11)**: `/data` is mounted
<<<<<<< Updated upstream
  `nodev`, so a device node created on the chroot's `/dev` (e.g. `/dev/null`) does not
  function. sshd's `daemon()` reopens stdio onto `/dev/null` and exits with
=======
  `nodev`, so a device node created on the chroot'\''\'\'''\''s `/dev` (e.g. `/dev/null`) does not
  function. sshd'\''\'\'''\''s `daemon()` reopens stdio onto `/dev/null` and exits with
>>>>>>> Stashed changes
  `daemon() failed: No such device` — port 8022 never comes up (foreground `sshd -D`
  works because it skips `daemon()`). Something had also clobbered `kalifs/dev/null`
  into a regular file (writes from `cmd >/dev/null` in the chroot). Fix: `service.sh`
  now binds real `/dev /proc /sys` (+ devpts) into the chroot before starting sshd,
  plus a persistent keepalive. **Guards are effect-based** (`[ -c dev/null ]`) not
<<<<<<< Updated upstream
  `/proc/mounts` — Magisk's mount namespace does NOT surface these binds in `/proc/mounts`,
  so a grep-based guard would re-mount forever. Manual restart from Android shell:
  `ssh -p 9022 shell@127.0.0.1 '[ -c /data/local/nhsystem/kalifs/dev/null ] || mount --bind /dev /data/local/nhsystem/kalifs/dev; /system/bin/chroot /data/local/nhsystem/kalifs /usr/sbin/sshd'`
=======
  `/proc/mounts` — Magisk'\''\'\'''\''s mount namespace does NOT surface these binds in `/proc/mounts`,
  so a grep-based guard would re-mount forever. Manual restart from Android shell:
  `ssh -p 9022 shell@127.0.0.1 '\''\'\'''\''[ -c /data/local/nhsystem/kalifs/dev/null ] || mount --bind /dev /data/local/nhsystem/kalifs/dev; /system/bin/chroot /data/local/nhsystem/kalifs /usr/sbin/sshd'\''\'\'''\''`
>>>>>>> Stashed changes
- Q4_K_M on GPU: extremely slow (falls back to generic kernels)
- 4B Q8_0: fails to load (exceeds 1GB per-allocation limit)
- Vulkan: dead end (vendor=1.1, Mesa Turnip=DeviceLostError)
- OpenCL embedded kernels: 60+ min JIT (use non-embedded)
- 1.2B model garbage rate ~50% — handled by garbage detection + context reset
- Context overflow at old 4096 limit — fixed with 8192
- 1.2B model stuck loops: fixates on reasoning without COMMAND (3 incidents in 3h observed 2026-03-21). Fixed with time-based backstop (5min) + dup-streak reset + few-shot resets
- smbclient path hallucination: model sometimes puts CIDR or angle brackets in share path (e.g., `//<192.168.1.15>/`, `//ip/10.0.0.0/24`). Harmless (command fails) but wastes a turn
<<<<<<< Updated upstream
- **smbclient fixation (2026-03-22)**: 1.2B model learns "exploit = smbclient" and generates it for every host. Silent validation rejection caused infinite loop. Fixed: let commands fail naturally + varied reset examples. Don't silently reject 1.2B model commands.
=======
- **smbclient fixation (2026-03-22)**: 1.2B model learns "exploit = smbclient" and generates it for every host. Silent validation rejection caused infinite loop. Fixed: let commands fail naturally + varied reset examples. Don'\''\'\'''\''t silently reject 1.2B model commands.
>>>>>>> Stashed changes
- **VNC empty output**: nxc vnc writes to stderr, so output is empty. VNC failure detection now treats empty output as failure (not just `[*]` check).
- **nxc vnc -p flag**: VNC has no `-u` flag, only `-p`. Failure extraction adjusted to only require password match.
