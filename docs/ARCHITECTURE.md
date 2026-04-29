# Nightcrawler — Architecture

```
 ░█▄░█ █ █▀▀ █░█ ▀█▀ █▀▀ █▀█ ▄▀█ █░█░█ █░░ █▀▀ █▀█
 ░█░▀█ █ █▄█ █▀█ ░█░ █▄▄ █▀▄ █▀█ ▀▄▀▄▀ █▄▄ ██▄ █▀▄  v0.1.0
```

## Overview

Nightcrawler is a shell-based autonomous penetration testing agent that runs entirely within a [Kali NetHunter](https://www.kali.org/docs/nethunter/) chroot on an Android phone. It uses a local 2B-parameter language model as its reasoning engine and the official [Kali Linux MCP server](https://www.kali.org/tools/mcp-kali-server/) as its tool interface.

**What makes it different from a vulnerability scanner?** Traditional scanners run a fixed checklist against every host. Nightcrawler *reasons* about what to do next — it picks targets, chooses tools, interprets output, and builds up knowledge over time. It operates more like a human pentester with infinite patience.

The model constructs raw CLI commands (e.g., `nmap -sS -T2 192.168.1.0/24`) rather than calling pre-defined tool APIs. This gives the agent access to every tool installed in Kali without needing hand-built wrappers for each one.

---

## System Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     PHONE  ·  NETHUNTER CHROOT                      │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  TMUX SESSION "nightcrawler"                                  │  │
│  │  Detachable · Survives screen-off · Remote-attachable via SSH │  │
│  │                                                               │  │
│  │  ┌─────────────┐                                             │  │
│  │  │  LLM        │  Constructs raw Kali commands               │  │
│  │  │  (2B model) │  e.g. "nmap -sS 192.168.1.0/24"            │  │
│  │  │  llama.cpp  │                                             │  │
│  │  │  :8080      │                                             │  │
│  │  └──────┬──────┘                                             │  │
│  │         │                                                     │  │
│  │         ▼                                                     │  │
│  │  ┌─────────────────┐      ┌──────────────────────────────┐   │  │
│  │  │  AGENT LOOP     │      │  SCOPE ENFORCEMENT PROXY     │   │  │
│  │  │  (main.py)      │─────▶│  :8800                       │   │  │
│  │  │                 │      │                              │   │  │
│  │  │  Picks targets, │      │  ✓ Validates target IPs      │   │  │
│  │  │  interprets     │      │  ✓ Blocks excluded hosts     │   │  │
│  │  │  output, learns │      │  ✓ Blocks excluded ports     │   │  │
│  │  │                 │      │  ✓ Enforces rate limits      │   │  │
│  │  └────────┬────────┘      │  ✓ Logs all commands         │   │  │
│  │           │               │  ✗ Rejects destructive cmds  │   │  │
│  │  ┌────────▼────────┐      └──────────┬───────────────────┘   │  │
│  │  │  WEB DASHBOARD  │                 │                       │  │
│  │  │  :8888          │                 ▼                       │  │
│  │  │  Monitor, steer │      ┌──────────────────────────────┐   │  │
│  │  │  the agent      │      │  Kali MCP Server (official)  │   │  │
│  │  └─────────────────┘      │  :5000                       │   │  │
│  │                           │  Executes: nmap, curl, hydra │   │  │
│  │                           │  smbclient, gobuster, dig... │   │  │
│  │                           └──────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  SQLite DB: hosts, vulns, creds, commands (WAL mode)         │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Tailscale — mesh VPN for remote SSH + dashboard access      │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Magisk Boot Services                                        │  │
│  │  Auto-starts LLM, GPU governor, SSH, watchdogs on boot       │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## The Three-Layer Command Stack

Every command the agent wants to run passes through three layers:

```
Layer 1: Agent (constructs the command)
   │  The LLM produces a raw CLI command like "nmap -sV -p 22 192.168.1.5"
   ▼
Layer 2: Scope Enforcement Proxy (:8800)    ← The safety layer
   │  Checks: Is this IP in scope? Is this port allowed?
   │  Checks: Is this a destructive command (rm, mkfs, reboot)?
   │  Logs every command to SQLite for audit trail
   ▼
Layer 3: Kali MCP Server (:5000)            ← The execution layer
   │  Official Kali package — runs commands via shlex (no shell injection)
   │  Returns stdout, stderr, return code
   ▼
Result flows back up to the agent for interpretation
```

**Why three layers?** The LLM can hallucinate or produce unsafe commands. The scope proxy catches these before they execute. The Kali MCP server provides secure command execution without shell interpretation. Even if the model goes rogue, it can't escape the scope proxy's validation.

### What the Scope Proxy Checks

| Check | What it does |
|-------|-------------|
| **Scope validation** | Extracts all IPs/CIDRs from the command, verifies each is within allowed networks |
| **Host exclusion** | Blocks commands targeting excluded hosts (e.g., gateway, the phone itself) |
| **Port exclusion** | Blocks commands targeting excluded ports (e.g., SCADA ports 502/503) |
| **Destructive filter** | Regex blocklist for dangerous commands: `rm -rf`, `mkfs`, `dd if=`, `reboot`, etc. |
| **Rate limiting** | Enforces max commands per minute, injects random jitter between scans |
| **Audit logging** | Every command (allowed or blocked) is logged with timestamp and reasoning |

---

## Phase State Machine

The agent progresses through phases as it learns about the network:

```
┌─────────┐              ┌─────────┐              ┌─────────┐
│ PHASE 0 │  WiFi up     │ PHASE 1 │  3+ hosts    │ PHASE 2 │
│ WiFi    │─────────────▶│ Recon   │─────────────▶│ Enum    │
│ Breach  │              │ & Map   │              │ & Probe │
└─────────┘              └─────────┘              └────┬────┘
                                                       │ vuln/cred found
                         ┌─────────┐              ┌────▼────┐
                         │ PHASE 4 │              │ PHASE 3 │
                         │ Cleanup │◀─────────────│ Exploit │
                         │ & Report│              │ & Pivot │
                         └─────────┘              └─────────┘
```

- **Phase 0 (WiFi Breach):** No network connection. Autonomously captures and cracks WPA2 handshakes using an external USB WiFi adapter. Skipped if already connected.
- **Phase 1 (Recon):** Discover hosts on the network using stealthy ping sweeps and ARP scans. One host per turn, rotating randomly.
- **Phase 2 (Enumerate):** Probe discovered services — identify versions, check configurations, map the attack surface. Still rotating across hosts.
- **Phase 3 (Exploit):** Test for vulnerabilities and default credentials on hosts with accumulated context. Uses playbooks for multi-step attacks.
- **Phase 4 (Cleanup):** Verify all findings are logged, generate report, optionally sync to a remote server.

**Important:** Phases track *overall* mission progress, but individual hosts advance independently. While the mission is in "enumerate," one host might still be in "recon" (just discovered) while another is ready for "exploit" (services fully mapped).

---

## Red Team Strategy: Patient Rotation

The agent doesn't scan like a vulnerability scanner. It operates like a patient adversary:

```
Traditional Scanner:          Nightcrawler:
  Scan ALL hosts               Discover host A
  ↓                            Probe host B port 22
  Enumerate ALL services       Check host C HTTP headers
  ↓                            Back to host A, try SMB
  Exploit ALL vulns            Discover host D
                               Back to host B, check version
                               ...hours pass...
                               Host A has enough context → exploit
```

Key principles:
- **One action per turn** — a single nmap scan, curl request, or dig query
- **Rotate hosts** — weighted random selection (70% interesting hosts, 30% new discovery)
- **Spread traffic** — no single host sees a burst of activity
- **Skip dead-ends** — hosts that time out or respond with nothing are auto-deprioritized
- **Exploit only when ready** — after many prior touches build enough context
- **Stealth first** — nmap -T2 timing, rate limiting, random jitter between commands

This makes the agent much harder to detect than traditional scanners. No single host sees more than one or two probes per hour.

---

## Exploit Pipeline

The 2B model is too small to reliably plan multi-step attacks. The exploit pipeline compensates with external intelligence:

```
Host selected for exploitation
  │
  ├─► CVE Database (24,956 entries)
  │   Matches service versions to known CVEs
  │   Returns ready-to-run exploit commands
  │
  ├─► Playbook Engine (27 attack chains)
  │   Multi-step sequences that BYPASS the LLM
  │   Execute directly through the scope proxy
  │   Examples: SMB enumeration, Pi-hole exploit, DNS zone transfer
  │
  ├─► Output Parser
  │   Extracts structured data from command output:
  │   CVEs, credentials, file paths, hostnames
  │
  └─► Attack Planner (every ~50 commands)
      Strategic directives injected into the LLM prompt
      "Focus on host X — has SSH + default creds"
```

**Why bypass the LLM for playbooks?** The 2B model can generate *similar-but-wrong* commands when following multi-step instructions. For example, it might produce `smbclient //192.168.1.5/share` instead of `smbclient -N -L //192.168.1.5/`. Direct execution ensures playbook steps run exactly as specified.

---

## Offline WiFi Mode

Inspired by [Pwnagotchi](https://pwnagotchi.ai/), the offline mode transforms the agent into an autonomous WiFi breach tool. When the phone has no WiFi connection (or the user toggles offline mode), it:

1. **Scans** for nearby WiFi networks using an external USB adapter in monitor mode
2. **Captures** WPA2 handshakes via PMKID collection or targeted deauthentication
3. **Cracks** the captured handshake using aircrack-ng with wordlists
4. **Connects** to the cracked network and transitions back to online pentest mode

Only steps 1-2 require user interaction (selecting the target and confirming Rules of Engagement). Everything after is fully autonomous.

### Capture Methods

| Method | Adapter | How it works | Speed |
|--------|---------|-------------|-------|
| **PMKID** | RT3572 | Passive — requests PMKID from the access point | ~60 seconds |
| **Deauth + Handshake** | RTL8821CU | Active — disconnects a client, captures reconnection | 2+ hours |

The agent alternates between capture methods in 13.5-minute cycles to maximize success probability.

---

## Data Storage

All data is stored in a SQLite database (`logs/nightcrawler.db`) with WAL mode for concurrent access:

| Table | Key | Purpose |
|-------|-----|---------|
| `hosts` | MAC address | Survives DHCP IP changes |
| `networks` | Gateway MAC hash | Isolates data per-network |
| `vulnerabilities` | host + finding | Deduplicated findings with CVE tags |
| `credentials` | service + user + pass | Discovered and manually-added creds |
| `commands` | timestamp | Full audit trail of every command |
| `host_memories` | host MAC | Persistent observations per host |

**Multi-network isolation:** All data is tagged with a `network_id` derived from the gateway's MAC address. Same CIDR range on different routers = separate data sets. This prevents cross-contamination between engagements.

---

## Security Model

1. **System prompt** — first line of defense. Instructs the LLM to stay in scope and use stealth timing.
2. **Scope proxy** — second line. Validates every command before it reaches the Kali MCP server. Even if the model ignores instructions, the proxy blocks out-of-scope actions.
3. **Audit trail** — every command logged for operational review, whether allowed or blocked.
4. **Credential encryption** — AES-256-GCM, key from `NC_CRED_KEY` environment variable.
5. **Secure wipe** — `scripts/wipe.sh` performs multi-pass shred + fstrim for post-engagement cleanup.
6. **Stealth filtering** — web dashboard rejects connections from the target network and spoofs nginx headers.
7. **Auto-blacklist** — the agent automatically excludes its own IP and the gateway from scanning.

---

## Memory Footprint

| Component | RAM Usage |
|-----------|----------|
| LLM model (Q8_0) | ~2.74 GB |
| KV cache (8192 ctx) | ~0.6 GB |
| Android system | ~4-5 GB |
| Agent + webui | ~50 MB |
| **Remaining for tools** | **~3.5 GB** |

**Critical:** Never run two LLM server instances simultaneously. Dual instances caused OOM crashes in testing (~3GB x 2 = phone reboot).

---

## Boot Sequence

Everything auto-starts after a reboot via Magisk:

| Time | What starts |
|------|------------|
| +10s | Android SSH (port 9022) |
| +12s | Mount /vendor in chroot (needed for GPU) |
| +14s | Kali SSH (port 8022) |
| +2min | Offline detection (checks for USB WiFi adapter) |
| +3min | GPU governor daemon (forces max GPU clock on battery) |
| +5min | LLM server watchdog (starts llama-server) |
| +8min | Kali services auto-start (agent, webui, scope proxy) |
| ~2h | LLM server scheduled restart (prevents memory growth) |

**After a reboot, all services are up within 10 minutes.** No manual intervention needed.

---

## Two Worlds: Kali Chroot vs Android

The phone has two separate Linux environments sharing the same kernel:

| | Kali Chroot | Android |
|---|---|---|
| C library | glibc | bionic |
| Purpose | Pentest tools, agent | LLM inference (GPU) |
| SSH port | 8022 | 9022 |

Binaries from one world can't run in the other (different C libraries). The only way to execute Android-side commands from Kali is via SSH: `ssh -p 9022 shell@127.0.0.1 "command"`.

The LLM runs on the Android side (for GPU access) but the agent reaches it at `http://127.0.0.1:8080` because they share the network namespace.

---

## Self-Healing

The agent has multiple recovery mechanisms to handle the 2B model's ~50% garbage rate:

| Mechanism | Trigger | Action |
|-----------|---------|--------|
| **Garbage streak reset** | 5 consecutive invalid outputs | Clear context, inject varied few-shot example |
| **Stuck detection** | 5 minutes without a command | Force context reset |
| **Duplicate detection** | Same command repeated | Force tool/target diversification |
| **Agent watchdog** | Log not updated in 40 min | Kill and restart agent process |
| **LLM watchdog** | Crash or memory growth | Restart LLM server (20 min cooldown) |
| **GPU governor** | Battery power throttle | Force max GPU clock (revert at ≤15%) |

---

## Extending Nightcrawler

### Adding a new playbook

Playbooks live in `data/playbooks.json`. Each playbook is a JSON object:

```json
{
  "id": "my_new_playbook",
  "name": "My Service Enumeration",
  "trigger": "my-service",
  "steps": [
    "nmap -sV -p 1234 {ip}",
    "curl http://{ip}:1234/api/version"
  ],
  "repeatable": false
}
```

The `trigger` field matches against host tags (auto-generated from nmap output). Template variables `{ip}`, `{share}`, `{user}`, `{password}` are filled from the database at runtime.

### Adding CVE entries

CVE entries live in `data/cve_exploits.json`:

```json
{
  "service": "my-service",
  "version_regex": "MyService ([0-9.]+)",
  "cve": "CVE-2024-XXXXX",
  "command": "nmap --script=my-vuln-check -p 1234 {ip}",
  "severity": "high"
}
```

### Modifying agent behavior

The LLM prompts are in `prompts/` and are **hot-reloadable** — edit them while the agent is running and changes take effect on the next turn. No restart needed.

