# Nightcrawler

An autonomous penetration testing agent that runs entirely on a smartphone. Drop the phone on a network, walk away, and it discovers hosts, maps services, finds vulnerabilities, and generates a pentest report — all without cloud connectivity.

```
 ░█▄░█ █ █▀▀ █░█ ▀█▀ █▀▀ █▀█ ▄▀█ █░█░█ █░░ █▀▀ █▀█
 ░█░▀█ █ █▄█ █▀█ ░█░ █▄▄ █▀▄ █▀█ ▀▄▀▄▀ █▄▄ ██▄ █▀▄  v0.1.0

 AUTONOMOUS MOBILE PENTEST AGENT
 OnePlus 8 · NetHunter · LFM2.5-1.2B · OpenCL GPU
```

## What is this?

**Penetration testing** (pentesting) is the practice of testing a computer network's security by simulating an attack — with the network owner's explicit permission. Professional pentesters are hired to find vulnerabilities *before* real attackers do.

Nightcrawler automates this process on a phone. It uses a small AI model (LFM2.5-1.2B-Instruct-Heretic, 1.2 billion parameters) running locally on the phone's GPU to decide what to do next — which host to probe, which tool to use, what to look for. No internet connection or cloud API required.

### How it works

1. **WiFi Breach** (optional) — If dropped without WiFi, it can autonomously crack WPA2 networks using an external USB WiFi adapter
2. **Reconnaissance** — Discovers devices on the network using stealthy scans
3. **Enumeration** — Probes discovered services (web servers, file shares, SSH, DNS, etc.)
4. **Exploitation** — Tests for known vulnerabilities and default credentials
5. **Reporting** — Generates a structured pentest report with findings and remediation advice

The agent operates like a patient human pentester — it rotates across hosts, does one small action per turn, and builds knowledge gradually over hours. This makes it much harder to detect than traditional vulnerability scanners that blast every host at once.

### Key concepts

| Term | What it means |
|------|--------------|
| **Drop box** | A device left on a target network to perform testing autonomously |
| **Scope** | The set of networks/hosts you're authorized to test |
| **Rules of Engagement (ROE)** | A legal document specifying what you're allowed to do |
| **Stealth** | Techniques to avoid detection by network monitoring (IDS/IPS) |
| **MCP** | Model Context Protocol — a standard interface for AI tool use |
| **C2** | Command and Control — the web dashboard for monitoring and steering the agent |

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   PHONE (OnePlus 8)                       │
│                                                           │
│  ┌─────────────┐     ┌──────────────────┐                │
│  │  LFM2.5     │     │  Agent Loop      │                │
│  │  1.2B model │◄───►│  (main.py)       │                │
│  │  on GPU     │     │  Decides what     │                │
│  │  (:8080)    │     │  to do next       │                │
│  └─────────────┘     └────────┬─────────┘                │
│                               │                           │
│                      ┌────────▼─────────┐                │
│                      │  Scope Proxy     │  ← Safety layer │
│                      │  Validates every │    Blocks out-  │
│                      │  command before  │    of-scope     │
│                      │  execution       │    actions      │
│                      └────────┬─────────┘                │
│                               │                           │
│                      ┌────────▼─────────┐                │
│                      │  Kali MCP Server │  ← Runs the    │
│                      │  nmap, curl,     │    actual       │
│                      │  smbclient, ...  │    commands     │
│                      └──────────────────┘                │
│                                                           │
│  ┌──────────────────┐  ┌──────────────────┐              │
│  │  Web Dashboard   │  │  SQLite DB       │              │
│  │  (:8888)         │  │  Hosts, vulns,   │              │
│  │  Monitor & steer │  │  creds, commands │              │
│  └──────────────────┘  └──────────────────┘              │
└──────────────────────────────────────────────────────────┘
```

For the full system design, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Features

- **Fully autonomous** — no human in the loop during operation
- **100% local inference** — AI runs on the phone's GPU, no cloud needed
- **Scope-enforced** — two-layer defense prevents out-of-scope actions
- **Stealth-first** — slow scan rates, host rotation, cover traffic, nmap -T2 only
- **27 exploit playbooks** — multi-step attack chains that execute automatically
- **24,956-entry CVE database** — version-aware vulnerability matching
- **Web dashboard** — real-time monitoring, host management, C2 controls
- **WiFi breach mode** — autonomous WPA2 cracking with USB adapter (Pwnagotchi-inspired)
- **Passive discovery** — background capture of mDNS/NBNS/DHCP/ARP broadcasts
- **Multi-network** — data isolated per network, survives DHCP changes via MAC-keyed hosts
- **Self-healing** — garbage detection, context reset, watchdogs, stuck detection
- **Training capture** — logs successful interactions for future model fine-tuning
- **Report generation** — downloadable pentest report with vulns, exploit chains, remediation

See [docs/FEATURES.md](docs/FEATURES.md) for the complete feature reference.

## Hardware

### Required
- **Android phone** with [Kali NetHunter](https://www.kali.org/docs/nethunter/) (tested on OnePlus 8, Snapdragon 865)
- **Root access** via [Magisk](https://github.com/topjohnwu/Magisk)
- **12GB+ RAM** (model uses ~1.3GB, Android uses ~4GB, rest for tools)

### Optional
- **USB WiFi adapter** for offline WiFi breach mode (Ralink RT3572 recommended)
- **Custom kernel** with MAC80211 for monitor mode ([build guide](docs/KERNEL_BUILD_PROMPT.md))
- **NVIDIA AGX** for offloading to a larger model over Tailscale

### GPU Performance

All inference via OpenCL on Adreno 650 GPU:

| Model | Quantization | Prompt Speed | Generation Speed |
|-------|-------------|-------------|-----------------|
| **LFM2.5-1.2B-Instruct-Heretic** (production) | Q8_0 | 115 tok/s | 13 tok/s |
| Qwen3.5-0.8B | Q8_0 | 30.5 tok/s | 6.3 tok/s |
| Qwen3.5-4B | Q4_0 | 10.1 tok/s | 2.0 tok/s |

> **Note:** Android throttles the GPU on battery power (6x slowdown). Nightcrawler includes a GPU governor daemon that forces max performance and auto-throttles at ≤15% battery.

## Quick Start

```bash
# 1. Install (inside Kali NetHunter chroot)
bash INSTALL.sh

# 2. Wait for llama-server to start (~5 min after boot)
curl -s http://127.0.0.1:8080/health  # Should return {"status":"ok"}

# 3. Start all services
bash scripts/run-36h.sh

# 4. Open the web dashboard (from any device on your Tailscale network)
# https://<your-tailscale-hostname>:8888
```

### Dry Run (no real commands executed)

```bash
NC_DRY_RUN=1 python3 main.py
```

This uses a mock Kali server so you can test the agent loop without executing real network commands.

### Manual Start (if not using tmux launcher)

```bash
kali-server-mcp --port 5000 &
python3 scope_proxy.py --config config.yaml --port 8800 --upstream http://127.0.0.1:5000 &
bash scripts/webui-daemon.sh start
python3 main.py &
```

## Configuration

Edit `config.yaml` before deployment:

```yaml
mission:
  id: "CLIENT-YYYY-XXX"           # Your engagement ID
  scope:
    networks: ["auto"]             # "auto" = detect from wlan0 at startup
    excluded_hosts: ["auto"]       # "auto" = gateway + self IP
    excluded_ports: [502, 503]     # SCADA/ICS ports to never touch
  authorization: "ROE-YYYY-XXX.pdf"
  max_runtime_hours: 0             # 0 = no limit

model:
  local:
    ctx_size: 8192
    port: 8080
```

**Dynamic scope detection** means zero config changes when moving between networks — the agent reads the current subnet from `wlan0` at startup.

## Project Structure

```
nightcrawler/
├── main.py                  # Entry point
├── config.yaml              # Mission scope + model config
├── scope_proxy.py           # Scope enforcement proxy
├── INSTALL.sh               # Installer
│
├── agent/                   # Core agent logic
│   ├── loop.py              # Decision loop + error recovery
│   ├── planner.py           # Phase state machine (recon → exploit)
│   ├── llm_client.py        # LLM API client (llama.cpp / remote)
│   ├── db.py                # SQLite backend (hosts, vulns, creds)
│   ├── host_memory.py       # Per-host observations + auto-tagging
│   ├── cve_db.py            # 24,956-entry CVE database
│   ├── attack_planner.py    # Strategic directives for exploit phase
│   ├── output_parser.py     # Extract structured data from tool output
│   ├── offline_manager.py   # WiFi breach pipeline state machine
│   ├── net_detect.py        # Auto-detect network from wlan0
│   ├── cover_traffic.py     # Stealth blending with realistic web traffic
│   ├── passive_capture.py   # Background tcpdump for broadcast traffic
│   └── ...
│
├── proxy/                   # Scope enforcement components
│   ├── scope.py             # IP/port/host validation
│   ├── rate_limiter.py      # Command rate limiting + jitter
│   └── command_filter.py    # Destructive command blocklist
│
├── webui/                   # Web dashboard (Flask)
│   ├── server.py            # API + stealth middleware
│   └── templates/index.html # Dashboard UI
│
├── data/                    # Static data files
│   ├── cve_exploits.json    # CVE→exploit command mappings
│   └── playbooks.json       # 27 multi-step attack playbooks
│
├── prompts/                 # LLM prompt templates (hot-reloadable)
├── scripts/                 # Operational scripts (start, stop, watchdogs)
├── tests/                   # Test suites (API, UI, offline mode)
├── kernels/                 # WiFi driver modules + kernel docs
├── simulation/              # Dry-run mock server
├── docs/                    # Architecture, GPU setup, features
├── logs/                    # Runtime data (gitignored)
└── models/                  # Model files (gitignored)
```

## How the Agent Thinks

The agent uses a simple but effective loop:

1. **Pick a target** — weighted random selection (70% hosts with known ports, 30% new discovery)
2. **Build context** — inject host memory, network observations, phase guidance into prompt
3. **Ask the LLM** — model produces `REASONING: ... COMMAND: ...`
4. **Validate** — scope proxy checks the command is in-scope and not destructive
5. **Execute** — command runs via Kali MCP server
6. **Learn** — output parser extracts findings, updates host memory
7. **Reset context** — clear conversation, keep persistent memory, repeat

The 1.2B model has a ~50% command success rate (inherent to its size). The agent compensates with:
- **Garbage detection** — 5-streak reset with varied few-shot examples
- **Duplicate detection** — forces tool/target diversification
- **Time-based stuck detection** — 5-minute backstop forces context reset
- **Direct playbook execution** — multi-step attacks bypass the LLM entirely

## Web Dashboard

The dashboard at `:8888` provides real-time monitoring and control:

- **Live feed** — every command, finding, and agent decision
- **Host cards** — clickable cards showing ports, services, vulnerabilities
- **Network map** — interactive force-directed graph (drag, zoom, pan)
- **Vulnerability details** — CVE tags, exploit chains, remediation steps
- **C2 controls** — star/blacklist hosts, force phase, pause/resume, inject commands
- **Offline mode** — Pwnagotchi-inspired WiFi attack UI with animated face

The dashboard is stealth-filtered: it spoofs nginx headers and returns empty 404s to connections from the target network.

## Tested Results

From 72+ hours of autonomous operation across multiple networks:

- **30+ hosts** discovered per network
- **2,000+ commands** executed autonomously
- **10+ vulnerabilities** found across multiple services
- **6+ playbooks** executed via direct execution
- Agent memory stable at 35-50MB throughout (no leaks)

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas where help is needed

- **Model fine-tuning** — improving command format compliance from ~50% to 85%+
- **New playbooks** — adding exploit chains for more services
- **CVE database** — expanding coverage beyond the current 24,956 entries
- **Adapter support** — testing with more USB WiFi chipsets
- **Documentation** — tutorials, setup guides for different phones
- **Testing** — more test coverage, especially for edge cases

### Development setup

```bash
# Clone the repo
git clone https://github.com/garagehq/nightcrawler.git
cd nightcrawler

# Dry-run mode (no real commands, no hardware needed)
NC_DRY_RUN=1 python3 main.py

# Run tests
python3 -m pytest tests/
```

## Legal

**This tool is for authorized penetration testing only.** You must have written permission (Rules of Engagement) from the network owner before deploying Nightcrawler. Unauthorized use against networks you don't own or have permission to test is illegal.

## License

MIT — see [LICENSE](LICENSE) for details.

## Support

If you enjoy this project, you can buy me a coffee ☕:

<a href="https://buymeacoffee.com/cyrilengmann" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50" width="210"></a>

> **[buymeacoffee.com/cyrilengmann](https://buymeacoffee.com/cyrilengmann)**
