# Nightcrawler — Feature Reference

Cross-referenced from `CLAUDE.md` (operational guide) and `docs/ARCHITECTURE.md` (system design).

## Exploit Pipeline

### CVE Database (`agent/cve_db.py` + `data/cve_exploits.json`)
- **24,956 entries** across 62 services, built from exploit-db CSV + manual curation
- Version-aware regex matching: "OpenSSH 9.2p1" → CVE-2024-6387 (regreSSHion)
- Returns ready-to-run commands, not just CVE IDs
- Replaces searchsploit entirely — instant lookups (2.3ms) vs slow CLI with wrong syntax
- 5.1MB on disk, ~50MB RAM, CPU-only
- Loaded once at startup, queried by hint system on every host selection

### Exploit Playbooks (`data/playbooks.json`)
- **27 multi-step attack sequences** triggered by host memory observations
- `repeatable: false` = one-and-done (recon/enumeration playbooks)
- `repeatable: true` = can retry up to 3 times (credential attacks)
- **Direct execution**: playbook steps bypass the LLM entirely — commands execute exactly as specified through the scope proxy, 2-3 seconds apart
- Completion persisted in SQLite (survives phone restarts)
- Template variables: `{ip}`, `{share}`, `{user}`, `{password}` (creds pulled from DB)
- Share names extracted from actual observations (not hardcoded)
- **Failed-cred filtering**: playbook steps skip credentials already in the failure list
- **Auto-tagging**: nmap output auto-tags hosts with service names (wordpress, tomcat, jenkins, snmp, ldap, smtp, rdp, nfs, mongodb, mssql, docker, ipmi, postgres, joomla, phpmyadmin) to trigger matching playbooks
- **Original 11**: smb_share_read, pihole_exploit, dns_zone_transfer, samba_deep, http_deep, vnc_attack, ssh_full_attack, telnet_attack, ftp_attack, redis_attack, mysql_attack
- **16 new (general-purpose)**: post_auth_ssh, snmp_enum, nfs_enum, ldap_enum, smtp_enum, wordpress_attack, mssql_attack, mongodb_attack, rdp_enum, ipmi_attack, docker_api, postgres_attack, http_tomcat, http_jenkins, http_phpmyadmin, joomla_enum
- All playbooks are safe: detection/enumeration/credential-testing only — nothing that crashes hosts

### Output Parser (`agent/output_parser.py`)
- Extracts structured intelligence from raw command output
- nmap vulners → CVE IDs → vulnerability DB + trigger CVE DB for next command
- smbclient ls → interesting files (.conf, .env, .bak) → host memory
- dig axfr → hostnames → new scan targets
- nxc [+] → credentials → DB + suggest post-exploit follow-up
- nikto → findings → vulnerability DB
- curl robots.txt → disallowed paths → suggest probing
- impacket-samrdump → usernames → suggest credential testing
- Service fingerprints → structured port→service cache in SQLite
- Checks for NT_STATUS errors before extracting (no false positives)

### Attack Planner (`agent/attack_planner.py`)
- Strategic directives injected into system prompt (cached, refreshed every ~50 commands)
- Identifies: no-follow-through hosts, untested SSH, unexplored ports
- Highlights confirmed access points and suggests priorities
- Answers: "Given everything we know, what should we focus on?"
- The 1.2B model can't strategize — the planner strategizes for it

### Per-Host Failed Command Tracking
- Records failed commands per host — injected as "DO NOT retry" hints in LLM system prompt
- Prevents the 1.2B model from repeating the same failed approach on a host
- Complements host memory observations with explicit negative feedback

### Vulnerability Dedup
- Uses **40-character prefix match** for deduplication — catches near-identical findings with minor wording differences
- Prevents DB bloat from repeated scans finding the same issue

### Smart Host Targeting
- **Priority weighting**: high (60%) for confirmed access, medium (30%) untested, low (10%) failed, exhausted (0%) for 5+ failures
- **Priority recalculated every turn** from live host memory — self-correcting as failures accumulate
- **Failure memory**: records every failed credential attempt (e.g., "FAILED SSH admin:admin")
- **VNC failure detection**: handles empty output from nxc vnc (writes to stderr) — treats empty output as failure
- **Failed cred filtering**: hints AND playbook steps skip already-failed credentials per-password
- **Untried tool boost**: impacket/nikto/gobuster get 80% selection probability when never tried
- **Tried-action dedup**: records searchsploit/axfr/enum4linux/nikto/impacket attempts, hints filter them out
- **Multi-turn mode**: 2-3 consecutive commands on high-priority hosts without rotation
- **Playbook completion**: persisted in SQLite, marked done on queue empty OR context reset
- Max 30 observations per host (auto-prunes old agent observations)
- Access indicators tightened: "has SSH open" ≠ confirmed access, only actual findings (shares, Pi-hole, Samba version, dnsmasq)

### Exploit Chain Tracking
- Vulnerabilities stored with `chain` column: the sequence of commands that found them
- Example: "smbclient -N -L //<target_host>/ → shares: share, nobody"
- Used in report generation to show clients how to reproduce/patch

## Pipeline Validation

Commands pass through 6 validation gates before execution:
1. **Dead-end skip**: hosts marked dead-end in host_memory are skipped
2. **Same-host enforcement**: rejects if target IP == last executed IP (unless multi-turn)
3. **_is_valid_command()**: rejects fake paths, placeholders, -T3+, missing target IP
4. **_is_duplicate()**: exact match against last 5 commands + DB history check (6h window, blocks 3rd repeat of same command)
5. **_dedup_ports()**: cleans duplicate ports in nmap -p lists
6. **Time-based stuck detection**: 5min without a command = force context reset

All rejection paths increment `garbage_streak`. At streak 5, `_reset_context_with_fewshot()` fires — including the validation rejection path (fixed: was missing reset trigger, caused infinite rejection loops).

### Context Reset (Varied Few-Shot)
- On streak 5: clears context, injects a concrete example on a random host
- **Port-matched examples**: picks SSH/DNS/HTTP/nmap examples based on target host's actual open ports
- Prevents tool fixation (e.g., model stuck generating smbclient for hosts without port 445)
- Key insight: don't silently reject the 1.2B model's commands — let them fail naturally so the model gets real feedback. Silent rejection loops are worse than wasted turns.

## Web UI & C2

### Dashboard (`:8888`)
- Separate process from agent (agent/ui_bridge.py writes to SQLite, webui reads)
- Stealth middleware: rejects connections from target network, allows localhost + Tailscale
- **Foreign network detection** uses CIDR matching (not string prefix) for accurate subnet comparison
- Server header spoofed as "nginx" — blue team scanners see dead-looking nginx
- Responsive: ~90ms API calls (was 10s+ when in-process with agent)
- **Mobile responsive**: no horizontal overflow (tested with Playwright at 375x812)
- **Mobile tab navigation**: ALL/FEED/HOSTS/VULNS/INTEL tabs for panel switching on small screens
- **Host sparklines**: 24h activity dots on each host card showing recent command activity
- **Success rate widget**: displayed in findings bar alongside vuln/cred counts
- **Agent health indicator**: green/red dot showing agent process status in real-time

### C2 Controls
- Star/blacklist hosts, force phase, pause/resume, kill switch
- **Agent pause/unpause button**: saves GPU power, agent-watchdog respects pause file (`/tmp/nc-agent-pause`)
- Command injection, tool preferences, config panel
- Host memory editing, network observations

### Network Map Visualization
- Toggle between list view and interactive network map via MAP VIEW button on Discovered Hosts panel
- **Force-directed layout**: nodes self-organize with repulsion physics, gateway at center
- **Draggable nodes**: click and drag any host to reposition; pinned after manual move
- **Zoom**: scroll wheel to zoom in/out (30%-300%), zoom indicator in footer
- **Pan**: shift+drag to pan the entire map view
- **Double-click**: reset zoom, pan, and all node positions to default layout
- **Host icons**: type-specific text badges (SRV/WEB/DNS/SSH/SMB/TEL/VNC/DB/H/?)
- **Color coding**: by service type, red glow for hosts with vulnerabilities
- **Click any host**: modal popup with full details — IP, MAC, ports, services, vulnerabilities with remediation, last 10 observations
- **Vuln badges**: hosts with findings show count above their icon
- **Port badges**: port count below each host
- **No external packages**: 100% vanilla Canvas API — works fully offline
- **Mobile responsive**: tested at 375x812 viewport, all panels accessible
- Physics auto-stops after 3s to save battery/CPU
- Responsive: re-renders on data updates, preserves user-positioned nodes

### Agent Feed (Per-Network, Paginated)
- Feed entries tagged with `network_id` when created — switching networks filters the feed
- Displays last 200 entries, count shows "200+" when more exist
- **Reverse pagination**: scrolling to the top loads 100 more older entries
- "Load more" sentinel at top shows remaining count, removed when all loaded
- Scroll position preserved after loading older entries
- Auto-scrolls to bottom on page load and when new entries arrive (if near bottom)

### Throughput Timeline
- Real-time bar chart showing commands-per-hour over the last 48 hours
- Color-coded: bright green (>15 cmd/hr), mid green (>5), dim green (>0), dark (0)
- **Cover traffic bars**: purple bars stacked with green offensive bars
- Hover/touch shows cmd/hr count + time (EDT) per bar
- Current rate displayed in panel header
- Polls `/api/throughput` every 10 seconds

### Command History Filtering
- Filter by tool type (nmap, nxc, smbclient, curl, dig, gobuster, nikto, hydra, impacket)
- Filter by status (success, error, blocked)
- Text search combines with filters
- Replaces the old search-only interface

### Passive Capture Panel
- **Clickable cards** — click any finding to expand and see: IP, MAC, hostname, protocol, network classification
- **Foreign network detection** — highlights IPs from non-target subnets (10.x, 172.16-31.x, other 192.168.x) with red alert badges
- **Pivot analysis** — expanded cards on foreign IPs show guidance: "Possible dual-homed host — investigate for pivot opportunities"
- CAPTURE button to start a 2-minute capture on demand
- Color-coded by type: cyan (mDNS), green (ARP), yellow (NBNS)
- Foreign networks auto-recorded as HIGH severity vulns with exploit chains
- Polls `/api/passive/results` every 15 seconds

### Report Generation (`/api/report`)
- REPORT button downloads formatted pentest report
- Includes: executive summary, vulnerabilities with exploit chains, remediation advice, credentials, host inventory
- Auto-generated remediation per finding type (SMB null session → disable anonymous access, etc.)
- Severity breakdown: critical/high/medium/low counts

### Credential Management
- **Separate panel** from vulnerabilities in the web UI
- **+ ADD button**: manually enter known credentials (service, username, password, host or generic)
- **Delete button (X)**: remove invalid/non-working credentials — agent stops trying them
- **Network-scoped**: credentials tagged with network_id, filtered by selected network
- **Agent integration**: analyst-added credentials prioritized in credential spray hints
- **Host-specific or generic**: assign to a specific IP or leave empty for any host on the network
- API: `POST /api/credentials` (add), `DELETE /api/credentials/<id>` (remove)

### Vulnerability Tracking
- Auto-recorded from command output (SMB shares, Pi-hole, NSE VULNERABLE, nxc [+])
- Deduplication: same host+vuln won't double-insert
- **Clickable vuln cards** in web UI — click to expand and see:
  - Full finding description with CVE tags
  - Exploit chain (exact commands that found the vuln)
  - Remediation steps (numbered, specific to the finding type)
  - CVE references as clickable badges
  - Discovery timestamp
- **CVE tagging**: findings auto-tagged with relevant CVEs (e.g., Pi-hole → CVE-2020-8816, CVE-2021-29449; SMB null session → CVE-2017-7494; OpenSSH → CVE-2024-6387)
- **[MISCONFIG] prefix**: configuration issues distinguished from software vulnerabilities
- **Detailed remediation**: 3-4 step fix instructions per finding type, with vendor-specific config changes
- API: `GET /api/vulnerabilities/<id>` returns full detail with CVEs and remediation
- Exported in reports with exploit chains

## Report Generation (`scripts/generate-report.py`)
- Generates markdown penetration test report from SQLite findings
- Deduplicates near-identical vulnerabilities before output
- Sorted by severity (CRITICAL → HIGH → MEDIUM → LOW)
- Each vulnerability includes: finding, CVEs, exploit chain (code block), numbered remediation steps, discovery timestamp
- Timestamps converted from UTC to EDT
- Host inventory with port-to-service name mapping
- Executive summary with severity breakdown and immediate action callout
- Cron-scheduled: auto-generates every 3 hours via Claude Code cron
- API: `GET /api/report` returns JSON, script outputs markdown

## Training Data Capture (`agent/training_capture.py`)
- Captures successful agent interactions for model finetuning
- Format: JSONL with ChatML, per-day per-phase files (e.g., `train_2026-03-22_exploit__pivot.jsonl`)
- Captures: system prompt, messages, assistant response, command, output, return code
- Only successes — garbage, errors, and empty outputs excluded
- 700+ examples captured across recon/enumerate/exploit phases
- API: `GET /api/training/stats`, `GET /api/training/eval` (format compliance, tool coverage)
- Storage: `training_data/` with 20GB budget

## Agent Watchdog (`scripts/agent-watchdog.sh`)
- External process that monitors agent log file freshness
- If agent log hasn't been updated in 40 minutes → process is hung → kills and restarts
- Also restarts if agent process is not running at all
- **Feed entry on restart**: pushes notification to agent feed when watchdog restarts the agent
- **Respects pause file**: checks `/tmp/nc-agent-pause` before restarting (maintenance/offline mode)
- Checks every 60 seconds
- Logs to `/tmp/nc-agent-watchdog.log`
- Integrated into `scripts/run-36h.sh` tmux session (window 4)
- Complements internal recovery (5-min stuck detector) — catches hard hangs

## Structured Agent Log
- **Plaintext structured log**: `/tmp/nc-agent-structured.log` — machine-parseable log format
- Complements the existing debug log with structured fields for monitoring and analysis

## Cover Traffic (`agent/cover_traffic.py`)
- **Stealth blending**: generates realistic web traffic to hide offensive activity on the network
- **Sliding scale**: COVER slider (0-100%) in control bar — 0% = current offensive-only throughput
- **85% default**: ~12-20 cover requests/min mixed with ~2-3 offensive commands/min
- **Pre-generated content**: 30 popular websites (Google, Instagram, YouTube, Reddit, Amazon, etc.), 40+ search queries, 10 API-like traffic patterns
- **LLM-generated queries**: 10-15% of searches use the 1.2B model for realistic random topics (high temperature for variety)
- **Realistic headers**: Chrome/Android User-Agent, proper Accept headers, follows redirects
- **Purple throughput bars**: cover traffic shown in purple on the throughput timeline, stacked with green offensive bars
- **Separate audit panel**: "COVER TRAFFIC" section at bottom of UI — not in agent feed, command history, or reports
- **Screen detection**: pauses cover traffic when phone display is on (user is using the phone)
- **Operating hours**: stops during off-hours (respects the operating hours config)
- **Low RAM**: uses curl (not a browser) — ~0 MB additional RAM
- **Natural jitter**: ±30% timing variation on requests to avoid machine-like patterns
- API: `GET/POST /api/cover-traffic`, `GET /api/cover-traffic/log`, `GET /api/cover-traffic/throughput`

## Operating Hours (`CONFIG > Operating Hours`)
- Set active hours for the agent (e.g., 7:00-23:00 EDT)
- Agent sleeps during off-hours — no active scanning or command execution
- Passive capture continues during off-hours (zero stealth cost)
- Throughput timeline shows 0 cmd/hr during sleep windows
- Configurable via web UI (CONFIG button) or API: `POST /api/operating-hours`
- Supports overnight wrapping (e.g., 22:00-06:00)
- Use case: operations that prohibit after-hours scanning

## Host Discovery
- **Seed sweep**: `nmap -sn` at agent startup, upserts all discovered hosts to SQLite DB
- **Periodic re-sweep**: every ~200 commands, discovers new hosts that joined the network
- **Passive capture**: background tcpdump for mDNS/NBNS/DHCP/ARP (zero stealth cost)
- **ARP scan**: `arp-scan -l -I wlan0` discovers hosts invisible to ICMP/TCP probes (5% hint probability)
- All discovered hosts immediately persisted to DB with correct `network_id`

## Self-Healing & Error Recovery
- **5-min stuck detector**: forces context reset if no command produced in 5 minutes
- **Garbage streak reset**: after 5 consecutive garbage/empty/invalid outputs, full context reset with varied few-shot
- **LLM-down backoff**: exponential delay (10s→60s) when 20+ consecutive empty responses detected
- **Consecutive error handling**: 2-30s retry delays, full reset at 8 errors, 60s cooldown
- **Agent watchdog**: external 40-min hang detection + process restart (with pause file for maintenance)
- **llama-server watchdog**: random 1.75-2.5h refresh cycle, crash detection, PID file enforcement
- **GPU governor**: prevents battery power throttling from killing inference speed

## Boot Sequence (`scripts/service.sh` → `scripts/autostart.sh`)
- **10 min total boot time** (was 25 min): +2min early detect, +5min llama-server, +8min Kali services
- **`autostart.sh` standalone script**: extracted from inline busybox subshell (busybox subshells silently fail)
- **Boot log delimiter**: `========== BOOT <date> ==========` in autostart log for easy log parsing
- **Stale pause file cleanup**: clears leftover pause files from previous boot when device is online
- **Early offline detection** at +2min: checks USB adapter + WiFi, creates pause files if needed
- **3 boot modes**:
  - **Online** (WiFi connected, no USB adapter): all services + agent + agent-watchdog
  - **Offline** (USB WiFi adapter detected): webui + mcp + proxy only (no agent, no llama)
  - **Disconnected** (no WiFi, no USB adapter): webui only

## Passive Network Capture (`agent/passive_capture.py`)
- Background tcpdump captures broadcast traffic (mDNS, NBNS, DHCP, ARP) — zero stealth cost
- Runs automatically every ~50 commands (uses total_commands, persists across restarts)
- Discovers hostnames, MAC-to-IP mappings, NetBIOS names from passive observation
- Parsed via tshark, ingested into host memory as observations
- API: `POST /api/passive/start`, `GET /api/passive/results`

## Credential Spray from Found Data (`agent/recon_tools.py`)
- Harvests usernames from impacket-samrdump output, RID brute results, DNS hostnames
- Generates credential spray hints using discovered usernames (not just hardcoded defaults)
- Filters against already-failed credentials per host
- Integrated into `_exploit_hint` fallback chain

## HTTP Content Analysis (`agent/recon_tools.py`)
- Parses HTTP response bodies for intelligence
- Extracts: login forms (POST targets), web frameworks (WordPress/Joomla/Drupal/Tomcat/Jenkins)
- Finds internal IPs in HTML, developer comments, API endpoint paths
- Auto-tags hosts with detected frameworks to trigger matching playbooks
- Runs on every curl response in `auto_extract_observations`

## Network Topology & Attack Paths (`agent/report_generator.py`)
- Topology: groups hosts by service type (SSH, SMB, web, DNS)
- Attack path analysis: builds narratives per host from combined findings
- Risk scoring: ranks hosts by severity of combined vulnerabilities
- API: `GET /api/topology`
- Finetuning evaluation: `GET /api/training/eval` — format compliance stats, tool coverage

## ARP Scan, Banner Grab & UDP Scanning (`agent/recon_tools.py`)
- **ARP scan**: `arp-scan -l -I wlan0` discovers hosts invisible to ICMP/TCP probes (5% hint probability)
- **Banner grab**: `nc -w 3 -v host port` fingerprints unknown/non-standard services
- **UDP scanning**: `nmap -sU -T2 --top-ports 10` discovers SNMP (161), TFTP (69), NTP (123) (8% hint probability)
- All are quiet techniques that complement active TCP scanning

## GPU Power Governor (`scripts/gpu-governor.sh`)
- Android throttles Adreno 650 GPU ~6x on battery (587→305MHz GPU clock)
- Governor override forces `performance` mode via sysfs — full GPU clock regardless of charging state
- Auto-reverts to `msm-adreno-tz` (power-saving) at ≤15% battery to prevent phone death
- Checks battery level every 60s
- Integrated into Magisk watchdog block — starts at boot before llama-server
- Logs: `/data/local/tmp/var/log/gpu-governor.log`

## Security

### Port Binding
| Port | Service | Binding | Exposure |
|------|---------|---------|----------|
| 8080 | llama-server | 127.0.0.1 | Localhost only |
| 5000 | kali-mcp | 127.0.0.1 | Localhost only |
| 8800 | scope-proxy | 127.0.0.1 | Localhost only |
| 8888 | webui | 0.0.0.0 | Stealth filtered (localhost + Tailscale only) |
| 8022 | Kali SSH | 127.0.0.1 + Tailscale | Invisible on target network (was port 22) |
| 9022 | Android SSH | 127.0.0.1 + Tailscale | Invisible on target network, pubkey-only |

### Stealth
- nmap timing enforced: -T2 only (never -T3+)
- Patient rotation: one action per host per turn
- Host rotation: same-host enforcement prevents scanning bursts
- Web UI spoofs nginx headers, returns empty 404 to target network

### Toast Notifications
- Success/info/warning toasts for destructive operations (network delete, agent restart)
- Auto-dismiss after 5 seconds with progress bar
- Stacked: multiple toasts don't overlap
- Green (success), blue (info), orange (warning) color coding

## Dynamic Network Detection (`agent/net_detect.py`)
- Auto-detects subnet, prefix, our IP, gateway from `wlan0` interface
- Supports 192.168.x, 10.x, 172.16-31.x — any private network
- `config.yaml` uses `networks: ["auto"]` and `excluded_hosts: ["auto"]`
- All components import from `net_detect` instead of hardcoding IPs
- 60-second cache for performance (avoids re-running `ip addr` every call)
- Scope proxy auto-configures scope from wlan0 if config says "auto"
- Auto-excludes gateway (.1) and self IP from scope
- Used by: scope_proxy, agent loop, passive capture, webui stealth filter

## Offline WiFi Mode (`agent/offline_manager.py`)
Pwnagotchi-inspired autonomous WiFi attack pipeline. Transforms the UI when device is offline.

### Pipeline Stages
1. **SCANNING** (manual) — User clicks SCAN, external USB adapter discovers networks
2. **SELECTING** (manual) — User clicks a network, confirms Rules of Engagement
3. **CAPTURING** (auto) — Starts immediately after target selection. airodump-ng + stealth deauth (13.5 min cycles, 1-frame targeted only)
4. **CRACKING** (auto) — Starts immediately when handshake captured. aircrack-ng CPU at ~310k keys/sec
5. **CONNECTING** (auto) — Starts immediately when password found. If connection fails, retries from CAPTURING
6. **ONLINE** — Auto-transition to pentest mode, agent + LLM auto-restart

Only steps 1 and 2 require user interaction. The rest is fully autonomous.

### UI (Offline Mode)
- Amber/orange theme (vs green online)
- Animated Pwnagotchi face — drifts side-to-side, blinks, stage-specific expressions, thought bubbles
- WiFi network cards with signal bars, encryption, channel, client count
- Handshake monitor panel (target, deauth count, capture status)
- Cracking progress bar with speed, ETA, candidates
- WiFi attack log (color-coded feed)
- Captured handshakes list with .cap download for exfiltration
- Adapter status indicator (green check when detected, red X when missing)
- Online panels (vulns, creds, cover traffic, etc.) hidden in offline mode

### Capture Engine
- **RT3572 primary adapter** with full injection + PMKID capture via hcxdumptool (60s handshake vs 2hr+ with RTL8821CU deauth)
- **Alternating 13.5min capture cycles**: hcxdumptool PMKID (primary) / airodump-ng + deauth (fallback) — cycles alternate methods for maximum capture probability
- **airodump-ng fallback** for adapters without PMKID support (RTL8821CU)
- **Sibling AP detection**: discovers APs with same SSID but different BSSID — deauths both to maximize handshake capture
- **Broadcast deauth fallback**: when no clients discovered on target AP, sends broadcast deauth instead of skipping
- **hcxdumptool retry loop**: 3 attempts with status updates to feed on each retry
- Stealth deauth: 1 frame per client, targeted only (never broadcast unless no clients), 2 min cooldown, max 3 per cycle
- Auto-cycles: 10s pause between cycles, repeats until handshake captured
- UI shows active capture with pulsing indicator + cycle count
- Auto-detects adapter unplug → stops capture → transitions to online mode

### Hash Conversion Pipeline
- pcapng → 22000 (hcxpcapngtool) → BSSID filter → pcap (hcxhash2cap) → aircrack-ng
- Filters captured hashes by target BSSID before cracking — no wasted cycles on neighbor APs
- Handles both hcxdumptool (pcapng) and airodump-ng (cap) capture formats

### Cracking
- aircrack-ng CPU at ~310k keys/sec (GPU not worth the complexity)
- Uses all available wordlists: wifite defaults + rockyou (14.5M passwords total)
- **Cracked passwords persist** in SQLite — survive reboots, crashes, and agent restarts
- **Previously cracked networks auto-resume**: selecting a network with a known password skips capture/crack, goes straight to connect

### Connection
- Connects via **Android shell** (`cmd wifi connect-network`) — not chroot wpa_supplicant
- Executed over SSH to Android side (`ssh -p 9022 shell@127.0.0.1`)
- Auto-transitions to online pentest mode on successful connection (agent + LLM restart)

### Handshake Management
- Download captured handshake files (.cap) for offline analysis
- Delete handshakes and re-run capture on a target
- Copyable passwords from crack results
- Manual offline/online toggle button in UI header

### Hardware Requirements
- **External USB WiFi adapter** — internal QCA6390 cannot do monitor mode
- **Primary: Ralink RT3572 (148f:3572)** — full injection + PMKID via hcxdumptool
  - Driver: `rt2800usb.ko` (+ rt2x00lib, rt2x00usb, rt2800lib), requires `firmware-misc-nonfree` (rt2870.bin)
- **Secondary: Edimax AC600 (7392:d811, RTL8821CU)** — NOT RTL8811AU as commonly listed
  - Driver: `8821cu.ko` (morrownr fork), 55 networks in 15s, 2.4GHz + 5GHz, no PMKID
- Also works: Edimax N150 (7392:b811, RTL8188EUS) — `8188eu.ko`, 28 networks in 15s
- Custom kernel (4.19.297-perf-g8228d522e928-dirty) with MAC80211=y, MODULE_SIG/MODVERSIONS disabled
- Kernel source: https://github.com/garagehq/kernel_oneplus_sm8250_nethunter
- Auto-detect: plugging in adapter auto-loads driver + enters offline mode

### API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/offline/state` | Full pipeline state + auto-detect |
| POST | `/api/offline/scan/start` | Start WiFi scanning |
| POST | `/api/offline/scan/stop` | Stop scanning |
| GET | `/api/offline/networks` | Discovered WiFi networks |
| POST | `/api/offline/target` | Select target (ROE required) |
| POST | `/api/offline/capture/start` | Start handshake capture |
| POST | `/api/offline/capture/stop` | Stop capture |
| GET | `/api/offline/handshakes` | Captured handshakes list |
| POST | `/api/offline/crack/start` | Start aircrack-ng |
| POST | `/api/offline/crack/stop` | Stop cracking |
| GET | `/api/offline/crack/status` | Progress, speed, ETA |
| POST | `/api/offline/connect` | Connect to cracked network |
| GET | `/api/offline/adapter` | Check USB adapter status |
| GET | `/api/offline/capture/<file>` | Download .cap file |

### Testing
- `tests/test_offline_api.py` — 60 API tests (full sim pipeline)
- `tests/test_offline_ui.py` — 38 Playwright UI tests (panels, transitions)
- Simulation mode: `POST /api/offline/simulate {"enabled": true}`

### Persistent Logging
- `logs/offline.log` — timestamped file log (commands, stage transitions, errors)
- SQLite: `offline_state` and `wifi_feed` keys persist across restarts
- `wifi_networks` and `wifi_handshakes` tables for scan results and captures

## Network Data Isolation
- All data (hosts, vulns, creds, commands, feed) tagged with `network_id`
- Network selector in UI filters all panels by selected network
- `add_vulnerability()` and `add_credential()` auto-detect network from host IP
- Feed entries tagged per-network, filtered on display
- No cross-pollination: selecting "Home Lab" shows only Home Lab data
- **Network deletion**: `DELETE /api/networks/<id>` permanently removes all associated data
  - Triple-confirmation in UI (confirm dialog + second confirm + type network name)
  - Auto-kills running agent process before deletion
  - Pauses agent watchdog via `/tmp/nc-agent-pause` file during delete
  - Clears per-network feed entries from both SQLite and in-memory state
  - Deletes: hosts, vulnerabilities, credentials, commands, network record
  - 2-minute delayed agent restart after deletion completes
  - Toast notifications: success, watchdog pause info, restart warning
  - For client privacy: after report delivery, delete engagement data

## Thor Export (`/api/export`)
- Full data export for NVIDIA AGX Thor consumption
- Includes: hosts, timeline, commands, host memories, vulns with remediation, credentials
- **Enriched with**: attack paths, network topology, passive capture findings
- All vuln entries include remediation text for Thor-side report generation
- API: `GET /api/export` or `GET /api/export/<network_id>`

## Testing (`tests/test_webui.py`)
- Playwright-based end-to-end UI tests (60 test cases)
- Desktop tests: all panels, vuln/host/passive card expansion, map interactions (zoom/pan/drag/reset), credential CRUD
- Mobile tests: 375x812 viewport — page load, all panels visible, map toggle, touch interactions
- Tests: panel existence, data population, vuln card expansion/collapse, CVE tags, remediation display, exploit chains, host card expansion, throughput chart, command filtering, passive capture button, control bar, all API endpoints
- Run: `python3 tests/test_webui.py`
- Requires: `pip3 install playwright && python3 -m playwright install chromium`

## Deferred to Thor (`docs/THOR_DEFERRED.md`)
- Full NVD/Vulners offline mirror (too much RAM for phone)
- Thinking/reasoning mode for exploit planning (1.2B token budget too small)
- Complex metasploit integration (msfconsole syntax too complex for 1.2B)
