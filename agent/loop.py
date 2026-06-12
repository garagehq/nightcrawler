"""Core agent decision loop."""

import asyncio
import re
import time

from agent.llm_client import LLMClient
from agent.planner import PhasePlanner
from agent.context import ContextManager
from agent.watchdog import Watchdog
from agent.mission_log import MissionLog

from agent import db
from agent import host_memory
from agent import training_capture
from agent import cve_db
from agent import output_parser
from agent import attack_planner
from agent import recon_tools

try:
    from agent.ui_bridge import update_state, push_feed
except ImportError:
    def update_state(u): pass
    def push_feed(t, c): pass

try:
    from agent import structured_log
except ImportError:
    structured_log = None


# Match any IPv4 address (private or public). Used wherever we need to
# extract target IPs from a command for dedup/dead-end/recent-IP logic.
# Previously these spots had a hardcoded `192\.168\.1\.\d+` regex which
# broke on every other network the agent runs on.
_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


class AgentLoop:
    """Main decision engine — calls LLM, executes commands through proxy."""

    MAX_CONSECUTIVE_ERRORS = 8
    RETRY_DELAYS = [2, 3, 5, 8, 10, 15, 20, 30]
    HEARTBEAT_INTERVAL = 10
    STUCK_TIMEOUT_SEC = 300  # 5 min without a command = stuck

    def __init__(self, config: dict, llm_client: LLMClient,
                 proxy_url: str, ui):
        self.config = config
        self.llm = llm_client
        self.proxy_url = proxy_url
        self.ui = ui
        self.context = ContextManager(max_tokens=6000)
        self.planner = PhasePlanner(config)
        self.mission_log = MissionLog(
            config.get("logging", {}).get("dir", "logs")
        )
        self.watchdog = Watchdog(0)  # uptime tracker only, no expiry
        self.consecutive_errors = 0
        self.garbage_streak = 0
        # Separate counter — garbage_streak gets reset to 0 every time the
        # LLM produces parseable output (which it does even when targeting
        # the wrong host), so same-host rejections never accumulate via that
        # path. Track them independently and force a context reset at 3.
        self.same_host_streak = 0
        self.recent_commands = []  # last N commands for dup detection
        self.last_executed_ip = ""  # for same-host enforcement
        self.last_command_time = time.time()  # for time-based stuck detection
        self.multi_turn_remaining = 0  # allow consecutive cmds on same host
        self.multi_turn_ip = ""
        self.active_playbook = None  # current playbook steps
        self.playbook_step = 0
        self.playbook_queue = []  # direct-execute queue (bypasses LLM)
        self.playbook_queue_ip = ""
        self.playbook_queue_mac = ""
        self.playbook_queue_id = ""
        self.iteration = 0
        self.total_commands = 0
        self.total_blocked = 0
        self.total_garbage = 0

        # Detect current network — only suggest hosts on THIS network.
        # Use ipaddress CIDR containment instead of .startswith() so that
        # networks larger than /24 (like /23, /22) are matched correctly.
        self.current_network_id = ""
        self._detect_current_network()

    def _detect_current_network(self):
        """Find the DB network_id whose CIDR contains our wlan0 IP."""
        try:
            import subprocess as _sp
            import ipaddress as _ip
            _r = _sp.run(["ip", "-4", "addr", "show", "wlan0"],
                         capture_output=True, text=True, timeout=5)
            _m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', _r.stdout)
            if not _m:
                return
            our_ip = _ip.ip_address(_m.group(1))
            for _n in db.get_networks():
                cidr = _n.get("cidr", "")
                if not cidr or cidr == "auto":
                    continue
                try:
                    if our_ip in _ip.ip_network(cidr, strict=False):
                        self.current_network_id = _n["network_id"]
                        return
                except ValueError:
                    continue
        except Exception:
            pass

    def _get_hosts(self):
        """Get hosts filtered to current network only.
        Returns [] (not all hosts) when network isn't detected — otherwise
        the agent would target hosts from previous networks.
        """
        if self.current_network_id:
            return db.get_hosts(network_id=self.current_network_id)
        return []

    async def run(self):
        """Main loop — runs until mission complete or killed."""
        self.ui.render_boot_complete()
        self.watchdog.start()

        # Initialize structured log
        try:
            if structured_log:
                structured_log.init()
        except Exception:
            pass

        # Kick off continuous passive capture at boot. On client-isolated
        # networks (hotel/guest WiFi), broadcast traffic is the only reliable
        # discovery signal — DHCP renewals, mDNS announcements, ARP requests
        # happen on their own schedule, so we need to listen continuously
        # rather than running short 2-min windows every ~50 commands (which
        # often never fires if the agent runs few commands).
        try:
            from agent.passive_capture import start_continuous
            start_continuous(interface="wlan0", cycle_seconds=300)
            push_feed("phase", "Continuous passive capture started (5-min cycles)")
        except Exception:
            pass

        # Phase-aware few-shot seed
        from agent.planner import Phase

        # Auto-detect current subnet for seed commands
        from agent.net_detect import get_current_network as _gcn
        _subnet, _seed_prefix, _our_ip, _gw_ip = _gcn()
        _seed_subnet = _subnet
        # _seed_prefix already set by _gcn() above
        try:
            import subprocess as _sp
            _r = _sp.run(["ip", "-4", "addr", "show", "wlan0"],
                         capture_output=True, text=True, timeout=5)
            _m = re.search(r'inet (\d+\.\d+\.\d+)\.(\d+)/(\d+)', _r.stdout)
            if _m:
                _seed_prefix = _m.group(1) + "."
                _seed_subnet = f"{_m.group(1)}.0/{_m.group(3)}"
        except Exception:
            pass

        if self.planner.current_phase <= Phase.RECON:
            # RECON: teach nmap scanning on CURRENT network
            self.context.append_user("Scan the network.")
            self.context.append_assistant(
                f"REASONING: Ping sweep for live hosts.\n"
                f"COMMAND: nmap -sn -T2 {_seed_subnet}"
            )
            # Run REAL discovery sweep — ARP scan first (more reliable on
            # client-isolated networks where ICMP is silently dropped), then
            # nmap to catch anything ARP missed. Both results merged into DB.
            try:
                import subprocess
                arp_hosts = recon_tools.run_arp_scan(interface="wlan0", timeout=15)
                arp_ips = []
                for h in arp_hosts:
                    arp_ips.append(h["ip"])
                    try:
                        db.upsert_host(
                            h["ip"], ports=[], mac=h["mac"],
                            info=f"Discovered via ARP scan ({h.get('vendor','')})".strip(),
                        )
                    except Exception:
                        pass
                if arp_hosts:
                    push_feed("result",
                              f"ARP scan: {len(arp_hosts)} hosts on {_seed_subnet} "
                              f"(layer-2, bypasses IP filtering)")
                    # On a client-isolated network ARP reveals a small,
                    # authoritative host count. If we find very few hosts
                    # via ARP across the full subnet, mark recon exhausted
                    # so the planner can advance to ENUMERATE instead of
                    # spinning RECON forever trying to find hosts that
                    # don't exist from our vantage point.
                    if len(arp_hosts) <= 5 and self.current_network_id:
                        try:
                            _exh = db.get_state("recon_exhausted_per_net", {})
                            _exh[self.current_network_id] = True
                            db.set_state("recon_exhausted_per_net", _exh)
                            push_feed("phase",
                                      f"Recon exhausted: only {len(arp_hosts)} "
                                      f"hosts reachable. Pivoting to ENUMERATE.")
                        except Exception:
                            pass
                sweep = subprocess.run(
                    ["nmap", "-sn", "-T3", "--max-retries", "1", _seed_subnet],
                    capture_output=True, text=True, timeout=30,
                )
                import re as _re
                live_ips = _re.findall(
                    r'Nmap scan report for (' + _seed_prefix.replace('.', r'\.') + r'\d+)', sweep.stdout
                )
                # Merge: arp_ips + live_ips (dedup, keep order)
                _seen = set()
                merged = []
                for _ip in arp_ips + live_ips:
                    if _ip not in _seen:
                        _seen.add(_ip)
                        merged.append(_ip)
                live_ips = merged
                # Auto-detect excluded hosts
                excluded = set()
                _cfg_excluded = self.config["mission"]["scope"].get("excluded_hosts", [])
                if _cfg_excluded == ["auto"] or "auto" in _cfg_excluded:
                    excluded.add(_seed_prefix + "1")  # gateway
                    if _m:
                        excluded.add(f"{_m.group(1)}.{_m.group(2)}")  # self
                else:
                    excluded = set(_cfg_excluded)
                live_ips = [ip for ip in live_ips if ip not in excluded]
                sweep_summary = f"{len(live_ips)} hosts up: " + ", ".join(live_ips[:15])
                if len(live_ips) > 15:
                    sweep_summary += f" (+{len(live_ips)-15} more)"
                # Upsert ALL discovered hosts into DB so agent can rotate
                for _lip in live_ips:
                    try:
                        db.upsert_host(_lip, ports=[], info=f"Discovered via ping sweep")
                    except Exception:
                        pass
                if live_ips:
                    push_feed("result", f"Sweep: {len(live_ips)} hosts discovered on {_seed_subnet}")
            except Exception:
                sweep_summary = f"4 hosts up: {_seed_prefix}2, {_seed_prefix}10, {_seed_prefix}15, {_seed_prefix}20"
            self.context.append_user(
                f"[STATUS]: success\n[OUTPUT]:\n{sweep_summary}\n\n"
                "Port-scan each live host. Use: nmap -sS -T2 --top-ports 100 <ip>"
            )
        else:
            # ENUMERATE/EXPLOIT: dynamic seed based on known hosts
            # Pick a tool appropriate to the host's known ports
            import random as _rand
            is_exploit = self.planner.current_phase >= Phase.EXPLOIT
            try:
                hosts_with_ports = [h for h in self._get_hosts()
                                    if len(h.get("ports", [])) > 0]
                if hosts_with_ports:
                    h = _rand.choice(hosts_with_ports)
                    ports = h.get("ports", [])
                    ip = h["ip"]
                    ps = set(ports)

                    # In EXPLOIT phase, 50/50 seed with exploit vs enumerate
                    if is_exploit and _rand.random() < 0.5:
                        # EXPLOIT phase: seed with credential-testing examples
                        if 23 in ps:
                            seed_cmd = f"nxc telnet {ip} -u admin -p admin"
                            seed_out = "TELNET  {ip}:23  admin:admin [+] SUCCESS"
                            seed_reason = f"Test default telnet creds on {ip}."
                        elif 22 in ps:
                            seed_cmd = f"nxc ssh {ip} -u pi -p raspberry"
                            seed_out = "SSH  {ip}:22  pi:raspberry [-] AUTH FAILED"
                            seed_reason = f"Test default SSH creds on {ip}."
                        elif ps & {445, 139}:
                            seed_cmd = f"nxc smb {ip} -u '' -p '' --shares"
                            seed_out = "SMB  {ip}:445  \\\\{ip}\\share READ"
                            seed_reason = f"Try SMB null session on {ip}."
                        elif ps & {80, 8080, 8888}:
                            p = min(ps & {80, 8080, 8888})
                            port_part = "" if p == 80 else f":{p}"
                            seed_cmd = f"curl -s http://{ip}{port_part}/admin/"
                            seed_out = "HTTP/1.1 200 OK\n<title>Admin</title>"
                            seed_reason = f"Check admin panel on {ip}."
                        elif 5900 in ps:
                            seed_cmd = f"nxc vnc {ip} -p password"
                            seed_out = "VNC  {ip}:5900  [-] AUTH FAILED"
                            seed_reason = f"Test VNC default password on {ip}."
                        else:
                            seed_cmd = f"nxc ssh {ip} -u root -p root"
                            seed_out = "SSH  {ip}:22  root:root [-] AUTH FAILED"
                            seed_reason = f"Test default creds on {ip}."
                    else:
                        # ENUMERATE phase: probe services
                        http_ports = ps & {80, 443, 8080, 8443, 8000, 8888, 3000, 9000, 9200}
                        if http_ports:
                            p = min(http_ports)
                            port_part = "" if p in (80, 443) else f":{p}"
                            seed_cmd = f"curl -s -I http://{ip}{port_part}/"
                            seed_out = "HTTP/1.1 200 OK\nServer: nginx/1.18"
                        elif ps & {445, 139}:
                            seed_cmd = f"smbclient -N -L //{ip}/"
                            seed_out = "Sharename  Type  Comment\nshare  Disk"
                        elif 53 in ps:
                            seed_cmd = f"dig @{ip} version.bind chaos txt"
                            seed_out = "status: NOERROR\nversion.bind"
                        elif 22 in ps:
                            seed_cmd = f"nmap -sV -T2 -p 22 {ip}"
                            seed_out = "22/tcp open ssh OpenSSH 9.2p1"
                        elif ps & {3306, 5432, 1433, 27017, 6379}:
                            p = min(ps & {3306, 5432, 1433, 27017, 6379})
                            seed_cmd = f"nmap -sV -T2 -p {p} {ip}"
                            seed_out = f"{p}/tcp open database"
                        elif ps & {2375, 2376}:
                            seed_cmd = f"curl -s http://{ip}:2375/version"
                            seed_out = '{"Version":"20.10.17"}'
                        else:
                            seed_cmd = f"nmap -sV -T2 -p {ports[0]} {ip}"
                            seed_out = f"{ports[0]}/tcp open unknown"
                    seed_reason = f"Probe {ip} port {ports[0]}."
                else:
                    seed_cmd = f"curl -s -I http://{ip}/"
                    seed_out = "HTTP/1.1 200 OK\nServer: lighttpd/1.4.53"
                    seed_reason = "Check HTTP on known host."
            except Exception:
                seed_cmd = f"curl -s -I http://{ip}/"
                seed_out = "HTTP/1.1 200 OK\nServer: lighttpd/1.4.53"
                seed_reason = "Check HTTP on known host."

            if is_exploit:
                self.context.append_user("Mix exploitation with enumeration. Try creds on known hosts AND scan new ones.")
            else:
                self.context.append_user("Enumerate services on discovered hosts.")
            self.context.append_assistant(
                f"REASONING: {seed_reason}\n"
                f"COMMAND: {seed_cmd}"
            )
            self.context.append_user(
                f"[STATUS]: success\n[OUTPUT]:\n{seed_out}\n\n"
                "Good. Now probe a DIFFERENT host with an appropriate tool."
            )

        # Initial health check
        health = await self.llm.health_check()
        self.ui.update_backend_status(health)

        # Start cover traffic if enabled
        try:
            from agent import cover_traffic
            ct_config = db.get_state("cover_traffic", {"enabled": False, "ratio": 85})
            if ct_config.get("enabled") and ct_config.get("ratio", 0) > 0:
                cover_traffic.start()
                push_feed("phase", f"Cover traffic started ({ct_config['ratio']}% blend)")
        except Exception:
            pass

        try:
            if structured_log:
                structured_log.log("INIT", f"Agent started, phase={self.planner.phase_name}")
        except Exception:
            pass

        while not self.planner.mission_complete:
            phase = self.planner.current_phase
            self.ui.update_phase(self.planner.phase_name)
            self.ui.update_stats(
                uptime=self.watchdog.format_elapsed(),
                commands=self.total_commands,
                blocked=self.total_blocked,
                errors=self.consecutive_errors,
            )

            # Push state to web UI
            findings = self.mission_log.get_findings_summary()
            update_state({
                "phase": self.planner.phase_name,
                "mode": "THOR" if self.llm.use_thor else "LOCAL",
                "uptime": self.watchdog.format_elapsed(),
                "thor_online": self.llm.use_thor,
                "wifi_up": findings.get("wifi_connected", False),
                "commands_total": self.total_commands,
                "commands_blocked": self.total_blocked,
                "errors": self.consecutive_errors,
                "iteration": self.iteration,
                "findings": {
                    "hosts": findings.get("live_hosts", 0),
                    "ports": findings.get("open_ports", 0),
                    "creds": findings.get("credentials", 0),
                    "vulns": findings.get("vulnerabilities", 0),
                },
                "hosts": findings.get("hosts", []),
                "creds": findings.get("creds", []),
                "vulns": findings.get("vulns", []),
            })

            try:
                # Operating hours check — sleep during off-hours
                # Passive capture still runs, but no active commands
                op_hours = db.get_state("operating_hours", None)
                if op_hours and op_hours.get("enabled"):
                    from datetime import datetime
                    now_h = datetime.now().hour
                    start_h = op_hours.get("start", 7)
                    end_h = op_hours.get("end", 23)
                    if start_h <= end_h:
                        in_window = start_h <= now_h < end_h
                    else:  # wraps midnight (e.g., 22-06)
                        in_window = now_h >= start_h or now_h < end_h
                    if not in_window:
                        if self.iteration % 60 == 0:  # log once per ~60 iterations
                            push_feed("phase", f"Off-hours ({now_h}:00) — sleeping until {start_h}:00. Passive capture active.")
                        # Run passive capture during off-hours
                        try:
                            from agent.passive_capture import start_capture, _running
                            if not _running:
                                start_capture(duration=120)
                        except Exception:
                            pass
                        await asyncio.sleep(60)
                        self.iteration += 1
                        continue

                # C2 control state checks
                ctrl = await self._check_control_state()
                if ctrl == "killed":
                    break
                if isinstance(ctrl, tuple) and ctrl[0] == "manual_cmd":
                    # Execute manually injected command
                    manual_cmd = ctrl[1]
                    self.ui.render_command(f"[MANUAL] {manual_cmd}")
                    push_feed("command", f"[MANUAL] {manual_cmd}")
                    result = await self._execute(manual_cmd)
                    self.context.append_tool_result(manual_cmd, result)
                    self.mission_log.record(manual_cmd, result, "[MANUAL]")
                    self.ui.render_result(result)
                    self.total_commands += 1
                    continue

                # Direct playbook execution — bypasses LLM entirely
                if self.playbook_queue:
                    pb_cmd = self.playbook_queue.pop(0)
                    self.ui.render_command(f"[PLAYBOOK] {pb_cmd}")
                    push_feed("command", f"[PLAYBOOK] {pb_cmd}")
                    result = await self._execute(pb_cmd)
                    self.mission_log.record(pb_cmd, result, "[PLAYBOOK]")
                    self.ui.render_result(result)
                    self.total_commands += 1
                    self.last_command_time = time.time()
                    self.last_executed_ip = self.playbook_queue_ip

                    # Process output for findings
                    try:
                        parsed = output_parser.parse_output(
                            self.playbook_queue_ip,
                            self.playbook_queue_mac,
                            pb_cmd,
                            result.get("output", ""),
                            result.get("status", ""))
                    except Exception:
                        parsed = {}

                    # Auto-extract observations
                    try:
                        if self.playbook_queue_mac:
                            host_memory.auto_extract_observations(
                                self.playbook_queue_ip,
                                self.playbook_queue_mac,
                                pb_cmd,
                                result.get("output", ""),
                                result.get("status", ""))
                    except Exception:
                        pass

                    # Log result
                    status = result.get("status", "unknown")
                    output = result.get("output", "")
                    if status == "success" and output.strip():
                        push_feed("result", output[:500])
                    elif status == "error":
                        push_feed("error", result.get("error", "")[:200])

                    # When queue empty, mark playbook done
                    if not self.playbook_queue:
                        if self.playbook_queue_mac and self.playbook_queue_id:
                            host_memory.mark_playbook_done(
                                self.playbook_queue_mac,
                                self.playbook_queue_id,
                                ip=self.playbook_queue_ip)
                            push_feed("phase",
                                f"Playbook {self.playbook_queue_id} done on {self.playbook_queue_ip}")
                        self.playbook_queue_id = ""
                        self.playbook_queue_ip = ""
                        self.playbook_queue_mac = ""
                    continue

                # Fix #3: Time-based stuck detection — if no command
                # executed in 5 min, force context reset regardless of
                # streak count. Catches all stuck patterns.
                if time.time() - self.last_command_time > self.STUCK_TIMEOUT_SEC:
                    self.ui.render_warning("5min stuck — forcing context reset")
                    push_feed("warning", "Stuck >5min, auto-reset")
                    self._reset_context_with_fewshot()
                    self.last_command_time = time.time()  # prevent rapid-fire resets

                # Build system prompt with phase context
                system = self._build_system_prompt()

                # Add starred host priority to prompt
                starred = db.get_state("starred_hosts", [])
                if starred:
                    priority_ips = [s["ip"] for s in starred if s.get("remaining", 0) > 0]
                    if priority_ips:
                        system += f"\n\nPRIORITY TARGET: Focus on {', '.join(priority_ips[:3])}"

                # Add tool preferences to prompt
                tool_prefs = db.get_state("tool_preferences", {})
                if tool_prefs:
                    disabled = tool_prefs.get("disabled", [])
                    preferred = tool_prefs.get("preferred", [])
                    if disabled:
                        system += f"\nAVOID tools: {', '.join(disabled)}"
                    if preferred:
                        system += f"\nPREFER tools: {', '.join(preferred)}"

                # Add blacklisted hosts to prompt (skip these entirely)
                blacklist = db.get_state("blacklisted_hosts", [])
                if blacklist:
                    bl_ips = [b["ip"] for b in blacklist if b.get("ip")]
                    if bl_ips:
                        system += f"\nBLACKLIST (do NOT scan): {', '.join(bl_ips)}"

                # Add host notes from analyst (context for the model)
                host_notes = db.get_state("host_notes", {})
                if host_notes:
                    notes_text = ""
                    for mac, note in host_notes.items():
                        if note.strip():
                            # Resolve MAC to IP for the model
                            ip = mac  # fallback
                            try:
                                for h in self._get_hosts():
                                    if h["mac"] == mac:
                                        ip = h["ip"]
                                        break
                            except Exception:
                                pass
                            notes_text += f"\n  {ip}: {note[:100]}"
                    if notes_text:
                        system += f"\nANALYST NOTES:{notes_text}"

                # Add host memory (compact — max 200 tokens), scoped to the
                # current network so the LLM doesn't see hosts from prior
                # engagements (which would cause out-of-scope targeting).
                memory_ctx = host_memory.build_prompt_context(
                    max_tokens=200, network_id=self.current_network_id)
                if memory_ctx:
                    system += f"\n{memory_ctx}"

                # Add network memory (scanned IPs, observations)
                net_id = getattr(self.mission_log, 'network_id', '')
                if net_id:
                    net_ctx = host_memory.build_network_prompt_context(net_id, max_tokens=100)
                    if net_ctx:
                        system += f"\n{net_ctx}"

                # Attack planner — cache plan, refresh every ~50 commands
                if (self.total_commands % 50 == 0 or
                        not hasattr(self, '_cached_plan')):
                    self._cached_plan = attack_planner.generate_plan(max_tokens=150)
                if self._cached_plan:
                    system += f"\n{self._cached_plan}"

                messages = self.context.get_messages()

                # Call LLM
                self.ui.render_thinking()
                response = await self.llm.chat(system, messages)

                # Detect garbage / degenerate output
                if self._is_garbage(response):
                    self.garbage_streak += 1
                    self.total_garbage += 1
                    self.ui.render_warning(
                        f"Garbage output (streak {self.garbage_streak})")
                    push_feed("warning",
                              f"Garbage output #{self.total_garbage}")
                    try:
                        if structured_log:
                            structured_log.log("WARNING", f"Garbage output (streak {self.garbage_streak})")
                    except Exception:
                        pass

                    # After 5 consecutive garbage outputs, full reset
                    if self.garbage_streak >= 5:
                        self.ui.render_warning("5 garbage streak — resetting context")
                        push_feed("warning", "Context reset after 5 garbage")
                        self._reset_context_with_fewshot()
                    else:
                        self.context.append_user(
                            "Your output was malformed. "
                            "Respond ONLY as:\n"
                            "REASONING: [1-2 sentences]\n"
                            "COMMAND: [single linux command]"
                        )
                    continue

                # Good output — reset garbage streak
                self.garbage_streak = 0
                self._no_command_total = 0  # reset LLM-down backoff

                # Parse response
                reasoning = self._parse_reasoning(response)
                command = self._parse_command(response)

                # Always append the assistant response to context
                self.context.append_assistant(response)

                if reasoning:
                    self.ui.render_agent_thought(reasoning)
                    push_feed("thought", reasoning)
                    try:
                        if structured_log:
                            structured_log.log("THOUGHT", reasoning[:200])
                    except Exception:
                        pass

                if command:
                    # Skip commands targeting known dead-end hosts
                    target_ips = _IPV4_RE.findall(command)
                    if target_ips and all(self._should_skip_host(ip) for ip in target_ips):
                        push_feed("warning", f"Skipped dead-end host: {target_ips[0]}")
                        self.context.append_user(
                            f"{target_ips[0]} is a dead-end (firewalled/down). "
                            "Pick a DIFFERENT, LIVE host. "
                            "REASONING: [text] COMMAND: [command]"
                        )
                        continue

                    # Same-host enforcement — one action per host per turn,
                    # UNLESS multi-turn exploitation is active on this host.
                    if self.last_executed_ip and target_ips:
                        if target_ips[0] == self.last_executed_ip:
                            if (self.multi_turn_remaining > 0 and
                                    target_ips[0] == self.multi_turn_ip):
                                # Multi-turn: allow consecutive on same host
                                self.multi_turn_remaining -= 1
                                # Mark playbook done when last step consumed
                                if self.multi_turn_remaining == 0 and self.active_playbook:
                                    _pb_id = self.active_playbook.get("id", "")
                                    _mt_mac = ""
                                    for _h in self._get_hosts():
                                        if _h["ip"] == self.multi_turn_ip:
                                            _mt_mac = _h.get("mac", "")
                                            break
                                    if _mt_mac and _pb_id:
                                        host_memory.mark_playbook_done(
                                            _mt_mac, _pb_id, ip=self.multi_turn_ip)
                                    self.active_playbook = None
                                    self.playbook_step = 0
                            else:
                                self.same_host_streak += 1
                                self.garbage_streak += 1
                                push_feed("warning",
                                          f"Same host rejected: {target_ips[0]} "
                                          f"(streak {self.same_host_streak})")
                                try:
                                    if structured_log:
                                        structured_log.log("WARNING",
                                                           f"Same host rejected: {target_ips[0]} "
                                                           f"(streak {self.same_host_streak})")
                                except Exception:
                                    pass
                                # After 3 same-host rejections in a row, the
                                # model is fixated. Force a context reset with
                                # a host-rotation few-shot example.
                                if self.same_host_streak >= 3:
                                    push_feed("warning",
                                              "Same-host fixation — resetting context")
                                    self._reset_context_with_fewshot()
                                    self.same_host_streak = 0
                                else:
                                    self.context.append_user(
                                        f"You just scanned {target_ips[0]}. "
                                        "ROTATE to a DIFFERENT host for stealth. "
                                        "REASONING: [text] COMMAND: [different host]"
                                    )
                                continue

                    # Validate command before execution
                    if not self._is_valid_command(command):
                        self.garbage_streak += 1
                        push_feed("warning", f"Invalid cmd rejected ({self.garbage_streak}): {command[:40]}")
                        if self.garbage_streak >= 5:
                            self.ui.render_warning("5 invalid streak — resetting context")
                            push_feed("warning", "Context reset: invalid cmd loop")
                            self._reset_context_with_fewshot()
                        else:
                            self.context.append_user(
                                "Invalid command — wrong tool for that host. "
                                "Try: nmap -sS -T2 --top-ports 20 <ip> or nxc ssh <ip> -u root -p root. "
                                "REASONING: [text] COMMAND: [single valid command]"
                            )
                        continue

                    # Duplicate command detection
                    if self._is_duplicate(command):
                        self.garbage_streak += 1
                        try:
                            if structured_log:
                                structured_log.log("WARNING", f"Duplicate: {command[:60]}")
                        except Exception:
                            pass
                        self.ui.render_warning(
                            f"Dup command (streak {self.garbage_streak}): {command[:60]}")
                        push_feed("warning",
                                  f"Dup #{self.garbage_streak}: {command[:40]}")
                        if self.garbage_streak >= 5:
                            self.ui.render_warning("5 dup streak — resetting context")
                            push_feed("warning", "Context reset: dup loop")
                            self._reset_context_with_fewshot()
                        else:
                            self.context.append_user(
                                f"You already ran '{command[:80]}'. "
                                "Try a DIFFERENT approach or tool. "
                                "REASONING: [new analysis] COMMAND: [different command]"
                            )
                        continue

                    self.recent_commands.append(command)
                    if len(self.recent_commands) > 5:
                        self.recent_commands.pop(0)

                    # Fix #4: Deduplicate ports in nmap -p lists
                    if 'nmap' in command and '-p' in command:
                        command = self._dedup_ports(command)

                    self.ui.render_command(command)
                    push_feed("command", f"[LLM] {command}")
                    try:
                        if structured_log:
                            structured_log.log("CMD", command)
                    except Exception:
                        pass
                    result = await self._execute(command)
                    # tool_result is appended as a user message,
                    # keeping the alternating user/assistant pattern
                    self.context.append_tool_result(command, result)
                    self.mission_log.record(command, result, reasoning)
                    self.ui.render_result(result)

                    status = result.get("status", "unknown")
                    try:
                        if structured_log:
                            _out = result.get("output", result.get("error", ""))
                            structured_log.log("RESULT", f"{status} | {_out[:100]}")
                    except Exception:
                        pass
                    if status == "blocked":
                        push_feed("blocked", result.get("error", ""))
                    elif status == "error":
                        push_feed("error", result.get("error", ""))
                    else:
                        output = result.get("output", "")
                        preview = output[:800] + "..." if len(output) > 800 else output
                        push_feed("result", preview)

                    self.total_commands += 1
                    self.last_command_time = time.time()
                    # Reset same-host streak — we successfully executed a
                    # command on a different host (otherwise we'd have hit
                    # the same-host rejection branch above and skipped here).
                    self.same_host_streak = 0
                    if target_ips:
                        self.last_executed_ip = target_ips[0]
                    if result.get("status") == "blocked":
                        self.total_blocked += 1

                    # Capture successful interactions for finetuning
                    if status == "success" and reasoning and command:
                        try:
                            training_capture.capture_successful_interaction(
                                system_prompt=system,
                                messages=messages,
                                response=response,
                                reasoning=reasoning,
                                command=command,
                                result=result,
                                phase=self.planner.phase_name,
                                network_id=getattr(self.mission_log, 'network_id', ''),
                            )
                        except Exception:
                            pass  # never let training capture crash the agent

                    # Auto-extract host observations + track scanned IPs
                    try:
                        ips_in_cmd = _IPV4_RE.findall(command)
                        net_id = getattr(self.mission_log, 'network_id', '')
                        for ip in set(ips_in_cmd):
                            # Track IP as scanned at network level
                            if net_id:
                                host_memory.mark_ip_scanned(net_id, ip)
                            # Look up MAC for this IP
                            mac = ""
                            try:
                                for h in self._get_hosts():
                                    if h["ip"] == ip:
                                        mac = h["mac"]
                                        break
                            except Exception:
                                pass
                            if mac:
                                host_memory.auto_extract_observations(
                                    ip, mac, command,
                                    result.get("output", ""),
                                    result.get("status", "")
                                )
                                # Record failed commands for retry prevention
                                _cmd_output = result.get("output", "") or result.get("error", "")
                                _cmd_status = result.get("status", "")
                                _out_lower = _cmd_output.lower()
                                _is_failure = (
                                    _cmd_status == "error"
                                    or not _cmd_output.strip()
                                    or "refused" in _out_lower
                                    or "timeout" in _out_lower
                                    or "timed out" in _out_lower
                                    or "failed" in _out_lower
                                    or "not found" in _out_lower
                                    or "host seems down" in _out_lower
                                    or "no route" in _out_lower
                                )
                                if _is_failure:
                                    try:
                                        host_memory.record_failed_command(
                                            mac, command, _cmd_output, ip=ip)
                                    except Exception:
                                        pass
                    except Exception:
                        pass

                    # Output parser — extract structured intelligence
                    try:
                        if target_ips:
                            _parse_mac = ""
                            for _h in self._get_hosts():
                                if _h["ip"] == target_ips[0]:
                                    _parse_mac = _h.get("mac", "")
                                    break
                            parsed = output_parser.parse_output(
                                target_ips[0], _parse_mac, command,
                                result.get("output", ""),
                                result.get("status", ""))
                            # Use parser's suggested next command for multi-turn
                            if (parsed.get("next_command") and
                                    self.multi_turn_remaining > 0):
                                # Override the hint with parser's suggestion
                                pass  # hint will be set in context below
                    except Exception:
                        parsed = {}

                    # WiFi connect detection
                    if ("wpa_supplicant" in command or
                            "dhclient" in command):
                        if result.get("status") == "success":
                            self.llm.notify_wifi_connected()
                            self.mission_log.set_finding("wifi_connected", True)

                    output_summary = result.get("output", "")[:500]

                    # Multi-turn: keep context if exploiting a high-priority host
                    if (self.multi_turn_remaining > 0 and
                            target_ips and target_ips[0] == self.multi_turn_ip):
                        # Stay on this host — use playbook step if available
                        next_hint = "Go DEEPER on this same host."
                        if (self.active_playbook and
                                self.playbook_step < len(self.active_playbook.get("steps", []))):
                            self.playbook_step += 1
                            if self.playbook_step < len(self.active_playbook["steps"]):
                                next_cmd = self.active_playbook["steps"][self.playbook_step]
                                next_hint = f"Next step: {next_cmd}"
                        elif parsed and parsed.get("next_command"):
                            next_hint = f"Next step: {parsed['next_command']}"

                        self.context.append_user(
                            f"[RESULT]: {output_summary}\n\n"
                            f"{next_hint} "
                            "REASONING: [text] COMMAND: [next step]"
                        )
                        continue

                    # Mark playbook completion if one was active
                    if self.active_playbook and self.multi_turn_ip:
                        pb_id = self.active_playbook.get("id", "")
                        _pb_mac = ""
                        for _h in self._get_hosts():
                            if _h["ip"] == self.multi_turn_ip:
                                _pb_mac = _h.get("mac", "")
                                break
                        if _pb_mac and pb_id:
                            host_memory.mark_playbook_done(
                                _pb_mac, pb_id, ip=self.multi_turn_ip)
                        self.active_playbook = None
                        self.playbook_step = 0

                    # Normal: reset context, suggest random host
                    self.context.clear()

                    # Suggest a random host — weighted by attack surface
                    import random as _random
                    try:
                        all_hosts = self._get_hosts()
                        excluded = set(self.config["mission"]["scope"].get(
                            "excluded_hosts", []))
                        all_memories = host_memory.get_all_memories()
                        dead_end_ips = set()
                        for mac, mem in all_memories.items():
                            if mem.get("status") == "dead-end":
                                dead_end_ips.add(mem.get("ip", ""))

                        recent_ips = set(_IPV4_RE.findall(
                                         " ".join(self.recent_commands[-3:])))

                        from agent.planner import Phase as _Ph
                        _is_exploit = self.planner.current_phase >= _Ph.EXPLOIT

                        if _is_exploit:
                            # EXPLOIT: weight by attack surface priority
                            high, medium, low = [], [], []
                            for h in all_hosts:
                                ip = h["ip"]
                                if ip in excluded or ip in dead_end_ips or ip in recent_ips:
                                    continue
                                if not h.get("ports"):
                                    continue
                                pri = host_memory.get_host_priority(h.get("mac", ""))
                                if pri == "high":
                                    high.append(ip)
                                elif pri == "exhausted":
                                    pass  # skip exhausted hosts
                                elif pri == "low":
                                    low.append(ip)
                                else:
                                    medium.append(ip)

                            # Heavy weight toward high-priority (confirmed access)
                            r = _random.random()
                            if high and r < 0.60:
                                suggested = _random.choice(high)
                            elif medium and r < 0.90:
                                suggested = _random.choice(medium)
                            elif low:
                                suggested = _random.choice(low)
                            elif high:
                                suggested = _random.choice(high)
                            elif medium:
                                suggested = _random.choice(medium)
                            else:
                                suggested = ""
                        else:
                            # ENUMERATE: original logic
                            interesting = [h["ip"] for h in all_hosts
                                           if h["ip"] not in excluded
                                           and h["ip"] not in dead_end_ips
                                           and h["ip"] not in recent_ips
                                           and len(h.get("ports", [])) > 0]
                            others = [h["ip"] for h in all_hosts
                                      if h["ip"] not in excluded
                                      and h["ip"] not in dead_end_ips
                                      and h["ip"] not in recent_ips
                                      and len(h.get("ports", [])) == 0]

                            if interesting and _random.random() < 0.7:
                                suggested = _random.choice(interesting)
                            elif others:
                                suggested = _random.choice(others)
                            elif interesting:
                                suggested = _random.choice(interesting)
                            else:
                                suggested = ""
                        if suggested:
                            # Check if we know this host's ports
                            try:
                                host_ports = []
                                for h in all_hosts:
                                    if h["ip"] == suggested:
                                        host_ports = h.get("ports", [])
                                        break
                                from agent.planner import Phase as _Phase
                                _exploiting = self.planner.current_phase >= _Phase.EXPLOIT
                                if not host_ports:
                                    hint = f"Try: nmap -sS -T2 --top-ports 20 {suggested} (unknown ports). "
                                elif _exploiting:
                                    # EXPLOIT: use depth hints for hosts with findings,
                                    # standard hints for others
                                    import random as _rh
                                    # Look up MAC for this IP
                                    _mac = ""
                                    for _h in all_hosts:
                                        if _h["ip"] == suggested:
                                            _mac = _h.get("mac", "")
                                            break
                                    _pri = host_memory.get_host_priority(_mac) if _mac else "medium"
                                    if _pri == "high" and _mac:
                                        # High-priority: check for playbook first
                                        pb = self._get_playbook(suggested, _mac, set(host_ports))
                                        if pb and pb["steps"]:
                                            # DIRECT EXECUTION: push all steps into queue
                                            # bypasses LLM — commands run exactly as specified
                                            self.playbook_queue = list(pb["steps"])
                                            self.playbook_queue_ip = suggested
                                            self.playbook_queue_mac = _mac
                                            self.playbook_queue_id = pb["id"]
                                            hint = f"Playbook {pb['id']} queued ({len(pb['steps'])} steps). "
                                            push_feed("phase",
                                                f"Playbook {pb['id']} starting on {suggested} ({len(pb['steps'])} steps)")
                                        else:
                                            hint = self._depth_hint(suggested, _mac, set(host_ports))
                                        # No multi-turn needed — playbook queue handles it
                                    elif _rh.random() < 0.5:
                                        hint = self._exploit_hint(suggested, set(host_ports))
                                    else:
                                        hint = self._enumerate_hint(suggested, set(host_ports))
                                else:
                                    # ENUMERATE phase: probe services
                                    hint = self._enumerate_hint(suggested, set(host_ports))
                            except Exception:
                                hint = f"Try probing {suggested} next. "
                        else:
                            hint = ""
                    except Exception:
                        hint = ""

                    # Add failed command hints for suggested host
                    _fail_hints = ""
                    try:
                        if suggested:
                            _sugg_mac = ""
                            for _fh in self._get_hosts():
                                if _fh["ip"] == suggested:
                                    _sugg_mac = _fh.get("mac", "")
                                    break
                            if _sugg_mac:
                                _fail_hints = host_memory.build_failed_command_hints(
                                    _sugg_mac, max_hints=5)
                                if _fail_hints:
                                    _fail_hints = f"\n{_fail_hints}\n"
                    except Exception:
                        pass

                    self.context.append_user(
                        f"[LAST COMMAND]: {command}\n"
                        f"[RESULT]: {output_summary}\n\n"
                        f"{hint}{_fail_hints}"
                        "REASONING: [text] COMMAND: [command]"
                    )
                else:
                    # No command produced — track streak
                    self.garbage_streak += 1
                    self._no_command_total = getattr(self, '_no_command_total', 0) + 1
                    if self.garbage_streak >= 5:
                        self.ui.render_warning("5 no-command streak — resetting context")
                        push_feed("warning", "Context reset: no commands")
                        self._reset_context_with_fewshot()
                        # Back off if LLM keeps returning empty (likely down/warming up)
                        if self._no_command_total > 20:
                            delay = min(60, self._no_command_total // 5 * 10)
                            push_feed("warning", f"LLM unresponsive ({self._no_command_total} empties), backing off {delay}s")
                            await asyncio.sleep(delay)
                    else:
                        self.context.append_user(
                            "You MUST include a COMMAND line. "
                            "REASONING: [text] COMMAND: [single command]"
                        )

                # Phase transition check
                changed = self.planner.evaluate(self.mission_log)
                if changed:
                    self.ui.render_phase_transition(self.planner.phase_name)
                    push_feed("phase", f"ENTERING: {self.planner.phase_name}")

                # Periodic Thor health check + passive capture
                self.iteration += 1
                if self.iteration % self.HEARTBEAT_INTERVAL == 0:
                    health = await self.llm.health_check()
                    self.ui.update_backend_status(health)

                # Passive capture now runs continuously (started at boot).
                # Re-ingest results every ~25 commands so the UI sees fresh
                # discoveries promptly without waiting for the cycle to end.
                if self.total_commands > 0 and self.total_commands % 25 == 0:
                    try:
                        from agent.passive_capture import parse_capture, ingest_findings
                        findings = parse_capture()
                        if findings:
                            count = ingest_findings(findings)
                            if count > 0:
                                push_feed("result",
                                          f"Passive capture: {count} new observations from {len(findings)} packets")
                    except Exception:
                        pass

                # Periodic host re-sweep every ~200 commands (~3-4 hours)
                # Periodic re-discovery — every ~100 commands. ARP scan first
                # (catches client-isolated hosts that ignore ICMP), then nmap
                # ping sweep. Combined results upserted to DB.
                if self.total_commands > 0 and self.total_commands % 100 == 0:
                    try:
                        from agent.net_detect import get_current_network
                        _subnet, _prefix, _, _ = get_current_network()
                        _all_ips = set()

                        # ARP scan
                        _arp_hosts = recon_tools.run_arp_scan(timeout=15)
                        for _h in _arp_hosts:
                            _all_ips.add(_h["ip"])
                            try:
                                db.upsert_host(
                                    _h["ip"], ports=[], mac=_h["mac"],
                                    info=f"Discovered via ARP re-sweep ({_h.get('vendor','')})".strip())
                            except Exception:
                                pass

                        # nmap ping sweep
                        import subprocess as _rsp
                        _rsweep = _rsp.run(
                            ["nmap", "-sn", "-T3", "--max-retries", "1", _subnet],
                            capture_output=True, text=True, timeout=45)
                        for _rip in re.findall(
                                r'Nmap scan report for (' + _prefix.replace('.', r'\.') + r'\d+)',
                                _rsweep.stdout):
                            if _rip not in _all_ips:
                                _all_ips.add(_rip)
                                existing = [h for h in self._get_hosts() if h["ip"] == _rip]
                                if not existing:
                                    db.upsert_host(_rip, ports=[],
                                                   info="Discovered via periodic re-sweep")

                        # Count truly new ones
                        _known = {h["ip"] for h in self._get_hosts()}
                        _new = len(_all_ips - _known) if _all_ips else 0
                        if _all_ips:
                            push_feed("result",
                                      f"Re-sweep: {len(_arp_hosts)} via ARP + "
                                      f"{len(_all_ips)} total alive on {_subnet}")
                    except Exception:
                        pass

                self.consecutive_errors = 0

            except Exception as e:
                self.consecutive_errors += 1
                self.mission_log.record_error(e)
                self.ui.render_error(
                    f"Error #{self.consecutive_errors}: {e}"
                )
                try:
                    if structured_log:
                        structured_log.log("ERROR", str(e)[:200])
                except Exception:
                    pass
                if self.consecutive_errors >= self.MAX_CONSECUTIVE_ERRORS:
                    self.ui.render_error(
                        f"{self.MAX_CONSECUTIVE_ERRORS} errors. "
                        "Resetting context and pausing 60s."
                    )
                    # Reset context instead of long pause
                    self.context.clear()
                    self.context.append_user(
                        "Context reset. Scan the next host. "
                        "REASONING: [text] COMMAND: [command]"
                    )
                    await asyncio.sleep(60)
                    self.consecutive_errors = 0
                else:
                    delay = self.RETRY_DELAYS[
                        min(self.consecutive_errors - 1,
                            len(self.RETRY_DELAYS) - 1)
                    ]
                    await asyncio.sleep(delay)

        self.ui.render_mission_complete()
        self.mission_log.finalize()

    async def _execute(self, command: str, max_retries: int = 2) -> dict:
        """Send command through scope proxy.

        Only retries on transport errors (proxy unreachable).
        Command execution errors (exit code != 0) are NOT retried — the
        command ran, it just failed, and retrying won't help (plus the
        proxy audit-logs each attempt, causing triple entries).
        """
        import httpx
        last_error = None
        for attempt in range(max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=300) as client:
                    resp = await client.post(
                        f"{self.proxy_url}/execute",
                        json={"command": command},
                    )
                    return resp.json()
            except Exception as e:
                last_error = str(e)
                if attempt < max_retries:
                    await asyncio.sleep(2 ** attempt)
        return {"status": "error", "error": last_error, "output": ""}

    def _build_system_prompt(self) -> str:
        """Load system prompt from file and inject phase context."""
        scope = self.config["mission"]["scope"]
        stealth = self.config["stealth"]
        template = _load_system_prompt().format(
            scope_networks=", ".join(scope["networks"]),
            excluded_hosts=", ".join(scope.get("excluded_hosts", [])),
            excluded_ports=", ".join(str(p) for p in scope.get("excluded_ports", [])),
            cred_spray_rate=stealth["cred_spray_rate_per_min"],
            phase_context=self.planner.phase_context,
        )
        # Append mission state summary
        summary = self.context.get_summary()
        if summary:
            template += f"\n\n## MISSION STATE\n{summary}"
        return template

    async def _check_control_state(self):
        """Check C2 control state: kill, pause, phase, manual queue, starred hosts."""
        # Kill switch
        if db.get_state("kill_switch", False):
            self.ui.render_warning("KILL SWITCH activated")
            push_feed("warning", "KILL SWITCH — mission terminated")
            self.planner.mission_complete = True
            return "killed"

        # Pause
        while db.get_state("paused", False):
            update_state({"phase": "PAUSED"})
            await asyncio.sleep(1)

        # Forced phase change
        forced = db.get_state("forced_phase")
        if forced:
            self.planner.force_phase(forced)
            db.set_state("forced_phase", None)
            self.ui.render_phase_transition(self.planner.phase_name)
            push_feed("phase", f"FORCED: {self.planner.phase_name}")
            # Reset context for new phase
            self.context.clear()
            self.context.append_user(
                f"Phase changed to {self.planner.phase_name}. "
                "REASONING: [text] COMMAND: [command]"
            )

        # Live config override
        config_override = db.get_state("agent_config", {})
        if config_override:
            if "temperature" in config_override:
                self.llm._temperature = config_override["temperature"]
            if "max_tokens" in config_override:
                self.llm._max_tokens = config_override["max_tokens"]

        # Manual command queue (FIFO)
        queue = db.get_state("command_queue", [])
        if queue:
            cmd = queue.pop(0)
            db.set_state("command_queue", queue)
            return ("manual_cmd", cmd)

        # Decrement starred host counters
        starred = db.get_state("starred_hosts", [])
        if starred:
            updated = []
            for s in starred:
                s["remaining"] = s.get("remaining", 0) - 1
                if s["remaining"] > 0:
                    updated.append(s)
            db.set_state("starred_hosts", updated)

        return "continue"

    @staticmethod
    def _is_valid_command(command: str) -> bool:
        """Reject obviously invalid commands before they hit the executor."""
        if not command or len(command) < 2:
            return False
        cmd_lower = command.lower().strip()
        # Reject format tags
        if cmd_lower in ('command:', 'reasoning:', 'command', 'reasoning'):
            return False
        # Reject backtick-prefixed
        if command.startswith('`'):
            return False
        # Must start with a letter or /
        if not command[0].isalpha() and command[0] != '/':
            return False
        # Reject fake file paths that don't exist
        if '/path/to/' in command or '/home/user/' in command:
            return False
        # Reject placeholder tokens (model failed to substitute a real value)
        if re.search(r'<(ip|target|host|port|url|user|password|domain)>', cmd_lower):
            return False
        # Fix #2: Network tools MUST have a target IP — model sometimes
        # omits it, wasting a turn on "nmap --top-ports 20" with no target
        net_tools = ('nmap', 'curl', 'dig', 'smbclient', 'ssh', 'nxc',
                     'gobuster', 'nikto', 'hydra', 'enum4linux', 'sqlmap',
                     'dirb', 'impacket-samrdump', 'impacket-rpcdump',
                     'impacket-secretsdump', 'impacket-wmiexec')
        first_word = cmd_lower.split()[0] if cmd_lower.split() else ''
        if first_word in net_tools:
            if not re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', command):
                return False
        # Reject invalid nmap timing (only -T0 through -T5)
        timing = re.search(r'-T(\d+)', command)
        if timing and int(timing.group(1)) > 5:
            return False
        # Enforce stealth: reject -T3, -T4, -T5 for nmap
        if 'nmap' in cmd_lower and timing and int(timing.group(1)) > 2:
            return False
        return True

    @staticmethod
    def _dedup_ports(command: str) -> str:
        """Fix #4: Remove duplicate ports from nmap -p lists."""
        match = re.search(r'(-p\s*)([\d,]+)', command)
        if match:
            prefix = match.group(1)
            ports_str = match.group(2)
            # Preserve order, remove duplicates
            seen = set()
            unique = []
            for p in ports_str.split(','):
                p = p.strip()
                if p and p not in seen:
                    seen.add(p)
                    unique.append(p)
            if unique:
                deduped = prefix + ','.join(unique)
                command = command[:match.start()] + deduped + command[match.end():]
        return command

    @staticmethod
    def _depth_hint(ip: str, mac: str, ports: set) -> str:
        """Generate exploit-depth hint based on what's already been found.

        Instead of re-running the same probe, suggest the NEXT logical
        step deeper into confirmed access points.
        """
        import random as _r
        findings = host_memory.get_access_findings(mac)
        failed = host_memory.get_failed_attacks(mac)
        tried = host_memory.get_tried_actions(mac)
        all_obs = [o["text"] for o in host_memory.get_memory(mac).get("observations", [])]

        hints = []

        # CVE DB lookup — version-specific exploits (highest priority)
        cve_hint = cve_db.get_exploit_hint(all_obs, ip)
        if cve_hint:
            hints.append(cve_hint)

        # SMB depth: if shares are known, READ them (not re-list!)
        if any("shares accessible" in f for f in findings):
            share_match = None
            for f in findings:
                if "shares accessible" in f:
                    share_match = f
            if share_match:
                # Extract share names
                shares = [s.strip() for s in
                          share_match.replace("SMB shares accessible:", "").split(",")]
                for share in shares:
                    share = share.strip()
                    if share and share != "IPC$":
                        hints.extend([
                            f"Try: smbclient -N //{ip}/{share} -c 'ls' (read share contents). ",
                            f"Try: smbclient -N //{ip}/{share} -c 'recurse ON; ls' (deep list). ",
                        ])
            hints.extend([
                f"Try: nxc smb {ip} -u '' -p '' --rid-brute (enumerate users). ",
                f"Try: enum4linux -a {ip} (full SMB enumeration). ",
            ])

        # Pi-hole depth: actual login mechanism (POST, not basic auth)
        if any("Pi-hole" in f or "pi-hole" in f for f in findings):
            hints.extend([
                f"Try: curl -s -X POST http://{ip}/admin/index.php -d 'pw=admin' (Pi-hole login). ",
                f"Try: curl -s -X POST http://{ip}/admin/index.php -d 'pw=raspberry' (Pi-hole login). ",
                f"Try: curl -s http://{ip}/admin/api.php?status (Pi-hole API). ",
                f"Try: gobuster dir -u http://{ip} -w /usr/share/wordlists/dirb/common.txt -q -t 5. ",
            ])

        # HTTP depth: if server responds, probe deeper + web exploits
        if any("HTTP server" in f or "HTTP 403" in f for f in findings):
            hints.extend([
                f"Try: curl -s http://{ip}/robots.txt (hidden paths). ",
                f"Try: curl -s http://{ip}/.env (leaked config). ",
                f"Try: curl -s http://{ip}/server-status (Apache status). ",
                f"Try: dirb http://{ip} /usr/share/wordlists/dirb/small.txt -S (dir scan). ",
                f"Try: nikto -h http://{ip} -Tuning 1 -maxtime 60s (web vuln scan). ",
            ])

        # VNC depth: if VNC is open, try passwords not yet failed
        if 5900 in ports:
            if not any("VNC" in f and "password" in f for f in failed):
                hints.append(f"Try: nxc vnc {ip} -p password (VNC default). ")
            if not any("VNC" in f and "admin" in f for f in failed):
                hints.append(f"Try: nxc vnc {ip} -p admin (VNC admin). ")
            if not any("VNC" in f and "raspberry" in f for f in failed):
                hints.append(f"Try: nxc vnc {ip} -p raspberry (VNC pi). ")

        # Samba version known: try specific exploits
        if any("Samba version" in f for f in findings):
            hints.extend([
                f"Try: impacket-samrdump {ip} (enumerate SAM users). ",
                f"Try: impacket-rpcdump {ip} (RPC endpoints). ",
            ])

        # DNS depth: try zone transfer, reverse lookups
        if any("DNS resolver" in f or "dnsmasq" in f for f in findings):
            hints.extend([
                f"Try: dig axfr @{ip} (zone transfer). ",
                f"Try: dig @{ip} -x {ip} (reverse lookup). ",
                f"Try: dig @{ip} any (all records). ",
            ])

        # Impacket on any SMB host (even without specific findings)
        if ports & {445, 139}:
            hints.extend([
                f"Try: impacket-samrdump {ip} (enumerate users via SAM). ",
                f"Try: impacket-rpcdump {ip} (RPC endpoints). ",
            ])

        # Filter out hints for tools we already tried on this host
        if tried and hints:
            filtered = []
            for h in hints:
                skip = False
                for t in tried:
                    action = t.replace("TRIED ", "").lower()
                    if action in h.lower():
                        skip = True
                        break
                if not skip:
                    filtered.append(h)
            if filtered:
                hints = filtered

        if hints:
            return _r.choice(hints)

        # Fallback to standard exploit hint if no depth available
        return AgentLoop._exploit_hint(ip, ports)

    @staticmethod
    def _enumerate_hint(ip: str, ports: set) -> str:
        """Generate enumerate-phase hint: service probing matched to ports."""
        hp = ports
        http_ports = hp & {80, 443, 8080, 8443, 8000, 8888, 3000, 9000, 9200}
        if http_ports:
            p = min(http_ports)
            scheme = "https" if p in (443, 8443, 9443) else "http"
            port_part = "" if p in (80, 443) else f":{p}"
            return f"Try: curl -s -I {scheme}://{ip}{port_part}/ (port {p}). "
        if hp & {445, 139}:
            return f"Try: smbclient -N -L //{ip}/ (has SMB). "
        if 53 in hp:
            return f"Try: dig @{ip} version.bind chaos txt (has DNS). "
        if 22 in hp:
            return f"Try: nmap -sV -T2 -p 22 {ip} (has SSH). "
        if hp & {3306, 5432, 1433, 27017, 6379}:
            p = min(hp & {3306, 5432, 1433, 27017, 6379})
            return f"Try: nmap -sV -T2 -p {p} {ip} (database). "
        if hp & {5900, 5901}:
            return f"Try: nmap -sV -T2 -p 5900 {ip} (VNC). "
        if 21 in hp:
            return f"Try: nmap -sV -T2 -p 21 {ip} (FTP). "
        return f"Try: nmap -sV -T2 -p {min(hp)} {ip}. "

    @staticmethod
    def _exploit_hint(ip: str, ports: set) -> str:
        """Generate exploit-phase hint: smart, varied attacks matched to ports.

        Filters out creds already tried on this host. Boosts untried tools
        (impacket, nikto, gobuster) with 80% probability if never used.
        """
        import random as _r

        # Get host memory to filter failed creds and check untried tools
        _mac = ""
        for _h in db.get_hosts():
            if _h["ip"] == ip:
                _mac = _h.get("mac", "")
                break
        failed = set()
        tried = set()
        if _mac:
            failed = set(host_memory.get_failed_attacks(_mac))
            tried = set(host_memory.get_tried_actions(_mac))

        hints = []
        priority_hints = []  # untried tools get boosted

        # SSH
        if 22 in ports:
            hints.append(f"Try: nmap -T2 --script=vulners -p 22 {ip} (CVE scan SSH). ")
            hints.append(f"Try: nmap -T2 --script=ssh-auth-methods -p 22 {ip} (SSH auth check). ")
            # Only suggest creds NOT already failed
            if not any("SSH pi:raspberry" in f for f in failed):
                hints.append(f"Try: nxc ssh {ip} -u pi -p raspberry (Pi default). ")
            if not any("SSH root:root" in f for f in failed):
                hints.append(f"Try: nxc ssh {ip} -u root -p root (SSH default). ")
            if not any("SSH admin:admin" in f for f in failed):
                hints.append(f"Try: nxc ssh {ip} -u admin -p admin (SSH default). ")
        if 23 in ports:
            hints.extend([
                f"Try: nxc telnet {ip} -u admin -p admin (telnet default). ",
                f"Try: nxc telnet {ip} -u root -p root (telnet default). ",
            ])
        if ports & {445, 139}:
            hints.append(f"Try: nmap -T2 --script=smb-vuln* -p 445 {ip} (SMB vuln scan). ")
            hints.append(f"Try: nxc smb {ip} -u '' -p '' --shares --rid-brute (null+RID). ")
            # Boost impacket if never tried on this host
            if not any("impacket-samrdump" in t for t in tried):
                priority_hints.append(f"Try: impacket-samrdump {ip} (enumerate SAM users). ")
            if not any("impacket-rpcdump" in t for t in tried):
                priority_hints.append(f"Try: impacket-rpcdump {ip} (RPC endpoints). ")
            if not any("enum4linux" in t for t in tried):
                priority_hints.append(f"Try: enum4linux -a {ip} (full SMB enum). ")
        if ports & {80, 443, 8080, 8888}:
            p = min(ports & {80, 443, 8080, 8888})
            pp = "" if p == 80 else f":{p}"
            hints.append(f"Try: curl -s http://{ip}{pp}/robots.txt (hidden paths). ")
            hints.append(f"Try: curl -s http://{ip}{pp}/.env (leaked config). ")
            hints.append(f"Try: nmap -T2 --script=http-vuln* -p {p} {ip} (HTTP vuln scan). ")
            # Boost nikto/gobuster if never tried
            if not any("nikto" in t for t in tried):
                priority_hints.append(f"Try: nikto -h http://{ip}{pp} -Tuning 1 -maxtime 60s (web vuln scan). ")
            if not any("gobuster" in t or "dirb" in t for t in tried):
                priority_hints.append(f"Try: gobuster dir -u http://{ip}{pp} -w /usr/share/wordlists/dirb/common.txt -q -t 5. ")
        if 5900 in ports:
            if not any("VNC" in f and "password" in f for f in failed):
                hints.append(f"Try: nxc vnc {ip} -p password (VNC default). ")
            if not any("VNC" in f and "raspberry" in f for f in failed):
                hints.append(f"Try: nxc vnc {ip} -p raspberry (VNC Pi default). ")
            if not any("VNC" in f and "admin" in f for f in failed):
                hints.append(f"Try: nxc vnc {ip} -p admin (VNC admin). ")
            hints.append(f"Try: nmap -T2 --script=vnc-info -p 5900 {ip} (VNC info). ")
        if 53 in ports:
            hints.extend([
                f"Try: dig axfr @{ip} (DNS zone transfer). ",
                f"Try: dig axfr @{ip} (DNS zone transfer). ",
            ])
        if 21 in ports:
            hints.extend([
                f"Try: nxc ftp {ip} -u anonymous -p anonymous (FTP anon). ",
                f"Try: nmap -T2 --script=ftp-anon -p 21 {ip} (FTP anon check). ",
            ])
        if ports & {3306, 5432, 6379}:
            if 6379 in ports:
                hints.append(f"Try: redis-cli -h {ip} INFO (Redis unauthenticated). ")
            if 3306 in ports:
                hints.append(f"Try: nxc mysql {ip} -u root -p root (MySQL default). ")

        if not hints and not priority_hints:
            hints = [
                f"Try: nmap -T2 --script=vulners -p {min(ports)} {ip} (CVE scan). ",
            ]

        # 80% chance to pick untried priority tools if available
        if priority_hints and _r.random() < 0.80:
            return _r.choice(priority_hints)
        if hints:
            return _r.choice(hints)
        if priority_hints:
            return _r.choice(priority_hints)

        # Fallback: try credential spray from harvested usernames or recon tools
        try:
            spray_hints = recon_tools.get_credential_spray_hints(ip, ports, max_hints=2)
            if spray_hints:
                return _r.choice(spray_hints)
            recon_hints = recon_tools.get_recon_hints(ip, ports)
            if recon_hints:
                return _r.choice(recon_hints)
        except Exception:
            pass

        return f"Try: nmap -T2 --script=vulners -p 22 {ip} (CVE scan). "

    def _get_playbook(self, ip: str, mac: str, ports: set) -> dict:
        """Find a matching playbook for this host based on observations."""
        import json, os
        try:
            pb_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "playbooks.json")
            with open(pb_path) as f:
                playbooks = json.load(f).get("playbooks", [])
        except Exception:
            return None

        obs = [o["text"] for o in
               host_memory.get_memory(mac).get("observations", [])]
        tried = host_memory.get_tried_actions(mac)
        obs_text = " ".join(obs).lower()

        for pb in playbooks:
            pb_id = pb.get("id", "")
            trigger = pb.get("trigger_obs", "").lower()
            trigger_ports = set(pb.get("trigger_ports", []))

            # Skip completed playbooks (unless repeatable, max 3 times) and failed ones
            repeatable = pb.get("repeatable", False)
            if host_memory.is_playbook_done(mac, pb_id):
                if not repeatable:
                    continue
                # Count how many times this playbook ran
                done_count = sum(1 for o in obs if o == f"PLAYBOOK_DONE {pb_id}")
                if done_count >= 3:
                    continue  # max 3 repeats
            if host_memory.is_playbook_failed(mac, pb_id):
                continue

            if trigger in obs_text and (not trigger_ports or
                                         trigger_ports & ports):
                # Extract actual share names from observations
                actual_shares = ["share"]  # fallback
                for o in obs:
                    if "shares accessible:" in o:
                        parts = o.split("shares accessible:")[-1]
                        actual_shares = [s.strip() for s in parts.split(",")
                                        if s.strip() and s.strip() != "IPC$"]
                        break

                # Extract creds for post-auth playbooks
                _user, _password = "root", "root"
                try:
                    creds = db.get_credentials()
                    for c in creds:
                        if c.get("host") == ip:
                            _user = c.get("username", "root")
                            _password = c.get("password", "root")
                            break
                except Exception:
                    pass

                # Filter out already-tried steps and failed creds
                failed_attacks = host_memory.get_failed_attacks(mac)
                steps = []
                for step in pb.get("steps", []):
                    share_name = actual_shares[0] if actual_shares else "share"
                    step_cmd = step.format(ip=ip, share=share_name,
                                           user=_user, password=_password)
                    # Check if we already tried this tool
                    skip = False
                    for t in tried:
                        action = t.replace("TRIED ", "").lower()
                        if action in step_cmd.lower():
                            skip = True
                            break
                    # Check if this is a cred test with a known-failed password
                    if not skip and 'nxc ' in step_cmd and ' -p ' in step_cmd:
                        import re as _re
                        _pm = _re.search(r"-p\s+'?([^'\s]+)", step_cmd)
                        if _pm:
                            _pw = _pm.group(1)
                            for f in failed_attacks:
                                if _pw in f and "FAILED" in f:
                                    skip = True
                                    break
                    if not skip:
                        steps.append(step_cmd)

                if steps:
                    return {"id": pb["id"], "steps": steps,
                            "desc": pb.get("desc", "")}
        return None

    def _reset_context_with_fewshot(self):
        """Shared context reset with few-shot example.

        Used by: time-based stuck detection, dup-loop reset, no-command reset.
        Injects a concrete example on a random host so the 2B model
        copies the pattern instead of repeating its stuck reasoning.
        Varies the example tool to prevent fixation on one command type.
        """
        try:
            if structured_log:
                structured_log.log("RESET", f"Garbage streak {self.garbage_streak}")
        except Exception:
            pass
        import random as _rand
        self.context.clear()
        try:
            _hosts = [h for h in db.get_hosts()
                      if len(h.get("ports", [])) > 0]
            _host = _rand.choice(_hosts) if _hosts else None
            reset_ip = _host["ip"] if _host else _gcn()[3]  # gateway as fallback
            _ports = _host.get("ports", [22]) if _host else [22]
        except Exception:
            from agent.net_detect import get_current_network as _gcn2; reset_ip = _gcn2()[3]
            _ports = [22]

        # Vary the example based on available ports — prevents smbclient fixation
        _examples = []
        if 22 in _ports:
            _examples.append((
                f"REASONING: Check SSH auth on {reset_ip}.\n"
                f"COMMAND: nmap -T2 --script=ssh-auth-methods -p 22 {reset_ip}",
                "[STATUS]: success\n[OUTPUT]:\nssh-auth-methods: publickey password\n\n"
            ))
            _examples.append((
                f"REASONING: Test SSH default creds on {reset_ip}.\n"
                f"COMMAND: nxc ssh {reset_ip} -u root -p root",
                "[STATUS]: success\n[OUTPUT]:\n[-] SSH root:root Authentication failed\n\n"
            ))
        if 53 in _ports:
            _examples.append((
                f"REASONING: Try DNS zone transfer on {reset_ip}.\n"
                f"COMMAND: dig axfr @{reset_ip}",
                "[STATUS]: success\n[OUTPUT]:\n; Transfer failed.\n\n"
            ))
        if any(p in _ports for p in [80, 443, 8080]):
            _examples.append((
                f"REASONING: Check web server on {reset_ip}.\n"
                f"COMMAND: curl -s http://{reset_ip}/robots.txt",
                "[STATUS]: success\n[OUTPUT]:\nUser-agent: *\nDisallow: /admin\n\n"
            ))
        if not _examples:
            _examples.append((
                f"REASONING: Probe ports on {reset_ip}.\n"
                f"COMMAND: nmap -sS -T2 --top-ports 20 {reset_ip}",
                "[STATUS]: success\n[OUTPUT]:\n22/tcp open ssh\n\n"
            ))

        _ex = _rand.choice(_examples)
        self.context.append_user(f"Probe {reset_ip}.")
        self.context.append_assistant(_ex[0])
        self.context.append_user(
            _ex[1] +
            "Good. Now probe a DIFFERENT host. "
            "REASONING: [text] COMMAND: [command]"
        )
        self.garbage_streak = 0
        self.same_host_streak = 0
        self.recent_commands.clear()
        self.last_executed_ip = ""
        self.multi_turn_remaining = 0
        self.multi_turn_ip = ""
        self.active_playbook = None
        self.playbook_step = 0
        # Don't clear playbook_queue on reset — let queued commands finish

    def _should_skip_host(self, ip: str) -> bool:
        """Check if a host is known dead-end and should be skipped."""
        try:
            for h in db.get_hosts():
                if h["ip"] == ip:
                    mem = host_memory.get_memory(h["mac"])
                    if mem.get("status") == "dead-end":
                        return True
                    break
        except Exception:
            pass
        return False

    def _is_duplicate(self, command: str) -> bool:
        """Check if exact same command was run recently.

        Checks two windows:
        1. Last 5 in-memory commands (fast, catches immediate repeats)
        2. Last 6 hours in DB (catches repeats across host rotation)
        """
        if command in self.recent_commands:
            return True
        # Check DB for same command in last 6 hours
        try:
            import sqlite3
            from datetime import datetime, timedelta, timezone
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
            conn = sqlite3.connect(db.DB_PATH, timeout=5)
            count = conn.execute(
                "SELECT COUNT(*) FROM commands WHERE command = ? AND timestamp > ?",
                (command, cutoff)
            ).fetchone()[0]
            conn.close()
            return count >= 3  # Allow up to 2 repeats over 6h, block on 3rd
        except Exception:
            return False

    @staticmethod
    def _is_garbage(response: str) -> bool:
        """Detect degenerate output (number sequences, repetition)."""
        if not response or len(response) < 10:
            return True
        # Mostly digits/commas (number sequence degeneration)
        non_alnum = response.replace(",", "").replace(" ", "").replace("\n", "")
        if len(non_alnum) > 50 and sum(c.isdigit() for c in non_alnum) / len(non_alnum) > 0.7:
            return True
        # Extreme repetition: same 10-char chunk repeated many times
        if len(response) > 100:
            chunk = response[10:20]
            if chunk and response.count(chunk) > len(response) // (len(chunk) * 2):
                return True
        return False

    # _is_refusal removed — abliterated model (LFM2.5-1.2B-Instruct-Heretic) doesn't refuse

    @staticmethod
    def _parse_reasoning(response: str) -> str:
        # Strip markdown heading prefixes (### REASONING:)
        cleaned = re.sub(r'^#+\s*', '', response.strip())
        match = re.search(r'REASONING:\s*(.+?)(?=COMMAND:|$)',
                          cleaned, re.DOTALL)
        if match:
            text = match.group(1).strip()
            # Strip markdown bold markers
            text = text.strip("*").strip()
            return text if text else None
        # If no REASONING tag, treat entire non-command text as reasoning
        if "COMMAND:" not in response.upper():
            text = response.strip()
            return text if text else None
        return None

    @staticmethod
    def _parse_command(response: str) -> str:
        match = re.search(r'COMMAND:\s*(.+)', response, re.IGNORECASE)
        if match:
            cmd = match.group(1).strip()
            # Strip markdown formatting: bold (**), code fences, backticks
            cmd = re.sub(r'^```\w*\s*', '', cmd)
            cmd = re.sub(r'\s*```$', '', cmd)
            # Strip leading/trailing backticks and asterisks (markdown)
            cmd = re.sub(r'^[`*]+', '', cmd)
            cmd = re.sub(r'[`*]+$', '', cmd)
            cmd = cmd.strip()
            # Remove leading shell prompts, markdown headers
            cmd = re.sub(r'^[#>$\s]+', '', cmd).strip()
            return cmd if cmd else None
        return None


def _load_system_prompt() -> str:
    """Load system prompt from prompts/system.md (hot-reloadable)."""
    import os
    for base in [os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "/root/nightcrawler", "/opt/nightcrawler"]:
        path = os.path.join(base, "prompts", "system.md")
        if os.path.exists(path):
            with open(path) as f:
                return f.read().strip()
    # Fallback
    return ("You are NIGHTCRAWLER, a pentest agent. "
            "SCOPE: {scope_networks}. {phase_context}\n"
            "REASONING: [text] COMMAND: [command]")
