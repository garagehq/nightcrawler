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
        if result.returncode == 0:
            return True
    except Exception:
        pass

    return False


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


async def main():
    _kill_existing_agents()  # Prevent duplicate agent processes (memory leak)

    config_path = os.environ.get("NC_CONFIG", "config.yaml")
    config = load_config(config_path)

    dry_run = (
        os.environ.get("NC_DRY_RUN", "0") == "1"
        or config.get("dry_run", {}).get("enabled", False)
    )

    ui = TerminalUI()

    # Boot sequence display
    proxy_port = config.get("scope_proxy", {}).get("port", 8800)
    llm_port = config["model"]["local"]["port"]

    services = [
        {"name": "Loading config", "status": "OK", "detail": config_path},
        {"name": "LLM backend", "status": "OK",
         "detail": f"llama.cpp :{llm_port}"},
        {"name": "Scope proxy", "status": "OK",
         "detail": f":{proxy_port}"},
    ]

    if dry_run:
        services.append(
            {"name": "Mode", "status": "DRY RUN", "detail": "simulation"}
        )
    else:
        services.append(
            {"name": "Mode", "status": "AUTONOMOUS", "detail": "live"}
        )

    # Thor is optional — check if reachable
    thor_cfg = config["model"].get("thor", {})
    if thor_cfg.get("enabled"):
        services.append(
            {"name": "Thor", "status": "CHECKING",
             "detail": thor_cfg.get("endpoint", "?")}
        )
    else:
        services.append(
            {"name": "Thor", "status": "SKIP", "detail": "disabled"}
        )

    # Web UI runs as separate daemon (webui-daemon.sh), not in agent process.
    # Agent communicates state via SQLite (agent/ui_bridge.py).
    webui_port = config.get("webui", {}).get("port", 8888)
    # Check if webui daemon is already running
    import subprocess as _sp
    webui_up = False
    try:
        _r = _sp.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=3)
        webui_up = f":{webui_port}" in _r.stdout
    except Exception:
        pass
    if webui_up:
        services.append(
            {"name": "Web UI", "status": "OK", "detail": f":{webui_port} (daemon)"}
        )
    else:
        # Auto-start the daemon
        try:
            _sp.Popen(["bash", "scripts/webui-daemon.sh", "start"],
                       stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            services.append(
                {"name": "Web UI", "status": "OK", "detail": f":{webui_port} (starting)"}
            )
        except Exception:
            services.append(
                {"name": "Web UI", "status": "SKIP", "detail": "daemon not started"}
            )

    ui.render_boot_sequence(services)

    # Initialize components
    llm = LLMClient(config["model"])
    proxy_url = f"http://127.0.0.1:{proxy_port}"

    loop = AgentLoop(
        config=config,
        llm_client=llm,
        proxy_url=proxy_url,
        ui=ui,
    )

    # Auto-blacklist self to prevent scanning our own services
    # This is critical for Thor — prevents red-teaming its own kali-mcp-server
    try:
        from agent import db as _db
        self_ips = config["mission"]["scope"].get("excluded_hosts", [])
        blacklist = _db.get_state("blacklisted_hosts", [])
        existing_ips = {b.get("ip") for b in blacklist}
        for self_ip in self_ips:
            if self_ip not in existing_ips:
                blacklist.append({"mac": f"self-{self_ip}", "ip": self_ip})
        _db.set_state("blacklisted_hosts", blacklist)
    except Exception:
        pass

    # If already connected, skip WiFi breach — check existing data for phase
    if check_network_connectivity():
        loop.mission_log.set_finding("wifi_connected", True)
        ui.wifi_up = True
        # Evaluate existing findings to determine correct starting phase
        findings = loop.mission_log.get_findings_summary()
        hosts = findings.get("live_hosts", 0)
        ports = findings.get("open_ports", 0)
        creds = findings.get("credentials", 0)
        vulns = findings.get("vulnerabilities", 0)
        if creds > 0 or vulns > 0 or (hosts >= 10 and ports >= 15):
            loop.planner.current_phase = Phase.EXPLOIT
            print(f"  {C.GREEN}[INIT]{C.RESET} Resuming at EXPLOIT ({hosts} hosts, {ports} ports, {creds} creds)")
        elif hosts >= 3:
            loop.planner.current_phase = Phase.ENUMERATE
            print(f"  {C.GREEN}[INIT]{C.RESET} Resuming at ENUMERATE ({hosts} hosts)")
        else:
            loop.planner.current_phase = Phase.RECON
            print(f"  {C.GREEN}[INIT]{C.RESET} Starting at RECON")
        print(f"  {C.GREEN}[INIT]{C.RESET} Network detected — skipping WiFi breach, starting at RECON")

    try:
        await loop.run()
    except KeyboardInterrupt:
        print(f"\n  [STOP] Interrupted by operator.")
    except Exception as e:
        import traceback
        print(f"\n  [FATAL] Unhandled error: {e}", flush=True)
        traceback.print_exc()
    finally:
        await llm.close()


if __name__ == "__main__":
    asyncio.run(main())
