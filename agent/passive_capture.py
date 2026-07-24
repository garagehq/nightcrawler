"""Passive network capture — discovers hosts/services from broadcast traffic.

Runs tcpdump in the background, parses mDNS, NBNS, DHCP, ARP broadcasts.
Zero stealth cost — only listens, never sends packets.
"""

import subprocess
import threading
import time
import re
import os
import json

from agent import db
from agent import host_memory


CAPTURE_FILE = "/tmp/nc-passive.pcap"
PARSED_FILE = "/tmp/nc-passive-parsed.json"
_capture_proc = None
_running = False
_continuous = False  # set True to make captures auto-restart in a loop


def is_running() -> bool:
    """True if tcpdump is currently capturing.

    Checks the live process, not just the module flag — so stale state from
    a crashed capture doesn't keep the function returning True forever.
    """
    global _capture_proc, _running
    if _capture_proc is None:
        _running = False
        return False
    if _capture_proc.poll() is not None:
        # Process exited
        _running = False
        _capture_proc = None
        return False
    return _running


def start_capture(interface="wlan0", duration=300):
    """Start background tcpdump for broadcast/multicast traffic."""
    global _capture_proc, _running
    if is_running():
        return

    # Kill any orphan tcpdump processes left over from a previous agent
    # restart. is_running() only checks THIS process's tracking, but tcpdump
    # children inherited by init survive across agent restarts and would
    # accumulate (4 running after a few restarts in testing).
    try:
        subprocess.run(
            ["pkill", "-f", f"tcpdump.*{CAPTURE_FILE}"],
            timeout=5
        )
    except Exception:
        pass

    # Capture broadcast traffic only: mDNS, NBNS, DHCP, ARP
    # BPF filter: only broadcast/multicast, limited rate
    cmd = [
        "tcpdump", "-i", interface, "-nn", "-q",
        "-U",  # unbuffered — flush packets to file immediately
        "-c", "5000",  # max 5000 packets per capture cycle
        "-w", CAPTURE_FILE,
        "(arp or port 5353 or port 137 or port 67 or port 68)",
    ]

    try:
        _capture_proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _running = True

        # Auto-stop after duration
        def _stop_after():
            time.sleep(duration)
            stop_capture()

        t = threading.Thread(target=_stop_after, daemon=True)
        t.start()
    except Exception:
        _running = False


def start_continuous(interface="wlan0", cycle_seconds=300):
    """Run passive capture in an infinite loop — best for stealth recon.

    On a client-isolated network, broadcast traffic is the only reliable
    signal of other hosts (DHCP renewals, mDNS announcements, ARP requests).
    A one-shot 2-minute capture misses most of it. Run continuously instead.
    Idempotent — calling twice has no effect.
    """
    global _continuous
    if _continuous:
        return
    _continuous = True

    def _loop():
        while _continuous:
            try:
                start_capture(interface=interface, duration=cycle_seconds)
                # Wait for the capture to finish, then parse + ingest results
                # before the next cycle so each cycle's data lands in the DB.
                time.sleep(cycle_seconds + 5)
                try:
                    findings = parse_capture()
                    if findings:
                        ingest_findings(findings)
                except Exception:
                    pass
            except Exception:
                time.sleep(30)  # back off on repeated failure

    threading.Thread(target=_loop, daemon=True).start()


def stop_continuous():
    """Stop the continuous capture loop after the current cycle completes."""
    global _continuous
    _continuous = False


def stop_capture():
    """Stop the background capture."""
    global _capture_proc, _running
    if _capture_proc:
        try:
            _capture_proc.terminate()
            _capture_proc.wait(timeout=5)
        except Exception:
            try:
                _capture_proc.kill()
            except Exception:
                pass
    _capture_proc = None
    _running = False


def parse_capture():
    """Parse the capture file and extract host info."""
    if not os.path.exists(CAPTURE_FILE):
        return []

    findings = []

    try:
        # Use tshark to extract fields
        # mDNS: hostnames
        result = subprocess.run(
            ["tshark", "-r", CAPTURE_FILE, "-Y", "mdns",
             "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name",
             "-e", "dns.a"],
            capture_output=True, text=True, timeout=30)

        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts = line.split("\t")
                ip = parts[0] if len(parts) > 0 else ""
                hostname = parts[1] if len(parts) > 1 else ""
                resolved = parts[2] if len(parts) > 2 else ""
                if ip and hostname:
                    findings.append({
                        "type": "mdns",
                        "ip": ip,
                        "hostname": hostname.replace(".local.", ""),
                        "resolved": resolved
                    })

        # mDNS PTR records — actual device names (e.g., "Living-Room-TV._airplay._tcp.local")
        try:
            result2 = subprocess.run(
                ["tshark", "-r", CAPTURE_FILE, "-Y", "mdns && dns.ptr.domain_name",
                 "-T", "fields", "-e", "ip.src", "-e", "dns.ptr.domain_name"],
                capture_output=True, text=True, timeout=30)
            for line in result2.stdout.strip().split("\n"):
                if line.strip():
                    parts = line.split("\t")
                    ip = parts[0] if len(parts) > 0 else ""
                    ptr_name = parts[1] if len(parts) > 1 else ""
                    if ip and ptr_name and not ptr_name.startswith("_"):
                        # Extract device name from PTR (before first ._)
                        device = ptr_name.split("._")[0] if "._" in ptr_name else ptr_name
                        device = device.replace(".local", "").strip(".")
                        if device and len(device) > 1:
                            findings.append({
                                "type": "mdns",
                                "ip": ip,
                                "hostname": device,
                                "resolved": ptr_name
                            })
                            # Update hosts table with hostname
                            try:
                                import sqlite3
                                conn = sqlite3.connect(
                                    os.path.join(os.path.dirname(os.path.dirname(
                                        os.path.abspath(__file__))), "logs", "nightcrawler.db"))
                                conn.execute(
                                    "UPDATE hosts SET hostname=? WHERE ip=? AND (hostname IS NULL OR hostname='')",
                                    (device, ip))
                                conn.commit()
                                conn.close()
                            except Exception:
                                pass
        except Exception:
            pass

        # DHCP hostnames
        try:
            result3 = subprocess.run(
                ["tshark", "-r", CAPTURE_FILE, "-Y", "dhcp",
                 "-T", "fields", "-e", "ip.src", "-e", "dhcp.option.hostname"],
                capture_output=True, text=True, timeout=30)
            for line in result3.stdout.strip().split("\n"):
                if line.strip():
                    parts = line.split("\t")
                    ip = parts[0] if len(parts) > 0 else ""
                    dhcp_name = parts[1] if len(parts) > 1 else ""
                    if ip and dhcp_name and ip not in ("0.0.0.0", "255.255.255.255"):
                        findings.append({
                            "type": "dhcp",
                            "ip": ip,
                            "hostname": dhcp_name
                        })
                        try:
                            import sqlite3
                            conn = sqlite3.connect(
                                os.path.join(os.path.dirname(os.path.dirname(
                                    os.path.abspath(__file__))), "logs", "nightcrawler.db"))
                            conn.execute(
                                "UPDATE hosts SET hostname=? WHERE ip=? AND (hostname IS NULL OR hostname='')",
                                (dhcp_name, ip))
                            conn.commit()
                            conn.close()
                        except Exception:
                            pass
        except Exception:
            pass

        # ARP: MAC-to-IP mappings
        result = subprocess.run(
            ["tshark", "-r", CAPTURE_FILE, "-Y", "arp",
             "-T", "fields", "-e", "arp.src.hw_mac", "-e", "arp.src.proto_ipv4"],
            capture_output=True, text=True, timeout=30)

        seen_arp = set()
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts = line.split("\t")
                mac = parts[0] if len(parts) > 0 else ""
                ip = parts[1] if len(parts) > 1 else ""
                if ip and mac and ip not in seen_arp:
                    seen_arp.add(ip)
                    findings.append({
                        "type": "arp",
                        "ip": ip,
                        "mac": mac.upper()
                    })

        # NBNS: NetBIOS names
        result = subprocess.run(
            ["tshark", "-r", CAPTURE_FILE, "-Y", "nbns",
             "-T", "fields", "-e", "ip.src", "-e", "nbns.name"],
            capture_output=True, text=True, timeout=30)

        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts = line.split("\t")
                ip = parts[0] if len(parts) > 0 else ""
                name = parts[1] if len(parts) > 1 else ""
                if ip and name:
                    findings.append({
                        "type": "nbns",
                        "ip": ip,
                        "hostname": name.strip()
                    })

    except Exception:
        pass

    # Accumulate parsed results (don't overwrite previous)
    try:
        existing = []
        if os.path.exists(PARSED_FILE):
            with open(PARSED_FILE) as f:
                existing = json.load(f)

        # Dedup by ip+type
        seen = set()
        for e in existing:
            seen.add(f"{e.get('ip','')}:{e.get('type','')}")

        for f in findings:
            key = f"{f.get('ip','')}:{f.get('type','')}"
            if key not in seen:
                existing.append(f)
                seen.add(key)

        with open(PARSED_FILE, "w") as f:
            json.dump(existing, f, indent=2)

        findings = existing  # return accumulated
    except Exception:
        pass

    return findings


def ingest_findings(findings):
    """Add passive findings to the host database.

    Also detects foreign networks (10.x, 172.16-31.x, different 192.168.x)
    and records them as high-value observations for pivot analysis.
    """
    db.init_db("logs")
    added = 0
    foreign_nets = set()

    # Our own IP shows up in our own ARP requests (when WE scan something,
    # we broadcast ARP). Filter it out so the agent doesn't end up with a
    # phantom "host" pointing at itself, which then triggers same-host
    # rejection loops and out-of-scope blocks.
    from agent.net_detect import get_current_network as _gcn
    try:
        _, _, _our_ip, _gw_ip = _gcn()
    except Exception:
        _our_ip, _gw_ip = None, None

    for f in findings:
        ip = f.get("ip", "")
        if not ip:
            continue

        # Skip non-routable/broadcast/self IPs
        if ip in ("0.0.0.0", "255.255.255.255") or ip.startswith("224.") or ip.startswith("239."):
            continue
        if _our_ip and ip == _our_ip:
            continue

        hostname = f.get("hostname", "")
        mac = f.get("mac", "")
        ftype = f.get("type", "")

        # Detect foreign networks using dynamic subnet detection
        import re
        from agent.net_detect import is_target_ip
        is_target = is_target_ip(ip)
        is_private = (ip.startswith("10.") or
                      bool(re.match(r'^172\.(1[6-9]|2\d|3[01])\.', ip)) or
                      ip.startswith("192.168."))

        if is_private and not is_target:
            subnet = ".".join(ip.split(".")[:3]) + ".0/24"
            # Track observed foreign subnets as a recon breadcrumb ONLY — do NOT
            # record them as vulnerabilities. A stray broadcast/multicast packet
            # (mDNS/NBNS/DHCP/ARP) carrying an out-of-scope source IP does not
            # establish reachability or any exposure; these devices are never
            # even probed. Recording each one as a "high" finding produced false
            # positives that dominated the vuln table (~83%) against phantom
            # hosts. Foreign subnets are recon context, not findings.
            foreign_nets.add(subnet)

        if not is_target:
            continue  # Don't add non-target hosts to the host DB

        # Try to find existing host
        existing = None
        for h in db.get_hosts():
            if h["ip"] == ip:
                existing = h
                break

        if existing:
            _mac = existing.get("mac", "")
            if _mac:
                if hostname and not hostname.startswith("_"):
                    # Real hostname (not mDNS service type)
                    obs_text = f"Passive {ftype}: hostname={hostname}"
                    host_memory.add_observation(_mac, obs_text,
                                                source="passive", ip=ip)
                    # Update hosts table
                    try:
                        import sqlite3
                        conn = sqlite3.connect(
                            os.path.join(os.path.dirname(os.path.dirname(
                                os.path.abspath(__file__))), "logs", "nightcrawler.db"))
                        conn.execute(
                            "UPDATE hosts SET hostname=? WHERE ip=? AND (hostname IS NULL OR hostname='')",
                            (hostname, ip))
                        conn.commit()
                        conn.close()
                    except Exception:
                        pass
                    added += 1
                elif hostname:
                    # mDNS service type — store as observation but not hostname
                    obs_text = f"Passive {ftype}: service={hostname}"
                    host_memory.add_observation(_mac, obs_text,
                                                source="passive", ip=ip)
                    added += 1
                if mac and mac != _mac:
                    obs_text = f"Passive ARP: additional MAC {mac} (possible spoofing)"
                    host_memory.add_observation(_mac, obs_text,
                                                source="passive", ip=ip)
                    added += 1
        elif ftype == "arp" and mac and is_target:
            # ARP from unknown host on target network — discovered passively!
            try:
                db.upsert_host(ip, ports=[], info=f"Discovered via passive ARP (MAC: {mac})")
                host_memory.add_observation(mac, f"Discovered via passive ARP capture",
                                            source="passive", ip=ip)
                added += 1
                foreign_nets.discard(ip)  # not foreign, just newly discovered
            except Exception:
                pass

    # Attempt reverse DNS for hosts without hostnames
    try:
        import subprocess
        for h in db.get_hosts():
            if not h.get("hostname") and h.get("ip", "").startswith(_prefix if "_prefix" in dir() else "192.168.0."):
                try:
                    result = subprocess.run(
                        ["dig", "+short", "-x", h["ip"]],
                        capture_output=True, text=True, timeout=3)
                    name = result.stdout.strip().rstrip(".")
                    if name and name != h["ip"] and "NXDOMAIN" not in name:
                        import sqlite3
                        conn = sqlite3.connect(
                            os.path.join(os.path.dirname(os.path.dirname(
                                os.path.abspath(__file__))), "logs", "nightcrawler.db"))
                        conn.execute("UPDATE hosts SET hostname=? WHERE ip=?", (name, h["ip"]))
                        conn.commit()
                        conn.close()
                        added += 1
                except Exception:
                    pass
    except Exception:
        pass

    return added


def run_capture_cycle(interface="wlan0", duration=120):
    """Run one full capture→parse→ingest cycle."""
    start_capture(interface, duration)
    # Wait for capture to finish
    time.sleep(duration + 5)
    findings = parse_capture()
    count = ingest_findings(findings)

    # Cleanup capture file
    try:
        os.remove(CAPTURE_FILE)
    except Exception:
        pass

    return {"findings": len(findings), "ingested": count}
