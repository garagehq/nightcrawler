"""Additional recon tools for the exploit pipeline.

- ARP scan for host discovery
- Banner grabbing with netcat
- Credential harvesting from found data
- HTTP content analysis
"""

import re
from agent import db
from agent import host_memory


def get_harvested_usernames():
    """Extract usernames from all host observations for credential spraying.

    Sources: impacket-samrdump output, DNS hostnames, NBNS names,
    HTTP forms, SSH banners.
    """
    usernames = set()
    db.init_db("logs")

    for h in db.get_hosts():
        mac = h.get("mac", "")
        if not mac:
            continue
        mem = host_memory.get_memory(mac)
        obs = mem.get("observations", [])

        for o in obs:
            text = o["text"] if isinstance(o, dict) else o
            text_lower = text.lower()

            # From samrdump: "Users: admin, guest, pi"
            if "users:" in text_lower or "user:" in text_lower:
                parts = re.findall(r'(?:users?:\s*)(.+)', text, re.IGNORECASE)
                for p in parts:
                    for name in p.split(","):
                        name = name.strip().split()[0] if name.strip() else ""
                        if name and len(name) > 1 and name not in ("No", "Found", "N/A"):
                            usernames.add(name)

            # From RID brute: "500: HOSTNAME\Administrator"
            rid_matches = re.findall(r'\d+:\s*\S+\\(\S+)', text)
            for m in rid_matches:
                if m and len(m) > 1:
                    usernames.add(m)

            # From hostname patterns: hostname might suggest usernames
            if "hostname=" in text_lower:
                hname = re.search(r'hostname=(\S+)', text)
                if hname:
                    usernames.add(hname.group(1).lower())

    # Always include common defaults
    defaults = {"admin", "root", "pi", "user", "test", "guest"}
    usernames.update(defaults)

    return list(usernames)


def get_credential_spray_hints(ip, ports, max_hints=3):
    """Generate credential spray hints using harvested usernames.

    Returns hints for services on this host using discovered usernames
    (not just hardcoded defaults).
    """
    usernames = get_harvested_usernames()
    hints = []

    # Get already-failed creds for this host
    mac = ""
    for h in db.get_hosts():
        if h["ip"] == ip:
            mac = h.get("mac", "")
            break
    failed = set(host_memory.get_failed_attacks(mac)) if mac else set()

    # Prioritize analyst-added credentials from the DB
    try:
        analyst_creds = db.get_credentials()
        for c in analyst_creds:
            cred_host = c.get("host", "")
            if cred_host and cred_host != ip:
                continue  # Skip creds assigned to a different host
            svc = c.get("service", "ssh")
            user = c.get("username", "")
            passwd = c.get("password", "")
            if not user or not passwd:
                continue
            proto_map = {"ssh": 22, "smb": 445, "telnet": 23, "vnc": 5900, "ftp": 21, "rdp": 3389}
            needed_port = proto_map.get(svc)
            if needed_port and needed_port in ports:
                key = f"{svc.upper()} {user}:{passwd}"
                if not any(key in f for f in failed):
                    if svc == "vnc":
                        hints.append(f"Try: nxc vnc {ip} -p {passwd} (analyst cred). ")
                    else:
                        hints.append(f"Try: nxc {svc} {ip} -u {user} -p {passwd} (analyst cred). ")
    except Exception:
        pass

    for user in usernames[:10]:  # max 10 users
        if 22 in ports:
            key = f"SSH {user}:"
            if not any(key in f for f in failed):
                hints.append(f"Try: nxc ssh {ip} -u {user} -p {user} (cred spray). ")
        if 23 in ports:
            key = f"TELNET {user}:"
            if not any(key in f for f in failed):
                hints.append(f"Try: nxc telnet {ip} -u {user} -p {user} (cred spray). ")
        if len(hints) >= max_hints:
            break

    return hints


def parse_http_content(ip, url, html_body):
    """Analyze HTTP response body for intelligence.

    Extracts: login forms, version strings, API endpoints,
    internal IPs, comments with developer info.
    """
    findings = []

    if not html_body or len(html_body) < 10:
        return findings

    body_lower = html_body.lower()

    # Login forms
    form_actions = re.findall(
        r'<form[^>]*action=["\']([^"\']+)["\'][^>]*', html_body, re.IGNORECASE)
    if any("login" in a.lower() or "auth" in a.lower() or "sign" in a.lower()
           for a in form_actions):
        findings.append(f"Login form detected: {', '.join(form_actions[:3])}")

    # Version strings in HTML
    versions = []
    # WordPress
    wp = re.search(r'wp-content|wordpress', body_lower)
    if wp:
        ver = re.search(r'ver=(\d+[\d.]+)', html_body)
        versions.append(f"WordPress{' ' + ver.group(1) if ver else ''}")
    # Joomla
    if "joomla" in body_lower:
        versions.append("Joomla")
    # Drupal
    if "drupal" in body_lower:
        ver = re.search(r'Drupal\s+(\d+[\d.]+)', html_body)
        versions.append(f"Drupal{' ' + ver.group(1) if ver else ''}")
    # phpMyAdmin
    if "phpmyadmin" in body_lower:
        versions.append("phpMyAdmin")
    # Tomcat
    if "apache tomcat" in body_lower:
        ver = re.search(r'Apache Tomcat/(\S+)', html_body, re.IGNORECASE)
        versions.append(f"Tomcat{' ' + ver.group(1) if ver else ''}")
    # Jenkins
    if "jenkins" in body_lower:
        ver = re.search(r'Jenkins ver\.\s*(\S+)', html_body)
        versions.append(f"Jenkins{' ' + ver.group(1) if ver else ''}")
    # Generic server version in meta/comments
    gen_ver = re.findall(r'(?:version|ver)[:\s=]+(\d+[\d.]+\S*)', html_body, re.IGNORECASE)
    for v in gen_ver[:2]:
        versions.append(f"Version: {v}")

    if versions:
        findings.append(f"Web frameworks: {', '.join(versions)}")

    # Internal IPs in links/content
    internal_ips = set(re.findall(
        r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        html_body))
    if internal_ips:
        findings.append(f"Internal IPs in response: {', '.join(list(internal_ips)[:5])}")

    # HTML comments (often contain developer info)
    comments = re.findall(r'<!--\s*(.+?)\s*-->', html_body, re.DOTALL)
    interesting = [c.strip()[:60] for c in comments
                   if len(c.strip()) > 5 and not c.strip().startswith("[if")]
    if interesting:
        findings.append(f"HTML comments: {'; '.join(interesting[:3])}")

    # API endpoints
    api_paths = set(re.findall(r'["\'](/api/[^"\'?\s]+)', html_body))
    if api_paths:
        findings.append(f"API endpoints: {', '.join(list(api_paths)[:5])}")

    return findings


def get_arp_scan_command():
    """Generate an arp-scan command for host discovery."""
    return "arp-scan -l -I wlan0 --retry 1 --timeout 500"


def run_arp_scan(interface: str = "wlan0", timeout: int = 10) -> list:
    """Run arp-scan and return parsed [{ip, mac, vendor}] list.

    ARP scan is the right discovery tool for hostile networks:
    - Layer-2 broadcast → bypasses most IP-level firewall rules
    - Doesn't reveal target IPs (unicast probes do)
    - Detects hosts that drop ICMP/TCP but answer ARP (almost all do)

    Returns [] on failure or when no hosts respond.
    """
    import subprocess
    import shutil
    if not shutil.which("arp-scan"):
        return []
    try:
        result = subprocess.run(
            ["arp-scan", "-l", "-I", interface, "--retry", "1", "--timeout", "500"],
            capture_output=True, text=True, timeout=timeout
        )
        hosts = []
        # Output lines look like:  "10.1.79.250\t70:69:5a:31:a3:bf\tCisco Systems, Inc"
        line_re = re.compile(
            r'^((?:\d{1,3}\.){3}\d{1,3})\s+([0-9a-fA-F:]{17})\s*(.*)$'
        )
        for line in result.stdout.splitlines():
            m = line_re.match(line.strip())
            if m:
                hosts.append({
                    "ip": m.group(1),
                    "mac": m.group(2).upper(),
                    "vendor": m.group(3).strip(),
                })
        return hosts
    except Exception:
        return []


def get_banner_grab_command(ip, port):
    """Generate a netcat banner grab command."""
    return f"nc -w 3 -v {ip} {port}"


def get_recon_hints(ip, ports):
    """Generate additional recon hints for unexplored techniques."""
    hints = []
    import random

    # ARP scan (only suggest occasionally)
    if random.random() < 0.05:  # 5% chance
        hints.append(f"Try: arp-scan -l -I wlan0 --retry 1 --timeout 500 (discover hidden hosts). ")

    # UDP scan — SNMP, TFTP, NTP (suggest occasionally, stealth-friendly with -T2)
    if random.random() < 0.08:  # 8% chance
        hints.append(f"Try: nmap -sU -T2 --top-ports 10 {ip} (UDP scan — SNMP/TFTP/NTP). ")

    # Banner grab for unknown services
    unknown_ports = [p for p in ports if p not in
                     {22, 53, 80, 443, 445, 139, 5900, 23, 21, 3306, 5432,
                      6379, 8080, 8443, 8888}]
    if unknown_ports:
        port = random.choice(unknown_ports)
        hints.append(f"Try: nc -w 3 -v {ip} {port} (banner grab unknown service). ")

    return hints
