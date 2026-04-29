"""Command output parser — extracts structured intelligence from raw tool output.

Turns dead text output into:
- Vulnerabilities → DB (shows in web UI)
- Credentials → DB
- Interesting files → host memory
- New targets → scan queue
- CVE IDs → triggers CVE DB lookup for next command
- Service fingerprints → structured port→service cache

This is the "brain" that the 2B model can't be — it understands tool
output formats and extracts actionable data automatically.
"""

import re
from agent import db
from agent import host_memory
from agent import cve_db


def parse_output(ip: str, mac: str, command: str, output: str,
                 status: str) -> dict:
    """Parse command output and extract structured intelligence.

    Returns a dict of extracted data for the agent loop to act on:
    {
        'new_targets': ['192.168.1.50', ...],  # from zone transfers
        'interesting_files': ['config.bak', ...],  # from SMB ls
        'cve_ids': ['CVE-2024-6387', ...],  # from vulners
        'next_command': 'smbclient ...',  # suggested follow-up
        'vulns_added': 2,  # count of new DB entries
    }
    """
    result = {
        'new_targets': [],
        'interesting_files': [],
        'cve_ids': [],
        'next_command': None,
        'vulns_added': 0,
    }

    if not output or status != "success":
        return result

    # Check for actual command-level failures even when proxy says "success"
    error_indicators = [
        "NT_STATUS_ACCESS_DENIED", "NT_STATUS_LOGON_FAILURE",
        "NT_STATUS_BAD_NETWORK_NAME", "NT_STATUS_IO_TIMEOUT",
        "Connection refused", "Host seems down", "No route to host",
        "Authentication failed", "permission denied",
    ]
    out_lower = output.lower()
    if any(e.lower() in out_lower for e in error_indicators):
        # Command ran but the tool reported failure — don't extract "findings"
        return result

    cmd_lower = command.lower()
    out = output

    # ── nmap vulners: extract CVE IDs ──
    if 'vulners' in cmd_lower and 'CVE-' in out:
        cves = list(set(re.findall(r'(CVE-\d{4}-\d+)', out)))
        result['cve_ids'] = cves[:10]  # max 10

        for cve_id in cves[:3]:
            try:
                db.add_vulnerability(ip, "ssh", f"CVE: {cve_id}", "medium")
                result['vulns_added'] += 1
            except Exception:
                pass

        # Trigger CVE DB lookup for follow-up command
        for cve_id in cves[:1]:
            matches = cve_db.lookup("", "")  # broad search
            # Try to find an exploit for this specific CVE
            for entry in cve_db._load_db():
                if entry.get('cve') == cve_id:
                    cmd = entry['commands'][0].format(ip=ip)
                    result['next_command'] = cmd
                    break

    # ── nmap VULNERABLE findings ──
    if '--script=' in cmd_lower and 'VULNERABLE' in out:
        vuln_matches = re.findall(
            r'(smb-vuln-\S+|CVE-\d{4}-\d+|ms\d{2}-\d+).*?VULNERABLE',
            out, re.IGNORECASE | re.DOTALL)
        for vuln in vuln_matches:
            try:
                db.add_vulnerability(ip, "nse", f"VULNERABLE: {vuln}", "critical")
                result['vulns_added'] += 1
            except Exception:
                pass

    # ── smbclient ls: extract interesting files ──
    if 'smbclient' in cmd_lower and '-c' in cmd_lower:
        # Look for interesting filenames in directory listings
        interesting_patterns = [
            r'(\S+\.(?:conf|config|cfg|ini|bak|backup|old|key|pem|crt|'
            r'env|passwd|shadow|htpasswd|db|sql|dump|log|txt|xml|json|'
            r'yml|yaml|csv|sh|py|pl|rb))\s',
        ]
        for pattern in interesting_patterns:
            files = re.findall(pattern, out, re.IGNORECASE)
            result['interesting_files'].extend(files)

        if result['interesting_files']:
            files_str = ', '.join(result['interesting_files'][:5])
            host_memory.add_observation(
                mac, f"Interesting files on share: {files_str}",
                source="agent", ip=ip)
            # Safe download: just list the file to prove read access
            # (kali-mcp uses shlex, no shell chaining with &&)
            for f in result['interesting_files']:
                if any(f.endswith(ext) for ext in ['.conf', '.env', '.bak',
                       '.passwd', '.key', '.pem']):
                    share = _extract_share(command)
                    if share:
                        # Use smbclient -c 'more file' to peek at contents
                        result['next_command'] = (
                            f"smbclient -N //{ip}/{share} -c 'more {f}'")
                        try:
                            db.add_vulnerability(
                                ip, "smb",
                                f"Readable file on share: {share}/{f}",
                                "high",
                                chain=f"smbclient -N //{ip}/{share} -c 'ls' → found {f}")
                        except Exception:
                            pass
                    break

    # ── dig axfr: extract hostnames as new targets ──
    if 'axfr' in cmd_lower and 'XFR size' in out:
        # Zone transfer succeeded!
        try:
            db.add_vulnerability(ip, "dns", "DNS zone transfer allowed (AXFR)",
                                 "high", chain=f"dig axfr @{ip} → zone data exposed")
            result['vulns_added'] += 1
        except Exception:
            pass

        # Extract A records → new targets
        a_records = re.findall(
            r'(\S+)\.\s+\d+\s+IN\s+A\s+(192\.168\.1\.\d+)', out)
        for hostname, target_ip in a_records:
            result['new_targets'].append(target_ip)
            host_memory.add_observation(
                mac, f"AXFR revealed: {hostname} → {target_ip}",
                source="agent", ip=ip)

    # ── nxc success: auto-record credentials ──
    if 'nxc' in cmd_lower and '[+]' in out:
        # Already handled by host_memory.auto_extract_observations
        # but we can suggest post-exploit follow-up
        if 'ssh' in cmd_lower:
            user_match = re.search(r'-u\s+(\S+)', command)
            pass_match = re.search(r"-p\s+'?([^'\s]+)", command)
            if user_match and pass_match:
                user = user_match.group(1)
                passwd = pass_match.group(1)
                result['next_command'] = (
                    f"sshpass -p '{passwd}' ssh -o StrictHostKeyChecking=no "
                    f"{user}@{ip} 'cat /etc/passwd; uname -a'")

    # ── nikto: extract findings ──
    if 'nikto' in cmd_lower:
        findings = re.findall(r'\+ (OSVDB-\d+|CVE-\d{4}-\d+):\s*(.+)', out)
        for vuln_id, desc in findings[:5]:
            try:
                db.add_vulnerability(ip, "http", f"{vuln_id}: {desc[:60]}",
                                     "medium")
                result['vulns_added'] += 1
            except Exception:
                pass

    # ── curl: detect interesting responses ──
    if 'curl' in cmd_lower:
        if 'robots.txt' in cmd_lower and 'Disallow' in out:
            paths = re.findall(r'Disallow:\s*(\S+)', out)
            if paths:
                host_memory.add_observation(
                    mac, f"robots.txt paths: {', '.join(paths[:5])}",
                    source="agent", ip=ip)
                # Suggest probing the first disallowed path
                result['next_command'] = f"curl -s http://{ip}{paths[0]}"

        if '.env' in cmd_lower and out.strip() and '404' not in out:
            if any(w in out for w in ['DB_', 'PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
                host_memory.add_observation(
                    mac, f"CRITICAL: .env file contains secrets!",
                    source="agent", ip=ip)
                try:
                    db.add_vulnerability(ip, "http",
                        ".env exposed with secrets", "critical")
                    result['vulns_added'] += 1
                except Exception:
                    pass

    # ── impacket-samrdump: extract usernames ──
    if 'samrdump' in cmd_lower:
        users = re.findall(r'(\w+)\s+\(\d+\)\s+.*User', out)
        if users:
            users_str = ', '.join(users[:10])
            host_memory.add_observation(
                mac, f"SAM users found: {users_str}",
                source="agent", ip=ip)
            # Suggest trying found usernames with default passwords
            if users:
                result['next_command'] = (
                    f"nxc ssh {ip} -u {users[0]} -p {users[0]}")

    # ── impacket-rpcdump: note endpoints ──
    if 'rpcdump' in cmd_lower and 'Protocol' in out:
        endpoint_count = out.count('Protocol:')
        if endpoint_count > 0:
            host_memory.add_observation(
                mac, f"RPC endpoints: {endpoint_count} found",
                source="agent", ip=ip)

    # ── Service fingerprinting from any nmap output ──
    if 'nmap' in cmd_lower and 'open' in out:
        services = re.findall(
            r'(\d+)/tcp\s+open\s+(\S+)\s+(.*)', out)
        for port, svc, banner in services:
            banner = banner.strip()[:60]
            if banner:
                # Store structured fingerprint
                _store_fingerprint(ip, mac, int(port), svc, banner)

    return result


def _extract_share(command: str) -> str:
    """Extract share name from smbclient command."""
    m = re.search(r'//[\d.]+/(\S+)', command)
    return m.group(1) if m else ""


def _store_fingerprint(ip: str, mac: str, port: int, service: str,
                       banner: str):
    """Store structured service fingerprint for CVE DB lookups."""
    try:
        fingerprints = db.get_state("service_fingerprints", {})
        key = f"{ip}:{port}"
        fingerprints[key] = {
            "ip": ip, "mac": mac, "port": port,
            "service": service, "banner": banner,
        }
        db.set_state("service_fingerprints", fingerprints)
    except Exception:
        pass


def get_fingerprints(ip: str) -> list:
    """Get all service fingerprints for a host."""
    try:
        fingerprints = db.get_state("service_fingerprints", {})
        return [v for k, v in fingerprints.items() if v.get("ip") == ip]
    except Exception:
        return []
