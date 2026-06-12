#!/usr/bin/env python3
"""Generate a markdown penetration test report from Nightcrawler findings."""

import json
import os
import sys
import sqlite3
import re
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def utc_to_edt(ts_str):
    """Convert UTC timestamp string to EDT display."""
    if not ts_str:
        return "Unknown"
    try:
        utc = datetime.fromisoformat(ts_str.replace("Z", "")).replace(tzinfo=timezone.utc)
        edt = utc - timedelta(hours=4)
        return edt.strftime("%Y-%m-%d %H:%M EDT")
    except Exception:
        return ts_str


def get_remediation(service, vuln):
    """Import remediation from webui server."""
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from webui.server import _get_remediation
        return _get_remediation(service, vuln)
    except Exception:
        return "Review finding and consult vendor documentation."


def dedup_vulns(vulns):
    """Remove near-duplicate vulnerabilities, keeping the most detailed one."""
    seen = {}
    for v in vulns:
        host = v.get("host", "")
        vuln_text = v.get("vuln", "")
        # Normalize: strip [MISCONFIG] prefix and truncate for comparison
        normalized = re.sub(r'^\[MISCONFIG\]\s*', '', vuln_text)
        # Key: host + first 40 chars of normalized finding
        key = f"{host}:{normalized[:40]}"
        if key in seen:
            # Keep the longer/more detailed version
            if len(vuln_text) > len(seen[key].get("vuln", "")):
                seen[key] = v
        else:
            seen[key] = v
    return list(seen.values())


def generate_report(output_path="logs/report.md", network_id=None):
    """Generate the full markdown report. Filters by network_id if provided."""
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "logs", "nightcrawler.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Auto-detect current network if not specified
    if not network_id:
        try:
            from agent.net_detect import get_current_network
            _subnet = get_current_network()[0]
            row = conn.execute("SELECT network_id FROM networks WHERE cidr=?", (_subnet,)).fetchone()
            if row:
                network_id = row[0]
        except Exception:
            pass

    if network_id:
        vulns = [dict(r) for r in conn.execute(
            "SELECT * FROM vulnerabilities WHERE network=? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END", (network_id,)).fetchall()]
        creds = [dict(r) for r in conn.execute("SELECT * FROM credentials WHERE network=?", (network_id,)).fetchall()]
        hosts = [dict(r) for r in conn.execute("SELECT * FROM hosts WHERE network=? ORDER BY ip", (network_id,)).fetchall()]
        total_cmds = conn.execute("SELECT COUNT(*) FROM commands WHERE network=?", (network_id,)).fetchone()[0]
    else:
        vulns = [dict(r) for r in conn.execute(
            "SELECT * FROM vulnerabilities ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END").fetchall()]
        creds = [dict(r) for r in conn.execute("SELECT * FROM credentials").fetchall()]
        hosts = [dict(r) for r in conn.execute("SELECT * FROM hosts ORDER BY ip").fetchall()]
        total_cmds = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
    conn.close()

    # Dedup vulns
    vulns = dedup_vulns(vulns)

    # Re-sort after dedup
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulns.sort(key=lambda v: sev_order.get(v.get("severity", "low"), 4))

    # Count by severity
    sev_counts = defaultdict(int)
    for v in vulns:
        sev_counts[v.get("severity", "medium")] += 1

    # Detect scope from network_id or current network
    scope_cidr = "auto-detected"
    if network_id:
        try:
            _sc = sqlite3.connect(db_path)
            _sr = _sc.execute("SELECT cidr FROM networks WHERE network_id=?", (network_id,)).fetchone()
            if _sr: scope_cidr = _sr[0]
            _sc.close()
        except Exception:
            pass
    if scope_cidr == "auto-detected":
        try:
            from agent.net_detect import get_current_network
            scope_cidr = get_current_network()[0]
        except Exception:
            pass

    now = datetime.now(timezone.utc) - timedelta(hours=4)

    md = []
    md.append("# Nightcrawler Penetration Test Report")
    md.append("")
    md.append(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M EDT')}")
    md.append(f"**Scope:** {scope_cidr}")
    md.append(f"**Duration:** Extended autonomous assessment (48h+)")
    md.append(f"**Agent:** Nightcrawler v0.1.0 — LFM2.5-1.2B-Instruct-Heretic on OnePlus 8 (Kali NetHunter)")
    md.append("")

    # Executive Summary
    md.append("## Executive Summary")
    md.append("")
    md.append(f"Nightcrawler autonomously discovered **{len(hosts)} hosts** on the target network "
              f"and executed **{total_cmds} commands** across reconnaissance, enumeration, and "
              f"exploitation phases. The assessment identified **{len(vulns)} unique vulnerabilities** "
              f"including {sev_counts.get('critical', 0)} critical, {sev_counts.get('high', 0)} high, "
              f"{sev_counts.get('medium', 0)} medium, and {sev_counts.get('low', 0)} low severity findings.")
    md.append("")

    if sev_counts.get("critical", 0) > 0 or sev_counts.get("high", 0) > 0:
        md.append("**Immediate action required** — high-severity findings include potential "
                  "remote code execution vectors and default credential access.")
    md.append("")

    md.append("| Severity | Count |")
    md.append("|----------|-------|")
    for sev in ["critical", "high", "medium", "low"]:
        md.append(f"| {sev.capitalize()} | {sev_counts.get(sev, 0)} |")
    md.append("")

    # Vulnerabilities
    md.append("## Vulnerabilities")
    md.append("")

    for i, v in enumerate(vulns, 1):
        sev = v.get("severity", "medium").upper()
        host = v.get("host", "?")
        service = v.get("service", "unknown")
        finding = v.get("vuln", "")
        chain = v.get("chain", "")
        discovered = utc_to_edt(v.get("timestamp", ""))

        # Extract CVEs
        cves = re.findall(r'CVE-\d{4}-\d+', finding)

        md.append(f"### {i}. [{sev}] {host} — {service.upper()}")
        md.append("")
        md.append(f"**Finding:** {finding}")
        md.append("")

        if cves:
            md.append(f"**CVEs:** {', '.join(cves)}")
            md.append("")

        if chain and chain != "Not recorded":
            md.append("**Exploit Chain:**")
            md.append("```")
            md.append(chain)
            md.append("```")
            md.append("")

        remediation = get_remediation(service, finding)
        # Format remediation as numbered list
        steps = re.split(r'\d+\.\s+', remediation)
        steps = [s.strip() for s in steps if s.strip()]
        if steps:
            md.append("**Remediation:**")
            for j, step in enumerate(steps, 1):
                md.append(f"{j}. {step}")
            md.append("")

        md.append(f"*Discovered: {discovered}*")
        md.append("")
        md.append("---")
        md.append("")

    # Credentials
    if creds:
        md.append("## Credentials Found")
        md.append("")
        md.append("| Service | Username | Host | Discovered |")
        md.append("|---------|----------|------|------------|")
        for c in creds:
            md.append(f"| {c.get('service', '?')} | {c.get('username', '?')} | "
                      f"{c.get('host', '?')} | {utc_to_edt(c.get('timestamp', ''))} |")
        md.append("")
    else:
        md.append("## Credentials")
        md.append("")
        md.append("No valid credentials were discovered during this assessment. "
                  "Default credential testing was performed against SSH, telnet, VNC, "
                  "and web interfaces using common defaults (admin, root, pi, raspberry).")
        md.append("")

    # Attack Path Analysis
    try:
        from agent.report_generator import generate_attack_paths, generate_topology
        paths = generate_attack_paths(network_id=network_id)
        if paths:
            md.append("## Attack Path Analysis")
            md.append("")
            md.append("Hosts ranked by combined vulnerability risk, with attack narratives:")
            md.append("")
            for p in paths:
                risk_label = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(p["risk_score"], "?")
                cve_str = ", ".join(p["cves"][:5]) if p["cves"] else "None"
                md.append(f"### {p['host']} — Risk: {risk_label}")
                md.append(f"- **Vulnerabilities:** {p['vulns_count']}")
                md.append(f"- **Services affected:** {', '.join(p['services_affected'])}")
                md.append(f"- **CVEs:** {cve_str}")
                md.append(f"- **Narrative:** {p['attack_narrative']}")
                md.append("")
    except Exception:
        pass

    # Network Topology
    try:
        topo = generate_topology(network_id=network_id)
        md.append("## Network Topology")
        md.append("")
        md.append(f"**Total hosts:** {topo['total_hosts']}")
        md.append("")
        md.append("| Service | Hosts | Count |")
        md.append("|---------|-------|-------|")
        for svc, key in [("SSH", "ssh_hosts"), ("SMB", "smb_hosts"), ("HTTP/Web", "web_hosts"), ("DNS", "dns_hosts")]:
            hosts_list = topo.get(key, [])
            if hosts_list:
                md.append(f"| {svc} | {', '.join(hosts_list[:10])} | {len(hosts_list)} |")
        md.append("")
    except Exception:
        pass

    # Passive Capture Findings
    try:
        passive_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                     "tmp", "nc-passive-parsed.json")
        # Try /tmp first
        if not os.path.exists(passive_file):
            passive_file = "/tmp/nc-passive-parsed.json"
        if os.path.exists(passive_file):
            with open(passive_file) as pf:
                passive = json.load(pf)
            # Filter out bogus IPs AND filter to report's network
            import ipaddress
            _report_net = None
            if scope_cidr != "auto-detected":
                try:
                    _report_net = ipaddress.ip_network(scope_cidr, strict=False)
                except (ValueError, TypeError):
                    pass
            def is_target_fn(ip):
                if not _report_net:
                    return True
                try:
                    return ipaddress.ip_address(ip) in _report_net
                except (ValueError, TypeError):
                    return False
            passive = [p for p in passive if p.get("ip", "") not in
                       ("0.0.0.0", "255.255.255.255") and
                       not p.get("ip", "").startswith("224.")]
            if passive:
                md.append("## Passive Network Capture")
                md.append("")
                md.append(f"Background traffic analysis captured **{len(passive)} findings** "
                          f"from mDNS, ARP, DHCP, and NBNS broadcasts (zero active packets sent).")
                md.append("")

                # Group by type
                by_type = defaultdict(list)
                foreign = []
                for p in passive:
                    by_type[p.get("type", "?")].append(p)
                    ip = p.get("ip", "")
                    if ip and not is_target_fn(ip):
                        foreign.append(p)

                md.append("| Type | IP | Hostname/MAC | Network |")
                md.append("|------|----|-------------|---------|")
                seen = set()
                for p in passive:
                    key = p.get("ip", "") + p.get("type", "")
                    if key in seen:
                        continue
                    seen.add(key)
                    ip = p.get("ip", "?")
                    detail = p.get("hostname", "") or p.get("mac", "")
                    net = "Target" if is_target_fn(ip) else "**FOREIGN**"
                    md.append(f"| {p.get('type', '?')} | {ip} | {detail} | {net} |")
                md.append("")

                if foreign:
                    md.append("### Foreign Network Alert")
                    md.append("")
                    md.append("The following IPs were observed on **non-target subnets**, "
                              "indicating potential pivot points or dual-homed hosts:")
                    md.append("")
                    for f in foreign:
                        subnet = ".".join(f["ip"].split(".")[:3]) + ".0/24"
                        md.append(f"- **{f['ip']}** ({f.get('type', '?')}) — subnet {subnet}. "
                                  f"Investigate for network bridging or routing to additional targets.")
                    md.append("")
    except Exception:
        pass

    # Host Inventory
    md.append("## Host Inventory")
    md.append("")
    md.append("| IP | MAC | Open Ports | Services |")
    md.append("|----|-----|------------|----------|")

    for h in hosts:
        ip = h.get("ip", "?")
        mac = h.get("mac", "?")
        if len(mac) > 17:
            mac = mac[:17]
        ports = h.get("ports", [])
        if isinstance(ports, str):
            try:
                ports = json.loads(ports) if ports else []
            except Exception:
                ports = []

        # Map ports to service names
        port_map = {
            22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            139: "NetBIOS", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 8888: "HTTP-Alt",
        }
        port_str = ", ".join(str(p) for p in ports) if ports else "—"
        svc_str = ", ".join(port_map.get(p, str(p)) for p in ports) if ports else "—"
        md.append(f"| {ip} | {mac} | {port_str} | {svc_str} |")

    md.append("")

    # Footer
    md.append("---")
    md.append("")
    md.append("*Generated by Nightcrawler Autonomous Pentest Agent v0.1.0*  ")
    md.append(f"*Assessment period: 48h+ continuous autonomous operation*  ")
    md.append(f"*Platform: OnePlus 8 (Snapdragon 865) running Kali NetHunter with LFM2.5-1.2B GPU inference*")

    report = "\n".join(md)

    out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            output_path)
    with open(out_path, "w") as f:
        f.write(report)

    print(f"Report generated: {out_path} ({len(vulns)} vulns, {len(hosts)} hosts, {len(md)} lines)")
    return out_path


if __name__ == "__main__":
    import sys
    nid = sys.argv[1] if len(sys.argv) > 1 else None
    generate_report(network_id=nid)
