"""Enhanced report generation with network topology and attack paths.

Produces a comprehensive pentest report with:
- Executive summary
- Network topology (host groupings, shared services)
- Vulnerability findings with CVEs and remediation
- Attack path analysis
- Credential findings
- Recommendations
"""

import json
from collections import defaultdict
from agent import db
from agent import host_memory


def generate_topology(network_id=None):
    """Build network topology from discovered hosts."""
    db.init_db("logs")
    hosts = db.get_hosts(network_id=network_id) if network_id else db.get_hosts()
    topology = {
        "total_hosts": len(hosts),
        "groups": {},
        "ssh_hosts": [],
        "smb_hosts": [],
        "web_hosts": [],
        "dns_hosts": [],
        "other_services": [],
    }

    for h in hosts:
        ip = h.get("ip", "")
        ports = h.get("ports", [])
        if isinstance(ports, str):
            try:
                ports = json.loads(ports)
            except Exception:
                ports = []

        # Group by service type
        if 22 in ports:
            topology["ssh_hosts"].append(ip)
        if 445 in ports or 139 in ports:
            topology["smb_hosts"].append(ip)
        if any(p in ports for p in [80, 443, 8080, 8443]):
            topology["web_hosts"].append(ip)
        if 53 in ports:
            topology["dns_hosts"].append(ip)

        # Group by subnet octet for topology
        octet = ip.split(".")[-1] if ip else "?"
        group = "low" if int(octet) < 50 else "mid" if int(octet) < 150 else "high"
        topology["groups"].setdefault(group, []).append(ip)

    return topology


def generate_attack_paths(network_id=None):
    """Identify potential attack paths from findings."""
    db.init_db("logs")
    vulns = db.get_vulnerabilities(network_id=network_id) if network_id else db.get_vulnerabilities()
    paths = []

    # Group vulns by host
    host_vulns = defaultdict(list)
    for v in vulns:
        host_vulns[v["host"]].append(v)

    for host, hvulns in host_vulns.items():
        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_sev = max(severity_scores.get(v.get("severity", "low"), 1)
                      for v in hvulns)

        services = list(set(v.get("service", "") for v in hvulns))
        cve_list = []
        for v in hvulns:
            import re
            cves = re.findall(r'CVE-\d{4}-\d+', v.get("vuln", ""))
            cve_list.extend(cves)

        path = {
            "host": host,
            "risk_score": max_sev,
            "vulns_count": len(hvulns),
            "services_affected": services,
            "cves": list(set(cve_list)),
            "attack_narrative": _build_narrative(host, hvulns),
        }
        paths.append(path)

    # Sort by risk score descending
    paths.sort(key=lambda x: -x["risk_score"])
    return paths


def _build_narrative(host, vulns):
    """Build a human-readable attack narrative for a host."""
    parts = []
    svc_set = set()

    for v in vulns:
        svc = v.get("service", "")
        vuln_text = v.get("vuln", "")
        svc_set.add(svc)

        if "null-session" in vuln_text.lower() or "smb shares" in vuln_text.lower():
            parts.append(f"SMB shares are accessible without authentication")
        elif "pi-hole" in vuln_text.lower() and "login" in vuln_text.lower():
            parts.append(f"Pi-hole admin accepts default credentials")
        elif "cve-2024-6387" in vuln_text.lower():
            parts.append(f"SSH is vulnerable to regreSSHion (unauthenticated RCE)")
        elif "vnc" in vuln_text.lower():
            parts.append(f"VNC is exposed with weak/no authentication")
        elif "telnet" in vuln_text.lower():
            parts.append(f"Telnet exposes all traffic in plaintext")
        elif "dns" in vuln_text.lower() and "resolver" in vuln_text.lower():
            parts.append(f"Open DNS resolver enables amplification attacks")
        elif "zone transfer" in vuln_text.lower():
            parts.append(f"DNS zone transfer exposes network topology")

    if not parts:
        parts.append(f"Multiple findings on {', '.join(svc_set)} services")

    narrative = f"Host {host}: " + ". ".join(parts) + "."

    # Add chaining analysis
    if len(vulns) > 1:
        narrative += (f" With {len(vulns)} findings across "
                      f"{len(svc_set)} services, this host presents "
                      f"a significant attack surface.")

    return narrative


def get_finetuning_stats():
    """Evaluate training data quality and format compliance."""
    import os
    import glob

    training_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "training_data")

    stats = {
        "total_examples": 0,
        "by_phase": {},
        "format_compliance": 0,
        "avg_command_length": 0,
        "unique_tools": set(),
        "files": [],
    }

    if not os.path.exists(training_dir):
        return stats

    total_cmd_len = 0
    compliant = 0

    for fpath in glob.glob(os.path.join(training_dir, "*.jsonl")):
        fname = os.path.basename(fpath)
        file_count = 0
        try:
            with open(fpath) as f:
                for line in f:
                    try:
                        d = json.loads(line.strip())
                        stats["total_examples"] += 1
                        file_count += 1

                        # Check format compliance (field is assistant_response or response)
                        response = (d.get("assistant_response", "") or
                                    d.get("response", "") or "")
                        command = d.get("command", "") or ""
                        if command:
                            compliant += 1  # has a parsed command = compliant

                        # Extract tool name
                        tool = command.split()[0] if command.strip() else ""
                        if tool:
                            stats["unique_tools"].add(tool)
                            total_cmd_len += len(command)

                        # Track by phase
                        phase = d.get("phase", "unknown")
                        stats["by_phase"][phase] = stats["by_phase"].get(phase, 0) + 1

                    except Exception:
                        pass
        except Exception:
            pass

        if file_count > 0:
            stats["files"].append({"name": fname, "examples": file_count})

    if stats["total_examples"] > 0:
        stats["format_compliance"] = round(
            compliant / stats["total_examples"] * 100, 1)
        stats["avg_command_length"] = round(
            total_cmd_len / max(compliant, 1))

    stats["unique_tools"] = list(stats["unique_tools"])
    return stats
