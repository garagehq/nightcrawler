"""Local CVE→command database for common pentest targets.

Loads from data/cve_exploits.json — a curated mapping of service + version
patterns to CVE IDs and ready-to-run exploit commands. ~50KB on disk,
minimal RAM footprint (loaded once, regex matching uses CPU not memory).

No external API calls — fully offline.
"""

import json
import os
import re
import random

_DB = None  # lazy-loaded


def _load_db():
    """Load the CVE database from JSON file."""
    global _DB
    if _DB is not None:
        return _DB

    db_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "cve_exploits.json"
    )
    try:
        with open(db_path) as f:
            data = json.load(f)
        _DB = data.get("exploits", [])
    except Exception:
        _DB = []
    return _DB


def lookup(service: str, version: str = "") -> list:
    """Return matching CVE entries for a service+version."""
    db = _load_db()
    results = []
    svc = service.lower()
    for entry in db:
        if entry["service"] in svc or svc in entry["service"]:
            if not version or re.search(entry["version_re"], version):
                results.append(entry)
    return results


def get_exploit_hint(observations: list, ip: str) -> str:
    """Parse host observations for version strings, return a CVE exploit hint.

    Returns a ready-to-run command string, or None if no match.
    """
    for obs_text in observations:
        # Match: "SSH: OpenSSH 9.2p1", "Samba version: 4.17.12",
        # "Port 22/ssh: OpenSSH 8.2p1 Ubuntu", etc.
        m = re.search(
            r'(OpenSSH|Samba|dnsmasq|Apache|nginx|lighttpd|Pi-hole|'
            r'vsftpd|ProFTPD|Redis|MySQL|PostgreSQL|MongoDB|Docker|'
            r'Elasticsearch|Jenkins|Tomcat|Grafana|GitLab|WordPress|'
            r'phpMyAdmin)\s*:?\s*v?(\S+)',
            obs_text, re.IGNORECASE)
        if m:
            service, version = m.group(1), m.group(2)
            matches = lookup(service, version)
            if matches:
                entry = random.choice(matches)
                cmd = random.choice(entry["commands"]).format(ip=ip)
                cve = entry["cve"]
                desc = entry["desc"][:40]
                return f"Try: {cmd} ({cve}: {desc}). "

        # Tag-based matching (no version needed)
        for tag, svc in [("Pi-hole", "pi-hole"), ("pi-hole", "pi-hole"),
                         ("smb", "smb"), ("vnc", "vnc"), ("telnet", "telnet"),
                         ("redis", "redis"), ("ftp", "ftp")]:
            if tag in obs_text:
                matches = lookup(svc)
                if matches:
                    entry = random.choice(matches)
                    cmd = random.choice(entry["commands"]).format(ip=ip)
                    return f"Try: {cmd} ({entry['cve']}: {entry['desc'][:30]}). "

    return None
