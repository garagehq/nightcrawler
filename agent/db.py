"""SQLite-backed persistent storage — multi-network, MAC-keyed hosts.

Schema v2: hosts keyed by MAC address, network-scoped data,
networks table for multi-network support.
"""

import sqlite3
import json
import os
import re
import time
import threading
import ipaddress

_local = threading.local()
DB_PATH = None
SCHEMA_VERSION = 2


def init_db(log_dir: str):
    """Initialize the database with schema v2."""
    global DB_PATH
    os.makedirs(log_dir, exist_ok=True)
    DB_PATH = os.path.join(log_dir, "nightcrawler.db")
    conn = _get_conn()
    conn.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;

        CREATE TABLE IF NOT EXISTS networks (
            network_id TEXT PRIMARY KEY,
            cidr TEXT DEFAULT '',
            gateway_mac TEXT DEFAULT '',
            ssid TEXT DEFAULT '',
            public_ip TEXT DEFAULT '',
            gateway TEXT DEFAULT '',
            first_seen TEXT,
            last_seen TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_networks_cidr ON networks(cidr);

        CREATE TABLE IF NOT EXISTS hosts (
            mac TEXT PRIMARY KEY,
            ip TEXT DEFAULT '',
            hostname TEXT DEFAULT '',
            network TEXT DEFAULT '',
            ports TEXT DEFAULT '[]',
            services TEXT DEFAULT '{}',
            info TEXT DEFAULT '',
            first_seen TEXT,
            last_seen TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_hosts_network ON hosts(network);
        CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);

        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT,
            username TEXT,
            password TEXT,
            host TEXT,
            network TEXT DEFAULT '',
            timestamp TEXT
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT,
            service TEXT,
            vuln TEXT,
            severity TEXT DEFAULT 'medium',
            network TEXT DEFAULT '',
            timestamp TEXT,
            chain TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            reasoning TEXT,
            command TEXT,
            status TEXT,
            output_preview TEXT,
            network TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            command TEXT,
            allowed INTEGER,
            reason TEXT,
            result_status TEXT,
            network TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS state (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS wifi_networks (
            bssid TEXT PRIMARY KEY,
            ssid TEXT DEFAULT '',
            channel INTEGER DEFAULT 0,
            encryption TEXT DEFAULT '',
            signal INTEGER DEFAULT 0,
            clients INTEGER DEFAULT 0,
            wps TEXT DEFAULT '',
            first_seen TEXT,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS wifi_handshakes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bssid TEXT,
            ssid TEXT,
            capture_file TEXT,
            captured_at TEXT,
            cracked BOOLEAN DEFAULT 0,
            password TEXT DEFAULT ''
        );
    """)
    conn.commit()

    # Run migration if needed
    version = get_state("schema_version", 0)
    if version < SCHEMA_VERSION:
        _migrate_v2(conn, log_dir)
        set_state("schema_version", SCHEMA_VERSION)


def _migrate_v2(conn, log_dir: str):
    """Migrate v1 data (IP-keyed hosts) to v2 (MAC-keyed)."""
    # Check if old IP-keyed data exists
    try:
        rows = conn.execute(
            "SELECT ip, ports, info, first_seen, last_seen FROM hosts "
            "WHERE mac = ip OR mac LIKE 'unknown-%'"
        ).fetchall()
    except Exception:
        rows = []

    # Also try importing from findings.json
    findings_path = os.path.join(log_dir, "findings.json")
    if os.path.exists(findings_path):
        try:
            with open(findings_path) as f:
                data = json.load(f)
            if data.get("wifi_connected"):
                set_state("wifi_connected", True)
            for h in data.get("hosts", []):
                ip = h["ip"]
                info = h.get("info", "")
                mac = _extract_mac(info) or f"unknown-{ip}"
                hostname = ""
                ports = h.get("ports", [])
                network = _ip_to_network(ip)
                _upsert_host_raw(conn, mac, ip, hostname, network,
                                 ports, info)
            for c in data.get("creds", []):
                conn.execute(
                    "INSERT INTO credentials (service,username,password,host,timestamp) VALUES (?,?,?,?,?)",
                    (c["service"], c["username"], c["password"],
                     c.get("host", ""), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                )
            for v in data.get("vulns", []):
                conn.execute(
                    "INSERT INTO vulnerabilities (host,service,vuln,severity,timestamp) VALUES (?,?,?,?,?)",
                    (v["host"], v["service"], v["vuln"],
                     v.get("severity", "medium"),
                     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                )
            conn.commit()
        except (json.JSONDecodeError, IOError, KeyError):
            pass


def _extract_mac(info: str) -> str:
    """Extract MAC address from info string like 'MAC:AA:BB:CC:DD:EE:FF (Vendor)'."""
    match = re.search(r'MAC:([0-9A-Fa-f:]{17})', info)
    if match:
        return match.group(1).upper()
    return ""


def _ip_to_network(ip: str) -> str:
    """Derive /24 network from an IP."""
    try:
        addr = ipaddress.ip_address(ip)
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except ValueError:
        return ""


def _get_conn() -> sqlite3.Connection:
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, timeout=10)
        _local.conn.row_factory = sqlite3.Row
    return _local.conn


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ── Networks ─────────────────────────────────────────

def upsert_network(network_id: str = "", cidr: str = "", gateway_mac: str = "",
                    ssid: str = "", public_ip: str = "", gateway: str = ""):
    """Insert or update a network. network_id is the primary key.

    Defensive: reject 'auto' as a CIDR (it's a config placeholder, not a real
    network). If network_id looks like a CIDR string (caller misuse), promote
    it to cidr so the row at least has a valid label.
    """
    import hashlib
    if cidr == "auto":
        cidr = ""
    # If caller passed a CIDR-like string as network_id (legacy bug), promote
    # it to the cidr field — but try to find an existing network that actually
    # contains it first so we don't create a duplicate.
    if network_id and "/" in network_id and not cidr:
        cidr = network_id
        network_id = ""  # force regenerate or lookup below
    if not network_id:
        # Generate from gateway MAC or CIDR
        seed = gateway_mac or cidr or "unknown"
        network_id = hashlib.sha256(seed.encode()).hexdigest()[:12]
    conn = _get_conn()
    existing = conn.execute("SELECT network_id FROM networks WHERE network_id=?",
                            (network_id,)).fetchone()
    if existing:
        updates = ["last_seen=?"]
        params = [_ts()]
        for field, val in [("cidr", cidr), ("gateway_mac", gateway_mac),
                           ("ssid", ssid), ("public_ip", public_ip),
                           ("gateway", gateway)]:
            if val:
                updates.append(f"{field}=?")
                params.append(val)
        params.append(network_id)
        conn.execute(f"UPDATE networks SET {','.join(updates)} WHERE network_id=?", params)
    else:
        conn.execute(
            "INSERT INTO networks (network_id,cidr,gateway_mac,ssid,public_ip,gateway,first_seen,last_seen) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (network_id, cidr, gateway_mac, ssid, public_ip, gateway, _ts(), _ts())
        )
    conn.commit()
    return network_id


def get_networks() -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT network_id, cidr, gateway_mac, ssid, public_ip, gateway, first_seen, last_seen "
        "FROM networks ORDER BY cidr"
    ).fetchall()
    return [dict(r) for r in rows]


# ── Hosts ────────────────────────────────────────────

def _upsert_host_raw(conn, mac, ip, hostname, network, ports, info):
    """Low-level upsert without commit (for batch operations)."""
    existing = conn.execute("SELECT ports, info, hostname FROM hosts WHERE mac=?", (mac,)).fetchone()
    if existing:
        old_ports = json.loads(existing["ports"])
        merged = sorted(set(old_ports + (ports or [])))
        new_info = info if info and len(info) > len(existing["info"]) else existing["info"]
        new_hostname = hostname or existing["hostname"] or ""
        conn.execute(
            "UPDATE hosts SET ip=?, hostname=?, network=?, ports=?, info=?, last_seen=? WHERE mac=?",
            (ip, new_hostname, network, json.dumps(merged), new_info, _ts(), mac)
        )
    else:
        conn.execute(
            "INSERT INTO hosts (mac,ip,hostname,network,ports,info,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
            (mac, ip, hostname, network, json.dumps(ports or []), info, _ts(), _ts())
        )


def upsert_host(ip: str, ports: list = None, info: str = "",
                mac: str = "", hostname: str = "", network: str = "",
                network_id: str = ""):
    """Insert or update a host. MAC is preferred key, falls back to IP."""
    conn = _get_conn()
    network = network_id or network  # prefer network_id
    if not mac:
        mac = _extract_mac(info) or f"unknown-{ip}"
    if not network:
        # Find an existing network whose CIDR *contains* this IP. Previously
        # we only matched /24, which created duplicate junk rows for /22 /23
        # networks (e.g. an IP in 172.18.180.0/22 would get keyed as
        # 172.18.180.0/24 and miss the real entry).
        try:
            ip_obj = ipaddress.ip_address(ip)
            for row in conn.execute(
                    "SELECT network_id, cidr FROM networks WHERE cidr != '' AND cidr != 'auto'"
            ).fetchall():
                try:
                    if ip_obj in ipaddress.ip_network(row["cidr"], strict=False):
                        network = row["network_id"]
                        break
                except (ValueError, KeyError):
                    continue
        except ValueError:
            pass
        if not network:
            # No existing match — fall back to /24 derivation
            network = _ip_to_network(ip)

    # Also check if this IP exists under a different MAC (IP changed)
    if mac.startswith("unknown-"):
        existing_by_ip = conn.execute(
            "SELECT mac FROM hosts WHERE ip=? AND mac NOT LIKE 'unknown-%'", (ip,)
        ).fetchone()
        if existing_by_ip:
            mac = existing_by_ip["mac"]
    else:
        # Reverse case: we have a real MAC, but there's already a placeholder
        # row for this IP (e.g. inserted by an earlier ping sweep). Merge the
        # placeholder's data into this upsert and delete the duplicate, so
        # the dashboard doesn't show 2 rows for the same host.
        placeholder = conn.execute(
            "SELECT mac, ports, info, hostname FROM hosts "
            "WHERE ip=? AND mac LIKE 'unknown-%'", (ip,)
        ).fetchone()
        if placeholder:
            try:
                old_ports = json.loads(placeholder["ports"])
                ports = sorted(set((ports or []) + old_ports))
            except Exception:
                pass
            if not info and placeholder["info"]:
                info = placeholder["info"]
            if not hostname and placeholder["hostname"]:
                hostname = placeholder["hostname"]
            conn.execute("DELETE FROM hosts WHERE mac=?", (placeholder["mac"],))

    _upsert_host_raw(conn, mac, ip, hostname, network, ports or [], info)
    conn.commit()

    # Ensure network exists
    if network:
        upsert_network(network)


def get_hosts(network: str = None, network_id: str = None) -> list:
    network = network_id or network
    conn = _get_conn()
    if network:
        rows = conn.execute(
            "SELECT mac, ip, hostname, network, ports, info, first_seen, last_seen "
            "FROM hosts WHERE network=? ORDER BY ip", (network,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT mac, ip, hostname, network, ports, info, first_seen, last_seen "
            "FROM hosts ORDER BY ip"
        ).fetchall()
    return [{"mac": r["mac"], "ip": r["ip"], "hostname": r["hostname"],
             "network": r["network"], "ports": json.loads(r["ports"]),
             "info": r["info"], "first_seen": r["first_seen"],
             "last_seen": r["last_seen"]} for r in rows]


def get_host_count(network: str = None, network_id: str = None) -> int:
    network = network_id or network
    conn = _get_conn()
    if network:
        return conn.execute("SELECT COUNT(*) FROM hosts WHERE network=?", (network,)).fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]


def get_total_ports(network: str = None, network_id: str = None) -> int:
    network = network_id or network
    conn = _get_conn()
    if network:
        rows = conn.execute("SELECT ports FROM hosts WHERE network=?", (network,)).fetchall()
    else:
        rows = conn.execute("SELECT ports FROM hosts").fetchall()
    return sum(len(json.loads(r["ports"])) for r in rows)


def get_host_history(ip: str, limit: int = 20) -> list:
    """Get timeline entries related to a specific host IP."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT timestamp, reasoning, command, status, output_preview "
        "FROM timeline WHERE command LIKE ? ORDER BY id DESC LIMIT ?",
        (f"%{ip}%", limit)
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


# ── Credentials ──────────────────────────────────────

def add_credential(service: str, username: str, password: str,
                   host: str = "", network: str = ""):
    """Add a credential. Auto-detects network from host IP if not provided."""
    conn = _get_conn()
    if not network and host:
        row = conn.execute("SELECT network FROM hosts WHERE ip=?", (host,)).fetchone()
        if row:
            network = row[0] or ""
    conn.execute(
        "INSERT INTO credentials (service,username,password,host,network,timestamp) VALUES (?,?,?,?,?,?)",
        (service, username, password, host, network, _ts())
    )
    conn.commit()


def get_credentials(network: str = None, network_id: str = None) -> list:
    network = network_id or network
    conn = _get_conn()
    if network:
        rows = conn.execute("SELECT * FROM credentials WHERE network=?", (network,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM credentials").fetchall()
    return [dict(r) for r in rows]


def get_cred_count(network: str = None, network_id: str = None) -> int:
    network = network_id or network
    conn = _get_conn()
    if network:
        return conn.execute("SELECT COUNT(*) FROM credentials WHERE network=?", (network,)).fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]


# ── Vulnerabilities ──────────────────────────────────

def add_vulnerability(host: str, service: str, vuln: str,
                      severity: str = "medium", network: str = "",
                      chain: str = "") -> bool:
    """Add a vulnerability. `chain` is the exploit path (commands that found it).
    Auto-detects network from host IP if not provided.
    Returns True if inserted, False if deduped against an existing finding."""
    conn = _get_conn()
    # Dedup: don't add same vuln for same host
    # Exact match OR first 40 chars match (handles variable response sizes)
    existing = conn.execute(
        "SELECT id FROM vulnerabilities WHERE host=? AND (vuln=? OR substr(vuln,1,40)=substr(?,1,40))",
        (host, vuln, vuln)).fetchone()
    if existing:
        return False
    # CVE-aware dedup: if this vuln names a CVE, skip when the same CVE is
    # already recorded for this host under ANY phrasing. Different detectors
    # emit the same finding differently ("CVE: X" from output_parser vs
    # "CVE found: X" from host_memory), whose first-40 chars differ and evade
    # the check above — the cause of repeat CVEs in reports.
    _cve = re.search(r'CVE-\d{4}-\d+', vuln or "", re.IGNORECASE)
    if _cve:
        dup = conn.execute(
            "SELECT id FROM vulnerabilities WHERE host=? AND upper(vuln) LIKE ?",
            (host, "%" + _cve.group(0).upper() + "%")).fetchone()
        if dup:
            return False
    # Auto-detect network from host if not provided
    if not network and host:
        row = conn.execute("SELECT network FROM hosts WHERE ip=?", (host,)).fetchone()
        if row:
            network = row[0] or ""
    conn.execute(
        "INSERT INTO vulnerabilities (host,service,vuln,severity,network,timestamp,chain) VALUES (?,?,?,?,?,?,?)",
        (host, service, vuln, severity, network, _ts(), chain)
    )
    conn.commit()
    return True


def get_vulnerabilities(network: str = None, network_id: str = None) -> list:
    network = network_id or network
    conn = _get_conn()
    if network:
        rows = conn.execute("SELECT * FROM vulnerabilities WHERE network=?", (network,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM vulnerabilities").fetchall()
    return [dict(r) for r in rows]


def get_vuln_count(network: str = None, network_id: str = None) -> int:
    network = network_id or network
    conn = _get_conn()
    if network:
        return conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE network=?", (network,)).fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]


# ── Timeline ─────────────────────────────────────────

def add_timeline(reasoning: str = None, command: str = None,
                 status: str = None, output_preview: str = None,
                 network_id: str = ""):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO timeline (timestamp,reasoning,command,status,output_preview,network) VALUES (?,?,?,?,?,?)",
        (_ts(), reasoning, command, status, (output_preview or "")[:500], network_id)
    )
    conn.commit()


def add_timeline_event(event: str, error: str = None, network_id: str = ""):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO timeline (timestamp,reasoning,command,status,output_preview,network) VALUES (?,?,?,?,?,?)",
        (_ts(), f"[{event}]", None, "event", error or "", network_id)
    )
    conn.commit()


def get_timeline(limit: int = 50, network: str = None) -> list:
    conn = _get_conn()
    if network:
        rows = conn.execute(
            "SELECT timestamp, reasoning, command, status, output_preview "
            "FROM timeline WHERE network=? ORDER BY id DESC LIMIT ?", (network, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT timestamp, reasoning, command, status, output_preview "
            "FROM timeline ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in reversed(rows)]


def get_timeline_count(network: str = None, network_id: str = None) -> int:
    network = network_id or network
    conn = _get_conn()
    if network:
        return conn.execute("SELECT COUNT(*) FROM timeline WHERE network=?", (network,)).fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM timeline").fetchone()[0]


# ── Commands (audit log) ─────────────────────────────

def add_command_log(command: str, allowed: bool, reason: str,
                    result_status: str = None, network: str = ""):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO commands (timestamp,command,allowed,reason,result_status,network) VALUES (?,?,?,?,?,?)",
        (_ts(), command, int(allowed), reason, result_status, network)
    )
    conn.commit()


def get_commands(limit: int = 100, network: str = None) -> list:
    conn = _get_conn()
    if network:
        rows = conn.execute(
            "SELECT timestamp, command, allowed, reason, result_status "
            "FROM commands WHERE network=? ORDER BY id DESC LIMIT ?", (network, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT timestamp, command, allowed, reason, result_status "
            "FROM commands ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in reversed(rows)]


def get_commands_search(query: str, limit: int = 50) -> list:
    """Search commands and timeline by keyword."""
    conn = _get_conn()
    pattern = f"%{query}%"
    rows = conn.execute(
        "SELECT timestamp, reasoning, command, status, output_preview "
        "FROM timeline WHERE command LIKE ? OR reasoning LIKE ? "
        "ORDER BY id DESC LIMIT ?",
        (pattern, pattern, limit)
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


# ── State (key-value) ────────────────────────────────

def set_state(key: str, value):
    conn = _get_conn()
    conn.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)",
                 (key, json.dumps(value)))
    conn.commit()


def get_state(key: str, default=None):
    conn = _get_conn()
    row = conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default


# ── Findings summary ─────────────────────────────────

def get_findings_summary(network_id: str = None) -> dict:
    """Get findings — optionally scoped to a network."""
    # Track per-network "recon is exhausted" — set by the agent once ARP scan
    # confirms a small/isolated network. Lets the planner advance to ENUMERATE
    # even when live_hosts < 3 (otherwise the agent stays stuck in RECON
    # forever on hostile guest WiFi where only the gateway is reachable).
    recon_exhausted = False
    if network_id:
        exhausted_map = get_state("recon_exhausted_per_net", {})
        recon_exhausted = bool(exhausted_map.get(network_id, False))
    return {
        "wifi_connected": get_state("wifi_connected", False),
        "live_hosts": get_host_count(network_id),
        "open_ports": get_total_ports(network_id),
        "credentials": get_cred_count(network_id),
        "vulnerabilities": get_vuln_count(network_id),
        "impact_documented": get_state("impact_documented", False),
        "cleanup_done": get_state("cleanup_done", False),
        "recon_exhausted": recon_exhausted,
        "hosts": get_hosts(network_id),
        "creds": get_credentials(network_id),
        "vulns": get_vulnerabilities(network_id),
        "networks": get_networks(),
    }


# ── Export for Thor ──────────────────────────────────

def export_network(network_id: str = None) -> dict:
    """Full export of a network's data for Thor consumption."""
    return {
        "export_time": _ts(),
        "network": network_id or "all",
        "findings": get_findings_summary(network_id),
        "timeline": get_timeline(limit=500, network=network_id),
        "commands": get_commands(limit=500, network=network_id),
        "blacklisted_hosts": get_state("blacklisted_hosts", []),
        "starred_hosts": get_state("starred_hosts", []),
        "host_notes": get_state("host_notes", {}),
        "host_memories": get_state("host_memories", {}),
        "network_notes": get_state("network_notes", {}),
        "network_names": get_state("network_names", {}),
        "tool_preferences": get_state("tool_preferences", {}),
    }
