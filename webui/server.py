"""Nightcrawler Web UI — hacker terminal dashboard.

Serves a real-time dashboard showing agent status, command feed,
findings, and mission progress. Accessible from phone browser
or remotely via Tailscale IP.
"""

import json
import os
import subprocess
import time
import threading
from flask import Flask, render_template, jsonify, Response, request, send_file

# Try to use SQLite backend
try:
    from agent import db as _db
    _HAS_DB = True
    # Auto-init DB if not already initialized
    _db_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
    if not _db.DB_PATH:
        _db.init_db(_db_dir)
    # Initialize offline manager state from DB (survives restarts)
    try:
        from agent import offline_manager
        offline_manager.init_state()
    except Exception:
        pass
except ImportError:
    _HAS_DB = False

app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(__file__), "templates"),
            static_folder=os.path.join(os.path.dirname(__file__), "static"))


# ── Stealth middleware: reject connections from the target network ──
# Only allow: localhost (127.x), Tailscale (100.x), and link-local.
# Blue team scanners on 192.168.x see a connection reset, not a web server.
_ALLOWED_PREFIXES = ("127.", "100.", "::1", "10.", "172.16.", "172.17.",
                     "172.18.", "172.19.", "172.2", "172.30.", "172.31.")

@app.after_request
def _strip_server_header(response):
    """Replace Server header so nmap/whatweb can't fingerprint as Python/Flask."""
    response.headers["Server"] = "nginx"
    return response

# Monkey-patch Werkzeug to stop injecting its own Server header
try:
    import werkzeug.serving
    werkzeug.serving.WSGIRequestHandler.server_version = "nginx"
    werkzeug.serving.WSGIRequestHandler.sys_version = ""
except Exception:
    pass


@app.before_request
def _stealth_filter():
    remote = request.remote_addr or ""
    if not any(remote.startswith(p) for p in _ALLOWED_PREFIXES):
        # Return empty 404 — looks like a misconfigured/dead service
        # No headers, no body, no server signature
        return Response("", status=404, headers={
            "Content-Length": "0",
            "Connection": "close",
        })

def _filter_records_by_network(records, network_id):
    """Filter a list of {'ip': ...} dicts to only those inside network_id's CIDR."""
    if not network_id or not records:
        return records
    try:
        import sqlite3 as _sql
        import ipaddress as _ip
        log_dir = os.environ.get("NC_LOG_DIR",
                                 os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"))
        conn = _sql.connect(os.path.join(log_dir, "nightcrawler.db"))
        row = conn.execute("SELECT cidr FROM networks WHERE network_id=?",
                           (network_id,)).fetchone()
        conn.close()
        if not row or not row[0]:
            return records
        net = _ip.ip_network(row[0], strict=False)
        def _in_net(rec):
            ip_str = rec.get("ip", "")
            if not ip_str:
                return False
            try:
                return _ip.ip_address(ip_str) in net
            except ValueError:
                return False
        return [r for r in records if _in_net(r)]
    except Exception:
        return records


# Shared state — updated by the agent loop
_state = {
    "phase": "INIT",
    "mode": "LOCAL",
    "uptime": "00:00:00",
    "watchdog": "08:00:00",
    "thor_online": False,
    "wifi_up": False,
    "commands_total": 0,
    "commands_blocked": 0,
    "errors": 0,
    "iteration": 0,
    "findings": {
        "hosts": 0,
        "ports": 0,
        "creds": 0,
        "vulns": 0,
    },
    "feed": [],        # recent agent actions [{ts, type, content}]
    "hosts": [],       # discovered hosts
    "creds": [],       # found credentials (redacted)
    "vulns": [],       # vulnerabilities
}
_state_lock = threading.Lock()


def update_state(updates: dict):
    """Called by the agent loop to push state updates.

    Also persists key fields to SQLite so the separate webui daemon
    process can read them (in-memory state is per-process).
    """
    with _state_lock:
        for k, v in updates.items():
            if k in _state and isinstance(_state[k], dict) and isinstance(v, dict):
                _state[k].update(v)
            else:
                _state[k] = v
    # Persist to shared SQLite for cross-process visibility
    try:
        from agent import db
        db.set_state("agent_ui_state", {
            "phase": updates.get("phase", ""),
            "mode": updates.get("mode", ""),
            "uptime": updates.get("uptime", ""),
            "commands_total": updates.get("commands_total", 0),
            "commands_blocked": updates.get("commands_blocked", 0),
            "errors": updates.get("errors", 0),
            "iteration": updates.get("iteration", 0),
            "thor_online": updates.get("thor_online", False),
        })
    except Exception:
        pass


def push_feed(event_type: str, content: str):
    """Push a new event to the live feed."""
    entry = {
        "ts": time.strftime("%H:%M:%S"),
        "type": event_type,
        "content": content,
    }
    with _state_lock:
        _state["feed"].append(entry)
        # Keep last 200 entries
        if len(_state["feed"]) > 200:
            _state["feed"] = _state["feed"][-200:]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/state")
def api_state():
    """Return current state — merges in-memory state with disk data."""
    log_dir = os.environ.get("NC_LOG_DIR",
                             os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"))

    # Read findings from disk
    findings_path = os.path.join(log_dir, "findings.json")
    disk_findings = {}
    if os.path.exists(findings_path):
        try:
            with open(findings_path) as f:
                disk_findings = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    # Read recent timeline entries as feed
    timeline_path = os.path.join(log_dir, "timeline.jsonl")
    feed = []
    if os.path.exists(timeline_path):
        try:
            with open(timeline_path) as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        ts = entry.get("timestamp", "")
                        if ts:
                            ts = ts.split("T")[1].split("Z")[0] if "T" in ts else ts
                        if entry.get("command"):
                            if entry.get("reasoning"):
                                feed.append({"ts": ts, "type": "thought",
                                             "content": entry["reasoning"][:300]})
                            feed.append({"ts": ts, "type": "command",
                                         "content": entry["command"]})
                            status = entry.get("status", "?")
                            preview = entry.get("output_preview", "")[:300]
                            if status == "error":
                                feed.append({"ts": ts, "type": "error",
                                             "content": preview})
                            elif status == "success":
                                feed.append({"ts": ts, "type": "result",
                                             "content": preview})
                        elif entry.get("event"):
                            feed.append({"ts": ts, "type": "thought",
                                         "content": f"[{entry['event']}]"})
                    except json.JSONDecodeError:
                        pass
        except IOError:
            pass

    # Build state from disk + in-memory
    with _state_lock:
        state = dict(_state)

    # Read agent's persisted UI state from SQLite (cross-process)
    try:
        from agent import db
        ui_state = db.get_state("agent_ui_state", {})
        if ui_state:
            for k in ("phase", "mode", "uptime", "commands_total",
                       "commands_blocked", "errors", "iteration", "thor_online"):
                if ui_state.get(k):
                    state[k] = ui_state[k]
    except Exception:
        pass

    # Override with disk data + DB data
    # Read creds/vulns from SQLite (authoritative) — filter by network if selected
    selected_net = request.args.get("network", "")
    db_creds, db_vulns = [], []
    import sqlite3 as _sql
    _dbpath = os.path.join(log_dir, "nightcrawler.db")
    if os.path.exists(_dbpath):
        _conn = _sql.connect(_dbpath)
        _conn.row_factory = _sql.Row
        if selected_net:
            db_creds = [dict(r) for r in _conn.execute("SELECT * FROM credentials WHERE network=?", (selected_net,)).fetchall()]
            db_vulns = [dict(r) for r in _conn.execute("SELECT * FROM vulnerabilities WHERE network=?", (selected_net,)).fetchall()]
        else:
            db_creds = [dict(r) for r in _conn.execute("SELECT * FROM credentials").fetchall()]
            db_vulns = [dict(r) for r in _conn.execute("SELECT * FROM vulnerabilities").fetchall()]
        _conn.close()
    db_cred_count = len(db_creds) or disk_findings.get("credentials", 0)
    db_vuln_count = len(db_vulns) or disk_findings.get("vulnerabilities", 0)

    # Hosts come from DB so they can be filtered by selected network.
    # disk_findings.get("hosts") is unfiltered and would leak hosts from other networks.
    if _HAS_DB:
        try:
            scoped_hosts = _db.get_hosts(network_id=selected_net) if selected_net else _db.get_hosts()
        except Exception:
            scoped_hosts = disk_findings.get("hosts", [])
    else:
        scoped_hosts = disk_findings.get("hosts", [])
    state["findings"] = {
        "hosts": len(scoped_hosts),
        "ports": sum(len(h.get("ports", [])) for h in scoped_hosts),
        "creds": db_cred_count,
        "vulns": db_vuln_count,
    }
    state["hosts"] = scoped_hosts
    state["creds"] = db_creds
    # Enrich vulns with remediation for frontend detail view
    for v in db_vulns:
        v["remediation"] = _get_remediation(v.get("service", ""), v.get("vuln", ""))
    state["vulns"] = db_vulns
    state["wifi_up"] = disk_findings.get("wifi_connected", False)

    # Read live feed from SQLite (written by agent's ui_bridge)
    try:
        _agent_feed = []
        if os.path.exists(_dbpath):
            _fconn = _sql.connect(_dbpath)
            _frow = _fconn.execute(
                "SELECT value FROM state WHERE key='agent_feed'").fetchone()
            if _frow:
                _agent_feed = json.loads(_frow[0])
            _fconn.close()
        # Use agent feed if available, fall back to disk timeline
        # Filter by selected network using the network tag on each entry.
        # Untagged warnings/errors are allowed through ONLY if their content
        # doesn't reference IPs from a different network — otherwise stale
        # per-host warnings from previous networks leak into the feed.
        raw_feed = _agent_feed if _agent_feed else (feed or [])
        if selected_net and raw_feed:
            # Get the selected network's CIDR so we can check IPs in content.
            import ipaddress as _ipa
            _sel_net = None
            try:
                if os.path.exists(_dbpath):
                    _cconn = _sql.connect(_dbpath)
                    _crow = _cconn.execute(
                        "SELECT cidr FROM networks WHERE network_id=?",
                        (selected_net,)).fetchone()
                    _cconn.close()
                    if _crow and _crow[0]:
                        _sel_net = _ipa.ip_network(_crow[0], strict=False)
            except Exception:
                pass

            import re as _refeed
            _ip_re = _refeed.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

            def _keep(e):
                # Drop entries explicitly tagged for a different network.
                if e.get("network", "") and e.get("network", "") != selected_net:
                    return False
                # Otherwise check whether the entry's content references any
                # foreign IPs. We need to do this even for entries tagged for
                # this network — historical "OUT OF SCOPE: 192.168.8.x" or
                # "Target 192.168.0.x..." entries got tagged with the network
                # the agent was on at the time, but their content references
                # IPs from somewhere else and shouldn't appear in this view.
                if _sel_net is None:
                    return True
                if e.get("network", "") == selected_net and \
                        e.get("type") not in ("command", "thought", "result",
                                               "blocked", "warning", "error"):
                    return True
                # Untagged entries: only certain types pass the type filter.
                if not e.get("network", ""):
                    if e.get("type") not in ("phase", "warning", "error"):
                        return False
                content = e.get("content", "") or ""
                ips = _ip_re.findall(content)
                if not ips:
                    return True  # No IPs → network-agnostic, keep
                # Keep if AT LEAST ONE referenced IP is in-scope. Drop only
                # if EVERY referenced IP is foreign (means the entry is purely
                # about another network).
                has_in_scope = False
                for ip in ips:
                    try:
                        if _ipa.ip_address(ip) in _sel_net:
                            has_in_scope = True
                            break
                    except ValueError:
                        continue
                return has_in_scope

            raw_feed = [e for e in raw_feed if _keep(e)]
        state["feed"] = raw_feed[-500:]
    except Exception:
        if feed:
            state["feed"] = feed[-500:]

    # Infer phase from disk
    hosts = disk_findings.get("live_hosts", 0)
    creds = disk_findings.get("credentials", 0)
    vulns = disk_findings.get("vulnerabilities", 0)
    if state.get("phase", "INIT") == "INIT":
        if disk_findings.get("wifi_connected"):
            if hosts >= 3:
                state["phase"] = "ENUMERATE"
            elif hosts > 0:
                state["phase"] = "RECON & MAP"
            else:
                state["phase"] = "RECON & MAP"

    # Count commands from log
    cmds_path = os.path.join(log_dir, "commands.jsonl")
    if os.path.exists(cmds_path):
        try:
            with open(cmds_path) as f:
                lines = f.readlines()
            state["commands_total"] = len(lines)
            state["commands_blocked"] = sum(
                1 for l in lines
                if '"allowed": false' in l or '"allowed":false' in l
            )
        except IOError:
            pass

    return jsonify(state)


@app.route("/api/feed", methods=["GET", "POST"])
def api_feed():
    """Return recent feed entries (GET) or push a new one (POST)."""
    if request.method == "POST":
        try:
            data = request.get_json(force=True)
            event_type = data.get("type", "system")
            content = data.get("content", "")
            if not content:
                return jsonify({"error": "content required"}), 400
            from agent.ui_bridge import push_feed
            push_feed(event_type, content)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    since = int(float(os.environ.get("feed_since", "0")))
    with _state_lock:
        return jsonify(_state["feed"][since:])


@app.route("/api/stream")
def api_stream():
    """SSE stream for real-time updates."""
    def generate():
        last_len = 0
        while True:
            with _state_lock:
                current_len = len(_state["feed"])
                if current_len > last_len:
                    new_entries = _state["feed"][last_len:]
                    last_len = current_len
                    for entry in new_entries:
                        yield f"data: {json.dumps(entry)}\n\n"
                # Always send heartbeat state
                state_snapshot = {k: v for k, v in _state.items()
                                  if k != "feed"}
                yield f"event: state\ndata: {json.dumps(state_snapshot)}\n\n"
            time.sleep(1)
    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/findings")
def api_findings():
    """Return detailed findings — SQLite first, JSON fallback."""
    selected_net = request.args.get("network", "")
    if _HAS_DB and _db.DB_PATH:
        try:
            return jsonify(_db.get_findings_summary(network_id=selected_net or None))
        except Exception:
            pass
    # Fallback to JSON file
    log_dir = os.environ.get("NC_LOG_DIR",
                             os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"))
    findings_path = os.path.join(log_dir, "findings.json")
    if os.path.exists(findings_path):
        try:
            with open(findings_path) as f:
                return jsonify(json.load(f))
        except (json.JSONDecodeError, IOError):
            pass
    return jsonify({})


@app.route("/api/commands")
def api_commands():
    """Return recent commands — SQLite first, JSONL fallback."""
    if _HAS_DB and _db.DB_PATH:
        try:
            return jsonify(_db.get_commands(100))
        except Exception:
            pass
    # Fallback
    log_dir = os.environ.get("NC_LOG_DIR",
                             os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"))
    commands_path = os.path.join(log_dir, "commands.jsonl")
    commands = []
    if os.path.exists(commands_path):
        with open(commands_path) as f:
            for line in f:
                try:
                    commands.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass
    return jsonify(commands[-100:])


@app.route("/api/timeline")
def api_timeline():
    """Return recent timeline entries."""
    if _HAS_DB and _db.DB_PATH:
        try:
            return jsonify(_db.get_timeline(50))
        except Exception:
            pass
    # Fallback
    log_dir = os.environ.get("NC_LOG_DIR",
                             os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"))
    timeline_path = os.path.join(log_dir, "timeline.jsonl")
    entries = []
    if os.path.exists(timeline_path):
        with open(timeline_path) as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass
    return jsonify(entries[-50:])


@app.route("/api/host/<ip>/history")
def api_host_history(ip):
    """Return scan history for a specific host."""
    if _HAS_DB and _db.DB_PATH:
        try:
            return jsonify(_db.get_host_history(ip, limit=20))
        except Exception:
            pass
    return jsonify([])


@app.route("/api/export")
@app.route("/api/export/<path:network>")
def api_export(network=None):
    """Export all data for Thor consumption. Includes topology, vulns, attack paths."""
    if _HAS_DB and _db.DB_PATH:
        try:
            data = _db.export_network(network)
            # Enrich with new data for Thor
            import sqlite3 as _esql
            _econn = _esql.connect(_db.DB_PATH)
            _econn.row_factory = _esql.Row
            data["vulnerabilities"] = [dict(r) for r in _econn.execute("SELECT * FROM vulnerabilities").fetchall()]
            data["credentials"] = [dict(r) for r in _econn.execute("SELECT * FROM credentials").fetchall()]
            _econn.close()
            # Add remediation to vulns
            for v in data["vulnerabilities"]:
                v["remediation"] = _get_remediation(v.get("service", ""), v.get("vuln", ""))
            # Add topology and attack paths
            try:
                from agent.report_generator import generate_topology, generate_attack_paths
                data["topology"] = generate_topology()
                data["attack_paths"] = generate_attack_paths()
            except Exception:
                pass
            # Add passive capture, filtered to the selected network's CIDR.
            try:
                pf = "/tmp/nc-passive-parsed.json"
                if os.path.exists(pf):
                    with open(pf) as _pf:
                        pc_data = json.load(_pf)
                    if network:
                        pc_data = _filter_records_by_network(pc_data, network)
                    data["passive_capture"] = pc_data
            except Exception:
                pass
            return jsonify(data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "SQLite not available"}), 500


@app.route("/api/networks")
def api_networks():
    """Return list of discovered networks."""
    if _HAS_DB and _db.DB_PATH:
        try:
            nets = _db.get_networks()
            # Attach notes from state
            net_notes = _db.get_state("network_notes", {})
            net_names = _db.get_state("network_names", {})
            for n in nets:
                nid = n.get("network_id", "")
                n["display_name"] = net_names.get(nid, "") or n.get("ssid", "") or n.get("cidr", "")
                n["notes"] = net_notes.get(nid, "")
            return jsonify(nets)
        except Exception:
            pass
    return jsonify([])


@app.route("/api/networks/<path:network_id>", methods=["PATCH"])
def api_edit_network(network_id):
    """Edit network name, notes, and add observations."""
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 500
    data = request.json or {}
    name = data.get("name")
    notes = data.get("notes")
    observation = data.get("observation")

    if name is not None:
        names = _db.get_state("network_names", {})
        names[network_id] = name
        _db.set_state("network_names", names)

    if notes is not None:
        net_notes = _db.get_state("network_notes", {})
        net_notes[network_id] = notes
        _db.set_state("network_notes", net_notes)

    if observation:
        try:
            from agent.host_memory import add_network_observation
            add_network_observation(network_id, observation, source="analyst")
        except Exception:
            pass

    return jsonify({"ok": True, "network_id": network_id})


@app.route("/api/networks/<path:network_id>", methods=["DELETE"])
def api_delete_network(network_id):
    """Delete a network and ALL associated data (hosts, vulns, creds, memories, timeline).
    Auto-kills agent before delete, restarts with 2-min delay after.
    This is irreversible — used for client data privacy after report delivery."""
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 500

    # Pause watchdog + kill agent to prevent re-insertion during delete
    import subprocess
    try:
        open("/tmp/nc-agent-pause", "w").write("delete in progress")
    except Exception:
        pass
    # Clear feed entries for this network (in-memory + SQLite)
    _state["feed"] = [e for e in _state.get("feed", []) if e.get("network", "") != network_id]
    try:
        feed = _db.get_state("agent_feed", [])
        feed = [e for e in feed if e.get("network", "") != network_id]
        _db.set_state("agent_feed", feed)
    except Exception:
        pass
    try:
        subprocess.run(["pkill", "-9", "-f", "python3 main.py"], timeout=5)
    except Exception:
        pass
    import time as _dtime
    _dtime.sleep(2)  # wait for process to die

    import sqlite3 as _dsql
    conn = _dsql.connect(_db.DB_PATH)
    c = conn.cursor()

    # Get the CIDR for this network to also match hosts stored with CIDR as network
    cidr = ""
    _nrow = c.execute("SELECT cidr FROM networks WHERE network_id=?", (network_id,)).fetchone()
    if _nrow:
        cidr = _nrow[0]
    ip_prefix = cidr.rsplit(".", 1)[0] + "." if cidr else ""

    # Count what we're deleting — match by network_id OR CIDR OR IP prefix
    counts = {}
    for table in ["hosts", "vulnerabilities", "credentials", "commands"]:
        total = c.execute(f"SELECT COUNT(*) FROM {table} WHERE network=?", (network_id,)).fetchone()[0]
        if cidr:
            total += c.execute(f"SELECT COUNT(*) FROM {table} WHERE network=?", (cidr,)).fetchone()[0]
        if ip_prefix and table == "hosts":
            total += c.execute(f"SELECT COUNT(*) FROM {table} WHERE ip LIKE ? AND network NOT IN (SELECT network_id FROM networks WHERE network_id != ?)",
                               (ip_prefix + "%", network_id)).fetchone()[0]
        counts[table] = total

    # Delete from all tables — by network_id AND CIDR
    for table in ["hosts", "vulnerabilities", "credentials", "commands"]:
        c.execute(f"DELETE FROM {table} WHERE network=?", (network_id,))
        if cidr:
            c.execute(f"DELETE FROM {table} WHERE network=?", (cidr,))
    # Also delete any hosts with IPs matching the subnet that slipped through
    if ip_prefix:
        c.execute("DELETE FROM hosts WHERE ip LIKE ? AND network NOT IN (SELECT network_id FROM networks WHERE network_id != ?)",
                  (ip_prefix + "%", network_id))
    c.execute("DELETE FROM networks WHERE network_id=?", (network_id,))
    # Also clean any CIDR-keyed network entry
    if cidr:
        c.execute("DELETE FROM networks WHERE network_id=?", (cidr,))

    # Clean up state entries
    for state_key in ["network_names", "network_notes"]:
        try:
            state_data = _db.get_state(state_key, {})
            if network_id in state_data:
                del state_data[network_id]
                _db.set_state(state_key, state_data)
        except Exception:
            pass

    # Clean host memories for hosts on this network's subnet
    try:
        memories = _db.get_state("host_memories", {})
        macs_to_delete = []
        for mac, mem in memories.items():
            mem_ip = mem.get("ip", "")
            if ip_prefix and mem_ip.startswith(ip_prefix):
                macs_to_delete.append(mac)
        for mac in macs_to_delete:
            del memories[mac]
        if macs_to_delete:
            _db.set_state("host_memories", memories)
    except Exception:
        pass

    # Clean passive capture file
    try:
        import json as _pjson
        _pfile = "/tmp/nc-passive-parsed.json"
        if os.path.exists(_pfile):
            with open(_pfile) as _pf:
                _pdata = _pjson.load(_pf)
            _pdata = [d for d in _pdata if not d.get("ip", "").startswith(ip_prefix)]
            with open(_pfile, "w") as _pf:
                _pjson.dump(_pdata, _pf)
    except Exception:
        pass
        # (they're orphaned but harmless)
    except Exception:
        pass

    conn.commit()
    conn.close()

    # Auto-restart agent after 2-minute delay (background thread)
    import threading
    def _delayed_restart():
        import time, subprocess, os
        time.sleep(120)  # 2 minutes
        # Remove pause file so watchdog resumes
        try:
            os.remove("/tmp/nc-agent-pause")
        except Exception:
            pass
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        subprocess.Popen(
            ["python3", "main.py"],
            cwd=project_dir,
            stdout=open("/tmp/nc-agent.log", "w"),
            stderr=subprocess.STDOUT,
            start_new_session=True)
    threading.Thread(target=_delayed_restart, daemon=True).start()

    return jsonify({
        "ok": True,
        "network_id": network_id,
        "deleted": counts,
        "message": f"Network {network_id} and all associated data permanently deleted. Agent will restart in 2 minutes."
    })


@app.route("/api/networks/<path:network_id>/memory")
def api_network_memory(network_id):
    """Get network-level memory (observations, scanned IPs)."""
    try:
        from agent.host_memory import get_network_memory
        return jsonify(get_network_memory(network_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Training Data Endpoints ───────────────────────────────

@app.route("/api/training/stats")
def api_training_stats():
    """Get training data statistics."""
    try:
        from agent.training_capture import get_stats
        return jsonify(get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/training/export/<format>")
def api_training_export(format):
    """Export training data for finetuning. Formats: chatml, jsonl, conversations."""
    try:
        from agent.training_capture import export_for_finetuning
        path, count = export_for_finetuning(format)
        return jsonify({"path": path, "count": count, "format": format})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Host Memory Endpoints ─────────────────────────────────

@app.route("/api/hosts/<mac>/memory")
def api_get_host_memory(mac):
    """Get memory/observations for a host."""
    try:
        from agent.host_memory import get_memory
        return jsonify(get_memory(mac))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/hosts/<mac>/memory", methods=["PATCH"])
def api_edit_host_memory(mac):
    """Edit host memory — add observations, change status, tags, avoid_tools."""
    try:
        from agent import host_memory
        data = request.get_json(force=True)

        if "observation" in data:
            host_memory.add_observation(mac, data["observation"],
                                        source="analyst", ip=data.get("ip", ""))
        if "status" in data:
            host_memory.update_status(mac, data["status"])
        if "tags" in data:
            mem = host_memory.get_memory(mac)
            if mem:
                mem["tags"] = data["tags"]
                host_memory.set_memory(mac, mem)
        if "avoid_tools" in data:
            host_memory.set_avoid_tools(mac, data["avoid_tools"])

        return jsonify({"ok": True, "memory": host_memory.get_memory(mac)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/hosts/memories")
def api_all_host_memories():
    """Get all host memories."""
    try:
        from agent.host_memory import get_all_memories
        return jsonify(get_all_memories())
    except Exception:
        return jsonify({})


@app.route("/api/hosts/memories/export")
def api_export_memories():
    """Export all host memories for Thor."""
    try:
        from agent.host_memory import export_memories
        return jsonify(export_memories())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── C2 Control Endpoints ──────────────────────────────────


# 1. Star/Prioritize Hosts
@app.route("/api/hosts/star", methods=["POST"])
def api_star_host():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    data = request.get_json(force=True)
    mac = data.get("mac", "")
    iterations = data.get("iterations", 5)
    if not mac:
        return jsonify({"error": "mac required"}), 400

    # Look up IP for this MAC
    starred = _db.get_state("starred_hosts", [])
    # Remove existing entry for this MAC (re-star updates iterations)
    starred = [s for s in starred if s.get("mac") != mac]

    # Resolve IP from hosts table
    ip = ""
    try:
        hosts = _db.get_hosts()
        for h in hosts:
            if h.get("mac") == mac:
                ip = h.get("ip", "")
                break
    except Exception:
        pass

    starred.append({"mac": mac, "ip": ip, "remaining": iterations})
    _db.set_state("starred_hosts", starred)
    return jsonify({"ok": True, "starred": starred})


@app.route("/api/hosts/star", methods=["DELETE"])
def api_unstar_host():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    data = request.get_json(force=True)
    mac = data.get("mac", "")
    if not mac:
        return jsonify({"error": "mac required"}), 400

    starred = _db.get_state("starred_hosts", [])
    starred = [s for s in starred if s.get("mac") != mac]
    _db.set_state("starred_hosts", starred)
    return jsonify({"ok": True, "starred": starred})


@app.route("/api/hosts/starred")
def api_starred_hosts():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify([])
    return jsonify(_db.get_state("starred_hosts", []))


# 1b. Blacklist Hosts
@app.route("/api/hosts/blacklist", methods=["POST"])
def api_blacklist_host():
    """Blacklist a host — agent will skip it entirely."""
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    data = request.get_json(force=True)
    mac = data.get("mac", "")
    ip = data.get("ip", "")
    if not mac and not ip:
        return jsonify({"error": "mac or ip required"}), 400

    blacklist = _db.get_state("blacklisted_hosts", [])
    # Don't add duplicates
    if not any(b.get("mac") == mac for b in blacklist):
        blacklist.append({"mac": mac, "ip": ip})
        _db.set_state("blacklisted_hosts", blacklist)
    return jsonify({"ok": True, "blacklisted": blacklist})


@app.route("/api/hosts/blacklist", methods=["DELETE"])
def api_unblacklist_host():
    """Remove a host from blacklist."""
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    data = request.get_json(force=True)
    mac = data.get("mac", "")
    blacklist = _db.get_state("blacklisted_hosts", [])
    blacklist = [b for b in blacklist if b.get("mac") != mac]
    _db.set_state("blacklisted_hosts", blacklist)
    return jsonify({"ok": True, "blacklisted": blacklist})


@app.route("/api/hosts/blacklisted")
def api_blacklisted_hosts():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify([])
    return jsonify(_db.get_state("blacklisted_hosts", []))


# 2. Force Phase Change
@app.route("/api/phase", methods=["POST"])
def api_force_phase():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    data = request.get_json(force=True)
    phase = data.get("phase", "").lower()
    valid = ["recon", "enumerate", "exploit", "report", "cleanup"]
    if phase not in valid:
        return jsonify({"error": f"Invalid phase. Valid: {valid}"}), 400
    _db.set_state("forced_phase", phase)
    return jsonify({"ok": True, "forced_phase": phase})


# 3. Pause/Resume Agent
AGENT_PAUSE_FILE = "/tmp/nc-agent-pause"


@app.route("/api/agent/pause", methods=["POST"])
def api_pause():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    _db.set_state("paused", True)
    # Create pause file so agent-watchdog won't restart the agent
    try:
        with open(AGENT_PAUSE_FILE, "w") as f:
            f.write("user-paused")
    except Exception:
        pass
    # Kill agent process to free resources
    try:
        subprocess.run(["pkill", "-9", "-f", "python3 main.py"],
                       capture_output=True, timeout=5)
    except Exception:
        pass
    return jsonify({"ok": True, "paused": True})


@app.route("/api/agent/unpause", methods=["POST"])
@app.route("/api/agent/resume", methods=["POST"])
def api_resume():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    _db.set_state("paused", False)
    # Remove pause file so agent-watchdog can restart the agent
    try:
        if os.path.exists(AGENT_PAUSE_FILE):
            os.remove(AGENT_PAUSE_FILE)
    except Exception:
        pass
    return jsonify({"ok": True, "paused": False})


@app.route("/api/agent/status")
def api_agent_status():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"paused": False, "kill_switch": False, "running": False, "pid": None})
    # Check if agent process is running
    pid = None
    running = False
    try:
        result = subprocess.run(["pgrep", "-f", "python3 main.py"],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().split("\n")
            pid = int(pids[0])
            running = True
    except Exception:
        pass
    paused = _db.get_state("paused", False) or os.path.exists(AGENT_PAUSE_FILE)
    return jsonify({
        "paused": paused,
        "kill_switch": _db.get_state("kill_switch", False),
        "running": running,
        "pid": pid,
    })


# 4. Manual Command Queue
@app.route("/api/commands/queue", methods=["POST"])
def api_queue_command():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    data = request.get_json(force=True)
    cmd = data.get("command", "").strip()
    if not cmd:
        return jsonify({"error": "command required"}), 400
    queue = _db.get_state("command_queue", [])
    queue.append(cmd)
    _db.set_state("command_queue", queue)
    return jsonify({"ok": True, "queue": queue})


@app.route("/api/commands/queue", methods=["GET"])
def api_get_queue():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify([])
    return jsonify(_db.get_state("command_queue", []))


# 5. Tool Preferences
@app.route("/api/tools/preferences", methods=["POST"])
def api_set_tool_prefs():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    data = request.get_json(force=True)
    prefs = {
        "disabled": data.get("disabled", []),
        "preferred": data.get("preferred", []),
    }
    _db.set_state("tool_preferences", prefs)
    return jsonify({"ok": True, "preferences": prefs})


@app.route("/api/tools/preferences", methods=["GET"])
def api_get_tool_prefs():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"disabled": [], "preferred": []})
    return jsonify(_db.get_state("tool_preferences",
                                 {"disabled": [], "preferred": []}))


# 6. Host Notes
@app.route("/api/hosts/<mac>/notes", methods=["POST"])
def api_set_host_note(mac):
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    data = request.get_json(force=True)
    note = data.get("note", "")
    notes = _db.get_state("host_notes", {})
    notes[mac] = note
    _db.set_state("host_notes", notes)
    return jsonify({"ok": True, "mac": mac, "note": note})


@app.route("/api/hosts/<mac>/notes", methods=["GET"])
def api_get_host_note(mac):
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"note": ""})
    notes = _db.get_state("host_notes", {})
    return jsonify({"note": notes.get(mac, "")})


# 7. Kill Switch
@app.route("/api/killswitch", methods=["POST"])
def api_killswitch():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    _db.set_state("kill_switch", True)
    _db.set_state("paused", True)
    return jsonify({"ok": True, "kill_switch": True})


# 8. Agent Config
@app.route("/api/config", methods=["GET"])
def api_get_config():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"temperature": 0.7, "max_tokens": 512})
    defaults = {"temperature": 0.7, "max_tokens": 512}
    return jsonify(_db.get_state("agent_config", defaults))


@app.route("/api/config", methods=["PATCH"])
def api_patch_config():
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 503
    data = request.get_json(force=True)
    config = _db.get_state("agent_config",
                           {"temperature": 0.7, "max_tokens": 512})
    for k, v in data.items():
        config[k] = v
    _db.set_state("agent_config", config)
    return jsonify({"ok": True, "config": config})


# 9. Command History Search
@app.route("/api/commands/search")
def api_search_commands():
    q = request.args.get("q", "").strip()
    limit = min(int(request.args.get("limit", 50)), 500)
    if not q:
        return jsonify([])

    if _HAS_DB and _db.DB_PATH:
        try:
            from agent.db import _get_conn
            conn = _get_conn()
            rows = conn.execute(
                "SELECT timestamp, command, allowed, reason, result_status "
                "FROM commands WHERE command LIKE ? ORDER BY id DESC LIMIT ?",
                (f"%{q}%", limit)
            ).fetchall()
            results = [dict(r) for r in reversed(rows)]

            # Also search timeline
            tl_rows = conn.execute(
                "SELECT timestamp, reasoning, command, status, output_preview "
                "FROM timeline WHERE command LIKE ? OR reasoning LIKE ? "
                "ORDER BY id DESC LIMIT ?",
                (f"%{q}%", f"%{q}%", limit)
            ).fetchall()
            tl_results = [dict(r) for r in reversed(tl_rows)]

            return jsonify({"commands": results, "timeline": tl_results})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Fallback: search JSONL files
    log_dir = os.environ.get("NC_LOG_DIR",
                             os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"))
    results = []
    cmds_path = os.path.join(log_dir, "commands.jsonl")
    if os.path.exists(cmds_path):
        with open(cmds_path) as f:
            for line in f:
                if q.lower() in line.lower():
                    try:
                        results.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass
    return jsonify({"commands": results[-limit:], "timeline": []})


# 10. Network Info
@app.route("/api/network/current")
def api_network_current():
    if _HAS_DB and _db.DB_PATH:
        try:
            nets = _db.get_networks()
            if nets:
                # Most recently seen network
                latest = max(nets, key=lambda n: n.get("last_seen", ""))
                info = {
                    "cidr": latest.get("cidr", ""),
                    "ssid": latest.get("ssid", ""),
                    "gateway": latest.get("gateway", ""),
                    "first_seen": latest.get("first_seen", ""),
                    "last_seen": latest.get("last_seen", ""),
                }
                # Uptime from agent start
                wifi = _db.get_state("wifi_connected", False)
                info["wifi_connected"] = wifi

                # Try to get public IP from state
                info["public_ip"] = _db.get_state("public_ip", "unknown")
                return jsonify(info)
        except Exception:
            pass
    return jsonify({"cidr": "", "ssid": "", "gateway": "",
                    "wifi_connected": False, "public_ip": "unknown"})


@app.route("/api/cover-traffic", methods=["GET"])
def api_get_cover_traffic():
    """Get cover traffic config and stats."""
    config = {"ratio": 85, "enabled": False}
    if _HAS_DB:
        config = _db.get_state("cover_traffic", config)
    try:
        from agent.cover_traffic import get_stats, _running
        stats = get_stats()
        config["running"] = _running
        config["stats"] = stats
    except Exception:
        config["running"] = False
        config["stats"] = {"total": 0, "hourly": {}}
    return jsonify(config)


@app.route("/api/cover-traffic", methods=["POST"])
def api_set_cover_traffic():
    """Set cover traffic ratio and enabled state."""
    if not _HAS_DB:
        return jsonify({"error": "DB not available"}), 500
    data = request.json or {}
    config = _db.get_state("cover_traffic", {"ratio": 85, "enabled": False})
    if "ratio" in data:
        config["ratio"] = max(0, min(100, int(data["ratio"])))
    if "enabled" in data:
        config["enabled"] = bool(data["enabled"])
    _db.set_state("cover_traffic", config)
    try:
        from agent import cover_traffic
        if config["enabled"] and config["ratio"] > 0:
            cover_traffic.start()
        else:
            cover_traffic.stop()
    except Exception:
        pass
    return jsonify({"ok": True, "cover_traffic": config})


@app.route("/api/cover-traffic/log")
def api_cover_traffic_log():
    """Return recent cover traffic entries for the audit panel."""
    try:
        from agent.cover_traffic import get_recent_log
        return jsonify(get_recent_log(limit=100))
    except Exception:
        return jsonify([])


@app.route("/api/cover-traffic/throughput")
def api_cover_traffic_throughput():
    """Return cover traffic hourly counts for the timeline chart."""
    try:
        from agent.cover_traffic import get_stats
        stats = get_stats()
        buckets = [{"hour": k, "count": v} for k, v in stats.get("hourly", {}).items()]
        return jsonify({"buckets": buckets[-48:]})
    except Exception:
        return jsonify({"buckets": []})


@app.route("/api/current-network")
def api_current_network():
    """Return the network_id of the network we're currently connected to."""
    try:
        from agent.net_detect import get_current_network
        subnet = get_current_network()[0]
        if _HAS_DB:
            import sqlite3 as _csql
            conn = _csql.connect(_db.DB_PATH)
            row = conn.execute("SELECT network_id FROM networks WHERE cidr=?", (subnet,)).fetchone()
            conn.close()
            if row:
                return jsonify({"network_id": row[0], "cidr": subnet})
        return jsonify({"network_id": None, "cidr": subnet})
    except Exception as e:
        return jsonify({"network_id": None, "error": str(e)})


@app.route("/api/operating-hours", methods=["GET"])
def api_get_operating_hours():
    """Get operating hours config."""
    if _HAS_DB:
        hours = _db.get_state("operating_hours", {"enabled": False, "start": 7, "end": 23})
        return jsonify(hours)
    return jsonify({"enabled": False, "start": 7, "end": 23})


@app.route("/api/operating-hours", methods=["POST"])
def api_set_operating_hours():
    """Set operating hours. Agent sleeps outside this window."""
    if not _HAS_DB:
        return jsonify({"error": "DB not available"}), 500
    data = request.json or {}
    hours = {
        "enabled": bool(data.get("enabled", False)),
        "start": int(data.get("start", 7)),
        "end": int(data.get("end", 23)),
    }
    _db.set_state("operating_hours", hours)
    return jsonify({"ok": True, "operating_hours": hours})


@app.route("/api/credentials", methods=["POST"])
def api_add_credential():
    """Add a credential manually. If host is empty, it's generic for the network."""
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 500
    data = request.json or {}
    service = data.get("service", "ssh")
    username = data.get("username", "")
    password = data.get("password", "")
    host = data.get("host", "")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    # Detect network from host or use current network
    network = ""
    if host:
        import sqlite3 as _csql
        conn = _csql.connect(_db.DB_PATH)
        row = conn.execute("SELECT network FROM hosts WHERE ip=?", (host,)).fetchone()
        if row:
            network = row[0] or ""
        conn.close()
    if not network:
        # Use first available network
        try:
            nets = _db.get_networks()
            if nets:
                network = nets[0].get("network_id", "")
        except Exception:
            pass
    _db.add_credential(service, username, password, host, network)
    return jsonify({"ok": True, "message": f"Credential saved: {service} {username}@{host or 'any'}"})


@app.route("/api/credentials/<int:cred_id>", methods=["DELETE"])
def api_delete_credential(cred_id):
    """Delete a credential by ID."""
    if not _HAS_DB or not _db.DB_PATH:
        return jsonify({"error": "DB not available"}), 500
    import sqlite3 as _dsql
    conn = _dsql.connect(_db.DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM credentials WHERE id=?", (cred_id,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if deleted:
        return jsonify({"ok": True, "message": f"Credential {cred_id} deleted"})
    return jsonify({"error": "Credential not found"}), 404


@app.route("/api/throughput")
def api_throughput():
    """Return command throughput bucketed by hour for the timeline chart."""
    import sqlite3 as _sql
    from collections import OrderedDict

    log_dir = os.environ.get("NC_LOG_DIR",
                             os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"))
    buckets = OrderedDict()

    # Read timeline for hourly buckets
    tl_path = os.path.join(log_dir, "timeline.jsonl")
    try:
        with open(tl_path) as f:
            for line in f:
                try:
                    d = json.loads(line.strip())
                    if not d.get("command", "").strip():
                        continue
                    ts = d.get("timestamp", "")
                    if "T" in ts:
                        hour_key = ts[:13]  # "2026-03-22T14"
                        buckets[hour_key] = buckets.get(hour_key, 0) + 1
                except Exception:
                    pass
    except Exception:
        pass

    # Merge with cover traffic hourly stats
    cover_buckets = {}
    try:
        from agent.cover_traffic import get_stats
        cover_stats = get_stats()
        cover_buckets = cover_stats.get("hourly", {})
    except Exception:
        pass

    # Build combined result with both offensive and cover counts
    all_hours = sorted(set(list(buckets.keys()) + list(cover_buckets.keys())))
    result = []
    for h in all_hours[-48:]:
        result.append({
            "hour": h,
            "count": buckets.get(h, 0),
            "cover": cover_buckets.get(h, 0),
        })
    return jsonify({"buckets": result})


@app.route("/api/topology")
def api_topology():
    """Network topology and attack path analysis."""
    try:
        from agent.report_generator import generate_topology, generate_attack_paths
        return jsonify({
            "topology": generate_topology(),
            "attack_paths": generate_attack_paths(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/training/eval")
def api_training_eval():
    """Finetuning data quality evaluation."""
    try:
        from agent.report_generator import get_finetuning_stats
        return jsonify(get_finetuning_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/passive/start", methods=["POST"])
def api_passive_start():
    """Start passive network capture."""
    try:
        from agent.passive_capture import start_capture
        duration = int(request.json.get("duration", 120)) if request.json else 120
        start_capture(duration=min(duration, 600))
        return jsonify({"status": "started", "duration": duration})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/passive/results")
def api_passive_results():
    """Get passive capture results, filtered by selected network."""
    try:
        import json as _json
        results_file = "/tmp/nc-passive-parsed.json"
        import os
        if os.path.exists(results_file):
            with open(results_file) as f:
                data = _json.load(f)
            # Filter by network's CIDR if one is selected.
            network_id = request.args.get("network", "")
            if network_id:
                data = _filter_records_by_network(data, network_id)
            return jsonify(data)
        return jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/vulnerabilities/<int:vuln_id>")
def api_vuln_detail(vuln_id):
    """Get detailed info for a single vulnerability."""
    import sqlite3 as _sql
    log_dir = os.environ.get("NC_LOG_DIR",
                             os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"))
    _dbpath = os.path.join(log_dir, "nightcrawler.db")
    try:
        conn = _sql.connect(_dbpath)
        conn.row_factory = _sql.Row
        row = conn.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "not found"}), 404
        v = dict(row)
        import re
        cves = re.findall(r'(CVE-\d{4}-\d+)', v.get("vuln", ""))
        v["cves"] = cves
        v["remediation"] = _get_remediation(v.get("service", ""), v.get("vuln", ""))
        return jsonify(v)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/generate", methods=["POST"])
def api_report_generate():
    """Generate the full markdown report. Pass ?network=<id> to filter."""
    try:
        import subprocess
        script = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                              "scripts", "generate-report.py")
        network_id = request.args.get("network", "")
        cmd = ["python3", script]
        if network_id:
            cmd.append(network_id)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return jsonify({"ok": True, "message": result.stdout.strip()})
        return jsonify({"ok": False, "error": result.stderr.strip()}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/report/download")
def api_report_download():
    """Download the generated markdown report."""
    log_dir = os.environ.get("NC_LOG_DIR",
                             os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"))
    report_path = os.path.join(log_dir, "report.md")
    if os.path.exists(report_path):
        with open(report_path) as f:
            return f.read(), 200, {"Content-Type": "text/markdown; charset=utf-8"}
    return "Report not found. Click REPORT to generate.", 404


@app.route("/api/report")
def api_report():
    """Generate a client-ready penetration test report."""
    import sqlite3 as _sql

    log_dir = os.environ.get("NC_LOG_DIR",
                             os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"))
    _dbpath = os.path.join(log_dir, "nightcrawler.db")

    scope_cidr = "auto"
    try:
        from agent.net_detect import get_current_network
        scope_cidr = get_current_network()[0]
    except: pass
    vulns, creds, hosts_data = [], [], []
    try:
        conn = _sql.connect(_dbpath)
        conn.row_factory = _sql.Row
        vulns = [dict(r) for r in conn.execute("SELECT * FROM vulnerabilities ORDER BY severity DESC").fetchall()]
        creds = [dict(r) for r in conn.execute("SELECT * FROM credentials").fetchall()]
        hosts_data = [dict(r) for r in conn.execute("SELECT * FROM hosts").fetchall()]
        total_cmds = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
        conn.close()
    except Exception:
        total_cmds = 0

    # Build report
    report = {
        "title": "Nightcrawler Penetration Test Report",
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scope": scope_cidr,
        "summary": {
            "hosts_discovered": len(hosts_data),
            "vulnerabilities_found": len(vulns),
            "credentials_found": len(creds),
            "commands_executed": total_cmds,
            "critical": sum(1 for v in vulns if v.get("severity") == "critical"),
            "high": sum(1 for v in vulns if v.get("severity") == "high"),
            "medium": sum(1 for v in vulns if v.get("severity") == "medium"),
            "low": sum(1 for v in vulns if v.get("severity") == "low"),
        },
        "vulnerabilities": [],
        "credentials": [],
        "hosts": [],
    }

    # Format vulnerabilities with remediation chain
    for v in vulns:
        entry = {
            "host": v.get("host", ""),
            "service": v.get("service", ""),
            "severity": v.get("severity", "medium"),
            "finding": v.get("vuln", ""),
            "exploit_chain": v.get("chain", "Not recorded"),
            "discovered": v.get("timestamp", ""),
            "remediation": _get_remediation(v.get("service", ""),
                                            v.get("vuln", "")),
        }
        report["vulnerabilities"].append(entry)

    # Format credentials
    for c in creds:
        report["credentials"].append({
            "host": c.get("host", ""),
            "service": c.get("service", ""),
            "username": c.get("username", ""),
            "password": "***REDACTED***",
            "discovered": c.get("timestamp", ""),
        })

    # Host summary
    for h in hosts_data:
        ports = h.get("ports", "")
        if isinstance(ports, str):
            try:
                ports = json.loads(ports) if ports else []
            except Exception:
                ports = []
        report["hosts"].append({
            "ip": h.get("ip", ""),
            "mac": h.get("mac", ""),
            "hostname": h.get("hostname", ""),
            "ports": ports,
        })

    return jsonify(report)


# ---------------------------------------------------------------------------
# Offline Mode API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/offline/state")
def api_offline_state():
    """Return full offline pipeline state.

    Auto-detects two triggers for entering offline mode:
    1. WiFi is down (no IP on wlan0) — enters offline, kills agent+LLM
    2. USB WiFi adapter plugged in — enters offline, loads driver, keeps wlan0 up
    """
    from agent import offline_manager
    from agent.net_detect import is_wifi_connected
    state = offline_manager.get_state()

    if state["stage"] == 5:  # Currently ONLINE
        # WiFi down: inform UI but don't destroy session data
        if not offline_manager.SIMULATE and not is_wifi_connected():
            state["wifi_down"] = True
        # USB adapter: only auto-enter offline if we didn't JUST connect
        # (connect sets _state["_connected_at"] timestamp to prevent immediate revert)
        elif not offline_manager.SIMULATE:
            connected_at = state.get("_connected_at", 0)
            if connected_at and (time.time() - connected_at) < 300:
                pass  # Within 5 min of connect — don't revert to offline
            else:
                usb_adapters = offline_manager._get_usb_adapters()
                if usb_adapters:
                    offline_manager.force_offline()
                    state = offline_manager.get_state()

    elif state["stage"] < 5 and not offline_manager.SIMULATE:
        # Currently in OFFLINE mode — check if adapter was unplugged
        usb_adapters = offline_manager._get_usb_adapters()
        if not usb_adapters:
            # Adapter gone — stop capture and transition
            if is_wifi_connected():
                offline_manager.stop_capture()
                offline_manager.force_online()
                state = offline_manager.get_state()
            else:
                state["error"] = "USB adapter unplugged"

    # Include basic adapter info (no insmod — just check if USB device present)
    if "adapter" not in state and not offline_manager.SIMULATE:
        usb = offline_manager._get_usb_adapters()
        if usb:
            vid, pid, drv, ko_list, desc = usb[0]
            iface, _ = offline_manager._detect_ext_adapter()
            state["adapter"] = {"detected": True, "interface": iface or "",
                                "adapter": desc, "driver_loaded": offline_manager._is_module_loaded(drv)}
        else:
            state["adapter"] = None
    elif offline_manager.SIMULATE:
        state["adapter"] = None
    return jsonify(state)


@app.route("/api/offline/scan/start", methods=["POST"])
def api_offline_scan_start():
    from agent import offline_manager
    return jsonify(offline_manager.start_scan())


@app.route("/api/offline/scan/stop", methods=["POST"])
def api_offline_scan_stop():
    from agent import offline_manager
    return jsonify(offline_manager.stop_scan())


@app.route("/api/offline/networks")
def api_offline_networks():
    from agent import offline_manager
    # Parse latest CSV if real scan is running
    offline_manager.parse_scan_csv()
    return jsonify(offline_manager.get_networks())


@app.route("/api/offline/target", methods=["POST"])
def api_offline_target():
    from agent import offline_manager
    data = request.get_json(force=True)
    bssid = data.get("bssid", "")
    confirm_roe = data.get("confirm_roe", False)
    return jsonify(offline_manager.select_target(bssid, confirm_roe))


@app.route("/api/offline/capture/start", methods=["POST"])
def api_offline_capture_start():
    from agent import offline_manager
    return jsonify(offline_manager.start_capture())


@app.route("/api/offline/capture/stop", methods=["POST"])
def api_offline_capture_stop():
    from agent import offline_manager
    return jsonify(offline_manager.stop_capture())


@app.route("/api/offline/handshakes")
def api_offline_handshakes():
    from agent import offline_manager
    return jsonify(offline_manager.get_handshakes())


@app.route("/api/offline/handshakes/<int:hid>/download")
def api_offline_handshake_download(hid):
    """Download a specific handshake's capture file."""
    from agent import offline_manager
    hs = offline_manager.get_handshake(hid)
    if not hs or not hs.get("capture_file"):
        return jsonify({"error": "Handshake or capture file not found"}), 404
    cap_rel = hs["capture_file"]
    cap_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), cap_rel)
    if not os.path.exists(cap_path):
        # Try alternate extension
        for alt in [cap_path.replace(".pcapng", ".22000"), cap_path.replace(".22000", ".pcapng")]:
            if os.path.exists(alt):
                cap_path = alt
                break
        else:
            return jsonify({"error": "Capture file not found on disk"}), 404
    safe_name = os.path.basename(cap_path)
    return send_file(cap_path, as_attachment=True, download_name=safe_name)


@app.route("/api/offline/handshakes/<int:hid>", methods=["DELETE"])
def api_offline_handshake_delete(hid):
    """Delete a specific handshake record and its capture files."""
    from agent import offline_manager
    return jsonify(offline_manager.delete_handshake(hid))


@app.route("/api/offline/handshakes/network/<path:bssid>", methods=["DELETE"])
def api_offline_handshake_delete_by_bssid(bssid):
    """Delete all handshakes for a specific BSSID."""
    from agent import offline_manager
    return jsonify(offline_manager.delete_handshakes_by_bssid(bssid))


@app.route("/api/offline/crack/start", methods=["POST"])
def api_offline_crack_start():
    from agent import offline_manager
    data = request.get_json(force=True) if request.data else {}
    handshake_id = data.get("handshake_id")
    return jsonify(offline_manager.start_crack(handshake_id))


@app.route("/api/offline/crack/stop", methods=["POST"])
def api_offline_crack_stop():
    from agent import offline_manager
    return jsonify(offline_manager.stop_crack())


@app.route("/api/offline/crack/status")
def api_offline_crack_status():
    from agent import offline_manager
    s = offline_manager.get_state()
    return jsonify({
        "progress": s["crack_progress"],
        "speed": s["crack_speed"],
        "candidates": s["crack_candidates"],
        "total": s["crack_total"],
        "eta": s["crack_eta"],
        "wordlist": s["crack_wordlist"],
        "password": s["password"],
    })


@app.route("/api/offline/connect", methods=["POST"])
def api_offline_connect():
    from agent import offline_manager
    return jsonify(offline_manager.connect())


@app.route("/api/offline/capture/<path:filename>")
def api_offline_download_capture(filename):
    """Download a .cap file for exfiltration."""
    cap_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "captures")
    safe_name = os.path.basename(filename)
    path = os.path.join(cap_dir, safe_name)
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name=safe_name)
    return jsonify({"error": "File not found"}), 404


@app.route("/api/offline/force", methods=["POST"])
def api_offline_force():
    """Force offline/online mode (testing only)."""
    from agent import offline_manager
    data = request.get_json(force=True)
    mode = data.get("mode", "offline")
    if mode == "offline":
        return jsonify(offline_manager.force_offline())
    else:
        return jsonify(offline_manager.force_online())


@app.route("/api/offline/simulate", methods=["POST"])
def api_offline_simulate():
    """Enable/disable simulation mode (testing only)."""
    from agent import offline_manager
    data = request.get_json(force=True)
    offline_manager.set_simulate(data.get("enabled", True))
    return jsonify({"ok": True, "simulate": offline_manager.SIMULATE})


@app.route("/api/offline/adapter")
def api_offline_adapter():
    """Check if external WiFi adapter USB device is present (no driver loading)."""
    from agent import offline_manager
    usb_adapters = offline_manager._get_usb_adapters()
    if usb_adapters:
        vid, pid, driver_name, ko_list, desc = usb_adapters[0]
        iface, mon = offline_manager._detect_ext_adapter()
        return jsonify({
            "detected": True,
            "interface": iface or "",
            "adapter": desc,
            "driver": driver_name,
            "driver_loaded": offline_manager._is_module_loaded(driver_name),
            "usb_id": f"{vid}:{pid}",
        })
    return jsonify({
        "detected": False,
        "interface": "",
        "adapter": "",
        "driver": "",
        "usb_id": "",
    })


# ── Wi-Fi one-tap connect (open + operator-saved private networks) ─────────
# Convenience layer: connect the phone to open networks or private networks the
# operator saved a password for. NEVER cracks — a locked network with no saved
# password is not joinable. Separate from the offline monitor-mode pipeline.

@app.route("/api/wifi/scan")
def api_wifi_scan():
    from agent import wifi_connect
    return jsonify({"networks": wifi_connect.scan_available()})


@app.route("/api/wifi/status")
def api_wifi_status():
    from agent import wifi_connect
    return jsonify(wifi_connect.get_status())


@app.route("/api/wifi/connect", methods=["POST"])
def api_wifi_connect():
    from agent import wifi_connect
    data = request.get_json(force=True) or {}
    return jsonify(wifi_connect.connect_to(data.get("ssid", "")))


@app.route("/api/wifi/saved", methods=["GET", "POST"])
def api_wifi_saved():
    """List/add/remove the operator's own saved networks.

    GET never returns stored passwords — only SSID + hidden flag.
    """
    from agent import wifi_connect
    if request.method == "GET":
        return jsonify({"saved": [{"ssid": n["ssid"], "hidden": n.get("hidden", False)}
                                  for n in wifi_connect.list_saved()]})
    data = request.get_json(force=True) or {}
    if data.get("action") == "remove":
        return jsonify(wifi_connect.remove_saved(data.get("ssid", "")))
    return jsonify(wifi_connect.add_saved(
        data.get("ssid", ""), data.get("psk", ""), data.get("hidden", False)))


@app.route("/api/wifi/simulate", methods=["POST"])
def api_wifi_simulate():
    """Enable/disable Wi-Fi connect simulation mode (testing only)."""
    from agent import wifi_connect
    data = request.get_json(force=True) or {}
    wifi_connect.SIMULATE = bool(data.get("enabled", True))
    return jsonify({"ok": True, "simulate": wifi_connect.SIMULATE})


def _get_remediation(service: str, vuln: str) -> str:
    """Generate remediation advice based on the finding."""
    v_lower = vuln.lower()
    if "null-session" in v_lower or "null session" in v_lower or "smb shares" in v_lower:
        return ("1. Disable anonymous/null SMB sessions: set 'restrict anonymous = 2' in smb.conf. "
                "2. Remove unnecessary shares or set proper ACLs. "
                "3. Update Samba to latest version (CVE-2017-7494 SambaCry affects <4.6.4). "
                "4. Consider disabling SMBv1 entirely.")
    if "pi-hole" in v_lower and ("login" in v_lower or "pw=" in v_lower):
        return ("1. Set a strong, unique admin password for Pi-hole (pihole -a -p <password>). "
                "2. Bind admin interface to localhost only (WEBPASSWORD + lighttpd config). "
                "3. Update Pi-hole to latest version — CVE-2020-8816, CVE-2021-29449, CVE-2020-11108 affect older versions. "
                "4. Place admin behind VPN or SSH tunnel, not exposed on LAN.")
    if "pi-hole" in v_lower and "api" in v_lower:
        return ("1. Pi-hole API should require authentication. Set WEBPASSWORD via pihole -a -p. "
                "2. Restrict API access to localhost via lighttpd config. "
                "3. CVE-2022-23513 (broken access control) — update Pi-hole to latest.")
    if "pi-hole" in v_lower:
        return ("1. Set a strong admin password (pihole -a -p). "
                "2. Restrict admin panel to localhost/VPN. "
                "3. Update Pi-hole — multiple RCE CVEs in older versions.")
    if "vnc" in v_lower and "no auth" in v_lower:
        return ("1. Enable VNC authentication immediately. "
                "2. Use a strong password (not 'password', 'admin', or 'raspberry'). "
                "3. CVE-2006-2369 (RealVNC auth bypass) — update to latest version. "
                "4. Prefer SSH tunneling over direct VNC exposure. Bind to localhost.")
    if "vnc" in v_lower:
        return ("1. Set a strong VNC password. "
                "2. Bind VNC to localhost and access via SSH tunnel. "
                "3. Disable VNC if not needed.")
    if "dns" in v_lower and ("zone transfer" in v_lower or "axfr" in v_lower):
        return ("1. Restrict AXFR to authorized secondary DNS servers only (allow-transfer ACL). "
                "2. This exposes all internal hostnames, IPs, and network topology. "
                "3. In BIND: add 'allow-transfer { trusted-servers; };' to zone config. "
                "4. In dnsmasq: AXFR not typically supported, but verify with --no-hosts if needed.")
    if "dns" in v_lower and ("resolver" in v_lower or "open" in v_lower):
        return ("1. Restrict DNS resolver to internal clients only (ACL/firewall). "
                "2. Disable recursion for external queries. "
                "3. Open resolvers can be used for DNS amplification DDoS attacks. "
                "4. dnsmasq: use 'interface=eth0' and 'bind-interfaces' to limit exposure.")
    if "telnet" in v_lower:
        return ("1. Disable telnet IMMEDIATELY — all traffic including passwords sent in plaintext. "
                "2. Replace with SSH for all remote access. "
                "3. If telnet is required for legacy devices, isolate on a dedicated VLAN with strict ACLs.")
    if "cve-2024-6387" in v_lower:
        return ("1. Update OpenSSH to 9.8p1 or later (fixes regreSSHion). "
                "2. CVE-2024-6387 is a signal handler race condition allowing unauthenticated RCE. "
                "3. Mitigate by setting 'LoginGraceTime 0' in sshd_config (disables timeout). "
                "4. Affects OpenSSH 8.5p1-9.7p1 on glibc-based Linux.")
    if "cve-2017-7494" in v_lower:
        return ("1. Update Samba to 4.6.4+ (fixes SambaCry RCE). "
                "2. CVE-2017-7494 allows remote code execution via writable SMB shares. "
                "3. Add 'nt pipe support = no' to smb.conf as workaround. "
                "4. Remove writable anonymous shares.")
    if "cve" in v_lower:
        import re
        cves = re.findall(r'(CVE-\d{4}-\d+)', vuln)
        cve_str = ', '.join(cves) if cves else vuln[:40]
        return (f"1. Apply vendor security patches for {cve_str}. "
                f"2. Check https://nvd.nist.gov/vuln/detail/{cves[0] if cves else ''} for full details. "
                f"3. If patching is not immediately possible, apply vendor-recommended mitigations. "
                f"4. Monitor for exploitation attempts in logs.")
    if ".env" in v_lower:
        return ("1. Remove .env file from web root immediately — may contain database passwords, API keys. "
                "2. Add '.env' to .htaccess deny rules or nginx location block. "
                "3. Move secrets to environment variables or a secrets manager. "
                "4. Rotate any credentials that were in the exposed .env file.")
    if "robots.txt" in v_lower:
        return ("1. Review robots.txt for sensitive path disclosure. "
                "2. robots.txt is public — don't list admin panels or internal paths. "
                "3. Use authentication/authorization instead of obscurity.")
    if "server-status" in v_lower:
        return ("1. Restrict /server-status to localhost: 'Require local' in Apache config. "
                "2. Exposes active connections, client IPs, and request URLs.")
    if "ftp" in v_lower and "anonymous" in v_lower:
        return ("1. Disable anonymous FTP unless specifically needed. "
                "2. If required, restrict to a read-only chroot with non-sensitive data. "
                "3. Consider replacing FTP with SFTP (SSH-based).")
    if "default" in v_lower or "password" in v_lower:
        return ("1. Change all default credentials immediately. "
                "2. Enforce strong password policy (min 12 chars, complexity). "
                "3. Enable account lockout after failed attempts. "
                "4. Consider key-based authentication where supported.")
    return "Review this finding and consult the vendor documentation for remediation steps."


def get_tailscale_ip() -> str:
    """Get the Tailscale interface IP. Returns 127.0.0.1 if not available."""
    import subprocess

    # Method 1: tailscale CLI (works on Android side)
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True, text=True, timeout=5,
        )
        ip = result.stdout.strip()
        if ip:
            return ip
    except Exception:
        pass

    # Method 2: parse ip addr for tailscale0 (works in Kali chroot)
    try:
        result = subprocess.run(
            ["ip", "addr", "show", "tailscale0"],
            capture_output=True, text=True, timeout=5,
        )
        import re
        match = re.search(r'inet (100\.[\d.]+)/\d+', result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    return "127.0.0.1"


def run_webui(port: int = 8888, host: str = None, ssl: bool = True):
    """Start the web UI server in a background thread.

    By default binds to Tailscale IP only (not exposed on target network).
    Falls back to 127.0.0.1 if Tailscale isn't available.
    Pass host="0.0.0.0" to override and listen on all interfaces.
    SSL enabled by default using self-signed cert for Tailscale HTTPS.
    """
    if host is None:
        # Bind to 0.0.0.0 so it's reachable from both Tailscale and
        # localhost (phone's own browser). The webui is read-only dashboard
        # + C2 controls that require physical/Tailscale access anyway.
        host = "0.0.0.0"

    ssl_ctx = None
    if ssl:
        import ssl as _ssl
        cert_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "certs")
        cert_file = os.path.join(cert_dir, "cert.pem")
        key_file = os.path.join(cert_dir, "key.pem")
        if os.path.exists(cert_file) and os.path.exists(key_file):
            ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(cert_file, key_file)

    thread = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False,
                               use_reloader=False, ssl_context=ssl_ctx),
        daemon=True,
    )
    thread.start()
    proto = "https" if ssl_ctx else "http"
    print(f"WebUI: {proto}://{host}:{port}")
    return thread
