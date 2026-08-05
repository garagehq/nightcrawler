"""On-demand Wi-Fi connect (open networks + the operator's saved private networks).

A convenience layer that lets the operator connect the phone to:
  1. genuinely OPEN networks (no encryption — most public guest Wi-Fi), and
  2. private/locked networks the operator has SAVED a password for — home,
     office, a friend's Wi-Fi, a personal hotspot — including the operator's own
     hidden (non-broadcast) SSIDs.

It scans the phone's internal radio through Android's own Wi-Fi framework (over
SSH:9022) and connects on demand — the operator taps a network, it joins. It
does NOT auto-join in the background.

Hard boundary (must never change):
  * It NEVER cracks or guesses a password. A locked network with no saved
    credential is surfaced but is NOT joinable.
  * No monitor mode, no handshake/PMKID capture, no wordlists, no SSID
    de-anonymization. This module is independent of ``offline_manager.py`` (the
    monitor-mode cracking pipeline) and never invokes it.
  * "Hidden network" support means the operator's OWN hidden SSIDs, joined by a
    name + password the operator supplied. Third-party hidden networks that
    appear in a scan with an unknown name are shown for awareness only and are
    not joinable.
"""

import logging
import os
import re
import subprocess
import time
import urllib.request

from agent import db
from agent import net_detect

log = logging.getLogger("wifi_connect")

# Simulation mode: no SSH, no real radio. Toggle with NC_WIFI_SIM=1 or by
# setting this attribute directly (tests do the latter).
SIMULATE = os.environ.get("NC_WIFI_SIM", "0") == "1"

# Android shell over SSH (managed-mode association, same transport offline_manager
# uses in connect()). We deliberately drive Android's Wi-Fi framework rather than
# the chroot's wpa_supplicant, which would break Android Wi-Fi until reboot.
_ANDROID_SSH = ["ssh", "-p", "9022", "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no", "shell@127.0.0.1"]

# SQLite state keys (agent/db.py get_state/set_state)
_SAVED_KEY = "wifi_saved"     # [{"ssid": str, "psk": str, "hidden": bool}]
_STATUS_KEY = "wifi_status"   # {"last_ssid","connected","portal_pending","last_error","ts"}

# Security tokens that mark a network as locked (needs a password).
_LOCKED_TOKENS = ("WPA", "WPA2", "WPA3", "WEP", "PSK", "SAE", "EAP")

# Captive-portal probe: a clean connection returns HTTP 204 with no body.
_PORTAL_CHECK_URL = "http://connectivitycheck.gstatic.com/generate_204"

# Fixed fake scan results for SIMULATE/testing: one open, one saved-able locked,
# one unsaved locked (never joinable), one hidden (unknown name, never joinable).
_SIM_NETWORKS = [
    {"ssid": "CoffeeShop", "bssid": "AA:BB:CC:00:00:01",
     "security": "[ESS]", "signal": -45},
    {"ssid": "HomeNet", "bssid": "AA:BB:CC:00:00:02",
     "security": "[WPA2-PSK-CCMP][ESS]", "signal": -55},
    {"ssid": "Neighbor5G", "bssid": "AA:BB:CC:00:00:03",
     "security": "[WPA2-PSK-CCMP][ESS]", "signal": -70},
    {"ssid": "", "bssid": "AA:BB:CC:00:00:04",
     "security": "[WPA2-PSK-CCMP][ESS]", "signal": -80},
]


# ── helpers ───────────────────────────────────────────────────────────────

def _run(cmd, timeout=15):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _ssh(remote_cmd, timeout=15):
    return _run(_ANDROID_SSH + [remote_cmd], timeout=timeout)


def _is_open(security):
    """True when the security string carries no lock token (bare [ESS] = open)."""
    s = (security or "").upper()
    return not any(tok in s for tok in _LOCKED_TOKENS)


# ── saved networks (the operator's own credentials) ───────────────────────

def list_saved():
    return db.get_state(_SAVED_KEY, []) or []


def _saved_map():
    return {n["ssid"]: n for n in list_saved() if n.get("ssid")}


def add_saved(ssid, psk, hidden=False):
    """Save a network the operator legitimately has access to.

    Requires a password — this tool never derives or guesses one.
    """
    ssid = (ssid or "").strip()
    if not ssid:
        return {"error": "ssid required"}
    if not psk:
        return {"error": "password required — this tool never guesses passwords"}
    saved = [n for n in list_saved() if n.get("ssid") != ssid]
    saved.append({"ssid": ssid, "psk": psk, "hidden": bool(hidden)})
    db.set_state(_SAVED_KEY, saved)
    return {"ok": True, "count": len(saved)}


def remove_saved(ssid):
    saved = [n for n in list_saved() if n.get("ssid") != ssid]
    db.set_state(_SAVED_KEY, saved)
    return {"ok": True, "count": len(saved)}


# ── status ────────────────────────────────────────────────────────────────

def _set_status(**kw):
    st = db.get_state(_STATUS_KEY, {}) or {}
    st.update(kw)
    st["ts"] = int(time.time())
    db.set_state(_STATUS_KEY, st)
    return st


def get_status():
    st = db.get_state(_STATUS_KEY, {}) or {}
    st["connected"] = True if SIMULATE else net_detect.is_wifi_connected()
    return st


# ── scanning (phone's own radio, managed mode — no USB adapter) ───────────

def scan_available():
    """List nearby networks via Android's Wi-Fi framework.

    Each item: {ssid, bssid, security, signal, open, saved, hidden, joinable}.
    Networks with an empty SSID are surfaced as "(hidden network)" and are NOT
    joinable — the tool does not de-anonymize other people's hidden SSIDs.
    """
    saved = _saved_map()

    if SIMULATE:
        raw = list(_SIM_NETWORKS)
    else:
        raw = _scan_cmd_wifi() or _scan_iw()

    out = []
    for n in raw:
        ssid = n.get("ssid", "") or ""
        is_open = _is_open(n.get("security", ""))
        hidden = ssid == ""
        is_saved = (not hidden) and ssid in saved
        out.append({
            "ssid": ssid if not hidden else "(hidden network)",
            "bssid": n.get("bssid", ""),
            "security": n.get("security", ""),
            "signal": n.get("signal", 0),
            "open": is_open,
            "saved": is_saved,
            "hidden": hidden,
            # Joinable only if we can do it without a password we weren't given:
            # an open network, or one whose password the operator has saved.
            "joinable": (not hidden) and (is_open or is_saved),
        })
    out.sort(key=lambda x: x.get("signal", -999), reverse=True)
    return out


def _scan_cmd_wifi():
    """Preferred: Android's cached scan results (non-disruptive)."""
    try:
        _ssh("cmd wifi start-scan", timeout=10)
        time.sleep(2)
        r = _ssh("cmd wifi list-scan-results", timeout=10)
    except Exception as e:
        log.warning("cmd wifi scan failed: %s", e)
        return []
    if r.returncode != 0 or not r.stdout.strip():
        return []
    return _parse_cmd_wifi(r.stdout)


def _parse_cmd_wifi(text):
    """Tolerant parser for `cmd wifi list-scan-results`.

    Column layout varies by Android version, so we extract by shape rather than
    fixed columns: a BSSID (MAC), the RSSI (a negative integer), the bracketed
    [..] tokens as security, and the SSID as the text sitting between the RSSI
    value and the security column (this preserves SSIDs that contain digits,
    e.g. "Neighbor5G"). Lines without a MAC are skipped.
    """
    nets = []
    mac_re = re.compile(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})')
    for line in text.splitlines():
        if "BSSID" in line and "SSID" in line:
            continue  # header
        m = mac_re.search(line)
        if not m:
            continue
        bssid = m.group(1)
        rest = line[m.end():]
        rssi_m = re.search(r'-\d{2,3}', rest)
        signal = int(rssi_m.group(0)) if rssi_m else 0
        flags = "".join(re.findall(r'\[[^\]]*\]', line))
        seg = rest[rssi_m.end():] if rssi_m else rest
        seg = re.sub(r'^\s*\([^)]*\)', '', seg)  # drop an RSSI "(age)" suffix
        br = seg.find('[')
        if br != -1:
            seg = seg[:br]
        ssid = seg.strip()
        nets.append({"ssid": ssid, "bssid": bssid,
                     "security": flags, "signal": signal})
    return nets


def _scan_iw():
    """Fallback: `iw dev wlan0 scan` (well-defined format) over SSH."""
    try:
        r = _ssh("iw dev wlan0 scan", timeout=20)
    except Exception as e:
        log.warning("iw scan failed: %s", e)
        return []
    if r.returncode != 0 or not r.stdout.strip():
        return []
    return _parse_iw(r.stdout)


def _parse_iw(text):
    nets = []
    cur = None
    for line in text.splitlines():
        bss = re.match(r'BSS ([0-9a-fA-F:]{17})', line.strip())
        if bss:
            if cur:
                nets.append(cur)
            cur = {"ssid": "", "bssid": bss.group(1), "security": "", "signal": 0}
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("signal:"):
            m = re.search(r'(-?\d+(?:\.\d+)?)', s)
            if m:
                cur["signal"] = int(float(m.group(1)))
        elif s.startswith("SSID:"):
            cur["ssid"] = s[len("SSID:"):].strip()
        elif s.startswith("RSN:"):
            cur["security"] = cur["security"] or "[WPA2]"
        elif s.startswith("WPA:"):
            cur["security"] = cur["security"] or "[WPA]"
    if cur:
        nets.append(cur)
    # Bare [ESS]-equivalent: no RSN/WPA line seen => open
    for n in nets:
        if not n["security"]:
            n["security"] = "[ESS]"
    return nets


# ── connecting (on demand) ────────────────────────────────────────────────

def connect_to(ssid):
    """Connect to `ssid` if it is open, or the operator saved its password.

    Never cracks: a locked network with no saved credential returns an error and
    no association is attempted.
    """
    ssid = (ssid or "").strip()
    if not ssid or ssid == "(hidden network)":
        return {"error": "select a real network"}

    entry = _saved_map().get(ssid)
    if entry:
        mode = "saved"
    else:
        net = next((n for n in scan_available() if n["ssid"] == ssid), None)
        if net and net["open"]:
            mode = "open"
        elif net and not net["open"]:
            return {"error": (f"'{ssid}' is locked and you haven't saved its "
                              f"password. This tool never guesses or cracks "
                              f"passwords — add it under Saved networks if it's "
                              f"yours.")}
        else:
            return {"error": f"'{ssid}' not found in scan and not saved"}

    _set_status(last_ssid=ssid, connected=False, portal_pending=False, last_error="")

    if SIMULATE:
        portal = ssid == "CoffeeShop"
        _set_status(connected=True, portal_pending=portal)
        return {"ok": True, "ip": "192.168.0.184", "ssid": ssid, "portal": portal}

    remote = (f"cmd wifi connect-network '{ssid}' open" if mode == "open"
              else f"cmd wifi connect-network '{ssid}' wpa2 '{entry['psk']}'")
    try:
        r = _ssh(remote, timeout=15)
        if r.returncode != 0:
            _wpa_cli_fallback(ssid, entry, is_open=(mode == "open"))
        time.sleep(8)
        ok, ip = _verify_connected()
        if not ok:
            _set_status(connected=False, last_error="no IP / not associated")
            return {"error": "association failed (no IP obtained)"}
        portal = _captive_portal_present()
        _set_status(connected=True, portal_pending=portal, last_error="")
        return {"ok": True, "ip": ip, "ssid": ssid, "portal": portal}
    except Exception as e:
        _set_status(connected=False, last_error=str(e))
        return {"error": str(e)}


def _wpa_cli_fallback(ssid, entry, is_open):
    """Best-effort fallback if `cmd wifi` returns non-zero. Sets scan_ssid for
    the operator's own hidden networks."""
    hidden = bool(entry.get("hidden")) if entry else False
    cmds = ["wpa_cli -i wlan0 add_network",
            f"wpa_cli -i wlan0 set_network 0 ssid '\"{ssid}\"'"]
    if hidden:
        cmds.append("wpa_cli -i wlan0 set_network 0 scan_ssid 1")
    if is_open:
        cmds.append("wpa_cli -i wlan0 set_network 0 key_mgmt NONE")
    else:
        cmds.append(f"wpa_cli -i wlan0 set_network 0 psk '\"{entry['psk']}\"'")
    cmds += ["wpa_cli -i wlan0 enable_network 0", "wpa_cli -i wlan0 save_config"]
    _ssh(" && ".join(cmds), timeout=20)


def _verify_connected():
    """(connected, ip) — connected == wlan0 has an IPv4 address."""
    if not net_detect.is_wifi_connected():
        return False, ""
    _, _, our_ip, _ = net_detect.get_current_network()
    return True, our_ip


def _captive_portal_present():
    """True if a captive portal is intercepting (no clean internet).

    A clean connection returns HTTP 204 with no body; a portal redirects
    (200/302) or the probe fails. We only DETECT — we never submit portal forms.
    """
    try:
        req = urllib.request.Request(_PORTAL_CHECK_URL,
                                     headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=6)
        return getattr(resp, "status", resp.getcode()) != 204
    except Exception:
        return True
