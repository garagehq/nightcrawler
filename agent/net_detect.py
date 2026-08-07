"""Dynamic network detection — auto-detects current subnet from wlan0.

All components should use this instead of hardcoding IP prefixes.
Supports: 192.168.x, 10.x, 172.16-31.x — any private network.

Detection sources, in priority order:
  1. `ip -4 addr show wlan0`               (gives IP + real prefix; best)
  2. `termux-wifi-connectioninfo`          (non-rooted Android; IP only, /24 assumed)
  3. `ifconfig wlan0`                       (fallback; IP + netmask if present)

Strict / fail-loud mode
------------------------
The historical behaviour on total detection failure is to return a hardcoded
`192.168.0.0/24`. On a non-rooted phone that can silently authorize scanning a
subnet you are NOT on. In the Termux "lite" build we run STRICT: if no source
positively yields our IP, `get_current_network()` returns `(None, None, None,
None)` so callers can fail closed (scan nothing) rather than guess a network.

Strict defaults to on when `NC_LITE=1`; callers may override per call.
"""

import ipaddress
import json
import os
import re
import subprocess
import time


_cache = {}

# Legacy fallback used only in non-strict (rooted) mode.
_FALLBACK = ("192.168.0.0/24", "192.168.0.", "192.168.0.1", "192.168.0.1")


def _strict_default():
    return os.environ.get("NC_LITE", "0") == "1"


def _from_ip_prefix(a_b_c, host, prefix_len):
    """Build the (subnet, prefix, our_ip, gateway) tuple from parts."""
    prefix = a_b_c + "."
    our_ip = f"{a_b_c}.{host}"
    # Normalize to the canonical network base so /23, /22 etc. are valid.
    try:
        net = ipaddress.ip_network(f"{our_ip}/{prefix_len}", strict=False)
        subnet = str(net)
    except ValueError:
        subnet = f"{a_b_c}.0/{prefix_len}"
    gateway = f"{a_b_c}.1"  # heuristic; not read from a routing table
    return subnet, prefix, our_ip, gateway


def _detect_from_ip():
    """`ip -4 addr show wlan0` — gives IP and the real prefix length."""
    try:
        result = subprocess.run(["ip", "-4", "addr", "show", "wlan0"],
                                capture_output=True, text=True, timeout=5)
        m = re.search(r'inet (\d+\.\d+\.\d+)\.(\d+)/(\d+)', result.stdout)
        if m:
            return _from_ip_prefix(m.group(1), m.group(2), m.group(3))
    except Exception:
        pass
    return None


def _detect_from_termux():
    """`termux-wifi-connectioninfo` — non-rooted Android. Returns IP only, so
    the prefix is assumed /24 (the common case). Requires the Termux:API app."""
    try:
        result = subprocess.run(["termux-wifi-connectioninfo"],
                                capture_output=True, text=True, timeout=5)
        data = json.loads(result.stdout)
        ip = str(data.get("ip", "")).strip()
        if ip and ip != "0.0.0.0":
            octets = ip.split(".")
            if len(octets) == 4 and all(o.isdigit() for o in octets):
                return _from_ip_prefix(".".join(octets[:3]), octets[3], "24")
    except Exception:
        pass
    return None


def _detect_from_ifconfig():
    """`ifconfig wlan0` — last-resort fallback. Prefix from netmask if present,
    else /24."""
    try:
        result = subprocess.run(["ifconfig", "wlan0"],
                                capture_output=True, text=True, timeout=5)
        out = result.stdout
        ip_m = re.search(r'inet (?:addr:)?(\d+\.\d+\.\d+)\.(\d+)', out)
        if not ip_m:
            return None
        prefix_len = "24"
        mask_m = re.search(r'(?:netmask|Mask:)\s*(\d+\.\d+\.\d+\.\d+)', out)
        if mask_m:
            try:
                prefix_len = str(ipaddress.IPv4Network(
                    f"0.0.0.0/{mask_m.group(1)}").prefixlen)
            except ValueError:
                pass
        return _from_ip_prefix(ip_m.group(1), ip_m.group(2), prefix_len)
    except Exception:
        pass
    return None


def _detect():
    """Try each source in priority order. Returns a tuple or None."""
    for source in (_detect_from_ip, _detect_from_termux, _detect_from_ifconfig):
        found = source()
        if found:
            return found
    return None


def get_current_network(strict=None):
    """Return (subnet, prefix, our_ip, gateway_ip) from the connected Wi-Fi.

    Example: ('192.168.0.0/24', '192.168.0.', '192.168.0.184', '192.168.0.1')

    strict=True  -> on detection failure return (None, None, None, None).
    strict=False -> on detection failure return the legacy 192.168.0.0/24.
    strict=None  -> default from NC_LITE (True when NC_LITE=1).
    """
    if strict is None:
        strict = _strict_default()

    if _cache.get("ts") and time.time() - _cache["ts"] < 60:
        return _cache["subnet"], _cache["prefix"], _cache["our_ip"], _cache["gateway"]

    found = _detect()
    if found:
        subnet, prefix, our_ip, gateway = found
        _cache.update({"subnet": subnet, "prefix": prefix, "our_ip": our_ip,
                       "gateway": gateway, "ts": time.time()})
        return found

    # No source positively identified our network. Do NOT cache a miss.
    if strict:
        return (None, None, None, None)
    return _FALLBACK


def is_target_ip(ip):
    """Check if an IP is on the current target network using CIDR matching.

    Returns False when the network is unconfirmed (strict/lite fail-closed).
    """
    subnet, _, _, _ = get_current_network()
    if not subnet:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except (ValueError, TypeError):
        return False


def get_gateway_ip():
    """Return the likely gateway IP (.1 on the current subnet), or None if the
    network is unconfirmed."""
    _, _, _, gw = get_current_network()
    return gw


def is_wifi_connected():
    """Check if wlan0 has an IP address (i.e., connected to a network).

    Returns True if wlan0 has an inet address, False otherwise.
    Also returns False if wlan0 is in monitor mode (wlan0mon exists).
    """
    try:
        # Check if monitor mode is active
        result = subprocess.run(["ip", "link", "show", "wlan0mon"],
                                capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            return False  # monitor mode active = not connected

        # Check if wlan0 has an IP
        result = subprocess.run(["ip", "-4", "addr", "show", "wlan0"],
                                capture_output=True, text=True, timeout=3)
        return bool(re.search(r'inet \d+\.\d+\.\d+\.\d+', result.stdout))
    except Exception:
        return False
