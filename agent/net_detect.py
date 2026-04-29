"""Dynamic network detection — auto-detects current subnet from wlan0.

All components should use this instead of hardcoding IP prefixes.
Supports: 192.168.x, 10.x, 172.16-31.x — any private network.
"""

import re
import subprocess


_cache = {}


def get_current_network():
    """Return (subnet, prefix, our_ip, gateway_ip) from wlan0.
    
    Example: ('192.168.0.0/24', '192.168.0.', '192.168.0.184', '192.168.0.1')
    """
    if _cache.get("ts") and __import__("time").time() - _cache["ts"] < 60:
        return _cache["subnet"], _cache["prefix"], _cache["our_ip"], _cache["gateway"]

    try:
        result = subprocess.run(["ip", "-4", "addr", "show", "wlan0"],
                                capture_output=True, text=True, timeout=5)
        match = re.search(r'inet (\d+\.\d+\.\d+)\.(\d+)/(\d+)', result.stdout)
        if match:
            prefix = match.group(1) + "."
            our_ip = f"{match.group(1)}.{match.group(2)}"
            subnet = f"{match.group(1)}.0/{match.group(3)}"
            gateway = f"{match.group(1)}.1"
            _cache.update({"subnet": subnet, "prefix": prefix,
                           "our_ip": our_ip, "gateway": gateway,
                           "ts": __import__("time").time()})
            return subnet, prefix, our_ip, gateway
    except Exception:
        pass

    return "192.168.0.0/24", "192.168.0.", "192.168.0.1", "192.168.0.1"


def is_target_ip(ip):
    """Check if an IP is on the current target network using CIDR matching."""
    import ipaddress
    subnet, _, _, _ = get_current_network()
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except (ValueError, TypeError):
        return False


def get_gateway_ip():
    """Return the likely gateway IP (.1 on the current subnet)."""
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
