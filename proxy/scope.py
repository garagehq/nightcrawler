"""IP/port/host scope validation."""

import ipaddress
import re
from typing import List, Set, Tuple


class ScopeValidator:
    """Validates that commands target only in-scope networks and hosts."""

    def __init__(self, networks: List[str], excluded_hosts: List[str],
                 excluded_ports: List[int]):
        self.allowed_networks = [
            ipaddress.ip_network(n, strict=False) for n in networks
        ]
        self.excluded_hosts = set(excluded_hosts)
        self.excluded_ports = set(excluded_ports)

        # Regex to extract IPs and CIDRs from command strings
        self._ip_re = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
        )
        self._port_re = re.compile(r'-p\s*(\d[\d,\-]*)')

    def validate(self, command: str) -> Tuple[bool, str]:
        """Check if command targets only in-scope IPs and allowed ports."""
        # Check IPs
        for ip_str in self._ip_re.findall(command):
            ok, reason = self._check_ip(ip_str)
            if not ok:
                return False, reason

        # Check ports
        for port_match in self._port_re.findall(command):
            for part in port_match.replace('-', ',').split(','):
                part = part.strip()
                if part.isdigit() and int(part) in self.excluded_ports:
                    return False, f"EXCLUDED PORT: {part}"

        return True, "OK"

    def _check_ip(self, ip_str: str) -> Tuple[bool, str]:
        try:
            if '/' in ip_str:
                net = ipaddress.ip_network(ip_str, strict=False)
                if not any(net.overlaps(a) for a in self.allowed_networks):
                    return False, f"OUT OF SCOPE: {ip_str} not in allowed networks"
            else:
                addr = ipaddress.ip_address(ip_str)
                if str(addr) in self.excluded_hosts:
                    return False, f"EXCLUDED HOST: {ip_str}"
                if not any(addr in n for n in self.allowed_networks):
                    return False, f"OUT OF SCOPE: {ip_str} not in allowed networks"
        except ValueError:
            pass
        return True, "OK"
