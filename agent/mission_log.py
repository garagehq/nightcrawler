"""Mission log — structured findings and timeline.

Uses SQLite for persistent storage with MAC-keyed hosts
and multi-network support.
"""

import json
import os
import re
import subprocess
import time

from agent import db


def _detect_network_identity() -> dict:
    """Collect full network identity: gateway MAC, SSID, public IP, CIDR."""
    import hashlib
    identity = {"cidr": "", "gateway_mac": "", "ssid": "", "public_ip": "",
                "gateway": "", "network_id": ""}

    # CIDR from wlan0
    try:
        result = subprocess.run(["ip", "addr", "show", "wlan0"],
                                capture_output=True, text=True, timeout=5)
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)
        if match:
            import ipaddress
            net = ipaddress.ip_network(f"{match.group(1)}/{match.group(2)}", strict=False)
            identity["cidr"] = str(net)
    except Exception:
        pass

    # Gateway IP from default route
    try:
        result = subprocess.run(["ip", "route", "show", "default"],
                                capture_output=True, text=True, timeout=5)
        match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if match:
            identity["gateway"] = match.group(1)
    except Exception:
        pass

    # Gateway MAC from ARP
    if identity["gateway"]:
        try:
            result = subprocess.run(["ip", "neigh", "show", identity["gateway"]],
                                    capture_output=True, text=True, timeout=5)
            match = re.search(r'([0-9a-fA-F:]{17})', result.stdout)
            if match:
                identity["gateway_mac"] = match.group(1).upper()
        except Exception:
            pass

    # SSID
    try:
        result = subprocess.run(["iwgetid", "-r"],
                                capture_output=True, text=True, timeout=5)
        ssid = result.stdout.strip()
        if ssid:
            identity["ssid"] = ssid
    except Exception:
        pass

    # Public IP (best-effort, may fail on air-gapped)
    try:
        result = subprocess.run(["curl", "-s", "--connect-timeout", "3",
                                 "https://ifconfig.me"],
                                capture_output=True, text=True, timeout=5)
        ip = result.stdout.strip()
        if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
            identity["public_ip"] = ip
    except Exception:
        pass

    # Generate network_id from gateway MAC (unique per router)
    seed = identity["gateway_mac"] or identity["cidr"] or "unknown"
    identity["network_id"] = hashlib.sha256(seed.encode()).hexdigest()[:12]

    if not identity["cidr"]:
        identity["cidr"] = "auto"  # fallback

    return identity


class MissionLog:
    """Tracks findings, timeline, and mission state via SQLite."""

    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        net_info = _detect_network_identity()
        self.network_id = net_info["network_id"]
        self.network_cidr = net_info["cidr"]
        db.init_db(log_dir)
        db.upsert_network(
            network_id=self.network_id,
            cidr=net_info["cidr"],
            gateway_mac=net_info["gateway_mac"],
            ssid=net_info["ssid"],
            public_ip=net_info["public_ip"],
            gateway=net_info["gateway"],
        )

        # Migrate existing JSON files into SQLite (one-time)
        findings_path = os.path.join(log_dir, "findings.json")
        if os.path.exists(findings_path) and db.get_host_count() == 0:
            # The init_db migration handles this now
            pass

    def record(self, command: str, result: dict, reasoning: str = None):
        output_preview = (result.get("output", ""))[:500]
        status = result.get("status", "unknown")
        db.add_timeline(reasoning=reasoning, command=command,
                        status=status, output_preview=output_preview,
                        network_id=self.network_id)
        self._auto_extract(command, result)
        self._write_compat_files(command, result, reasoning)

    def record_error(self, error: Exception):
        db.add_timeline_event("error", str(error), network_id=self.network_id)
        self._append_jsonl({
            "timestamp": self._ts(), "event": "error",
            "error": str(error)
        })

    def set_finding(self, key: str, value):
        db.set_state(key, value)
        self._save_findings_json()

    def add_host(self, ip: str, ports: list = None, info: str = "",
                 mac: str = "", hostname: str = ""):
        db.upsert_host(ip=ip, ports=ports, info=info,
                       mac=mac, hostname=hostname, network_id=self.network_id)
        self._save_findings_json()

    def add_credential(self, service: str, username: str, password: str,
                       host: str = ""):
        db.add_credential(service, username, password, host,
                          network_id=self.network_id)
        self._save_findings_json()

    def add_vulnerability(self, host: str, service: str, vuln: str,
                          severity: str = "medium"):
        db.add_vulnerability(host, service, vuln, severity,
                             network_id=self.network_id)
        self._save_findings_json()

    def get_findings_summary(self) -> dict:
        return db.get_findings_summary(network_id=self.network_id)

    def finalize(self):
        db.set_state("cleanup_done", True)
        self._save_findings_json()

    def _auto_extract(self, command: str, result: dict):
        """Extract hosts, ports, MACs, hostnames from command output."""
        output = result.get("output", "")
        status = result.get("status", "")

        if "wpa_supplicant" in command and status == "success":
            self.set_finding("wifi_connected", True)

        if "nmap" in command and ("open" in output or "Host is up" in output):
            host_blocks = re.split(r'Nmap scan report for ', output)
            for block in host_blocks[1:]:
                lines = block.strip().split("\n")
                first_line = lines[0]

                # Extract hostname and IP
                # Format: "hostname (192.168.1.2)" or just "192.168.1.2"
                hostname = ""
                ip_match = re.match(r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)', first_line)
                if ip_match:
                    hostname = ip_match.group(1)
                    ip = ip_match.group(2)
                else:
                    ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', first_line)
                    if not ip_match:
                        continue
                    ip = ip_match.group(1)

                ports = []
                info_parts = []
                mac = ""
                for line in lines[1:]:
                    port_match = re.match(r'(\d+)/tcp\s+open\s+(\S+)', line)
                    if port_match:
                        ports.append(int(port_match.group(1)))
                        info_parts.append(f"{port_match.group(1)}/{port_match.group(2)}")
                    mac_match = re.match(r'MAC Address:\s+([0-9A-Fa-f:]{17})\s+\((.+?)\)', line)
                    if mac_match:
                        mac = mac_match.group(1).upper()
                        info_parts.append(f"MAC:{mac} ({mac_match.group(2)})")
                info = ", ".join(info_parts) if info_parts else ""
                self.add_host(ip, ports=ports, info=info,
                              mac=mac, hostname=hostname)

    def _save_findings_json(self):
        try:
            path = os.path.join(self.log_dir, "findings.json")
            with open(path, "w") as f:
                json.dump(db.get_findings_summary(self.network_id), f, indent=2)
        except IOError:
            pass

    def _write_compat_files(self, command, result, reasoning):
        self._append_jsonl({
            "timestamp": self._ts(),
            "reasoning": reasoning,
            "command": command,
            "status": result.get("status", "unknown"),
            "output_preview": (result.get("output", ""))[:500],
        })

    def _append_jsonl(self, entry: dict):
        try:
            path = os.path.join(self.log_dir, "timeline.jsonl")
            with open(path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except IOError:
            pass

    @staticmethod
    def _ts() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
