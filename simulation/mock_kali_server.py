"""Mock kali-server-mcp for dry-run testing."""

import json
import re
from flask import Flask, request, jsonify


app = Flask(__name__)


# Canned responses for recognized command patterns
MOCK_RESPONSES = [
    (r'^nmap\s', {
        "status": "success",
        "output": (
            "Starting Nmap 7.94SVN\n"
            "Nmap scan report for 192.168.1.10\n"
            "Host is up (0.0031s latency).\n"
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh\n"
            "80/tcp   open  http\n"
            "445/tcp  open  microsoft-ds\n"
            "3389/tcp open  ms-wbt-server\n\n"
            "Nmap scan report for 192.168.1.15\n"
            "Host is up (0.0042s latency).\n"
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh\n"
            "80/tcp   open  http\n"
            "8080/tcp open  http-proxy\n\n"
            "Nmap scan report for 192.168.1.20\n"
            "Host is up (0.0055s latency).\n"
            "PORT     STATE SERVICE\n"
            "9100/tcp open  jetdirect\n"
            "631/tcp  open  ipp\n\n"
            "Nmap scan report for 192.168.1.25\n"
            "Host is up (0.0028s latency).\n"
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh\n"
            "3306/tcp open  mysql\n\n"
            "Nmap done: 256 IP addresses (4 hosts up)"
        ),
        "return_code": 0,
    }),
    (r'^nxc\s+smb', {
        "status": "success",
        "output": (
            "SMB  192.168.1.10  445  DC01  [*] Windows Server 2019 Build 17763 x64\n"
            "SMB  192.168.1.10  445  DC01  [+] Enumerated shares\n"
            "SMB  192.168.1.10  445  DC01  Share       Permissions  Remark\n"
            "SMB  192.168.1.10  445  DC01  -----       -----------  ------\n"
            "SMB  192.168.1.10  445  DC01  ADMIN$                   Remote Admin\n"
            "SMB  192.168.1.10  445  DC01  C$                       Default share\n"
            "SMB  192.168.1.10  445  DC01  IPC$        READ         Remote IPC\n"
            "SMB  192.168.1.10  445  DC01  NETLOGON    READ         Logon scripts\n"
            "SMB  192.168.1.10  445  DC01  Public      READ,WRITE   Public share\n"
            "SMB  192.168.1.10  445  DC01  SYSVOL      READ         Logon scripts"
        ),
        "return_code": 0,
    }),
    (r'^gobuster', {
        "status": "success",
        "output": (
            "===============================================================\n"
            "Gobuster v3.6\n"
            "===============================================================\n"
            "/admin                (Status: 302) [Size: 0]\n"
            "/api                  (Status: 200) [Size: 1247]\n"
            "/login                (Status: 200) [Size: 3891]\n"
            "/uploads              (Status: 403) [Size: 278]\n"
            "/config               (Status: 403) [Size: 278]\n"
            "==============================================================="
        ),
        "return_code": 0,
    }),
    (r'^curl\s', {
        "status": "success",
        "output": "<html><head><title>Test Server</title></head><body>OK</body></html>",
        "return_code": 0,
    }),
    (r'^(id|whoami)', {
        "status": "success",
        "output": "root",
        "return_code": 0,
    }),
    (r'^ip\s+(addr|link)', {
        "status": "success",
        "output": (
            "2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    inet 192.168.1.53/24 brd 192.168.1.255 scope global wlan0"
        ),
        "return_code": 0,
    }),
    (r'^airmon-ng', {
        "status": "success",
        "output": (
            "PHY     Interface       Driver          Chipset\n"
            "phy1    wlan1           88XXau          Realtek RTL8812AU\n\n"
            "(monitor mode enabled on wlan1mon)"
        ),
        "return_code": 0,
    }),
    (r'^airodump-ng', {
        "status": "success",
        "output": (
            " BSSID              PWR  Beacons  #Data  CH  ENC   ESSID\n"
            " AA:BB:CC:11:22:33  -42  145      89     6   WPA2  TargetNet\n"
            " DD:EE:FF:44:55:66  -67  98       12     11  WPA2  GuestWiFi\n"
            " 11:22:33:44:55:66  -78  45       3      1   WPA2  CorpSecure"
        ),
        "return_code": 0,
    }),
    (r'^aircrack-ng', {
        "status": "success",
        "output": "KEY FOUND! [ password123 ]",
        "return_code": 0,
    }),
    (r'^wpa_supplicant', {
        "status": "success",
        "output": "Successfully initialized wpa_supplicant",
        "return_code": 0,
    }),
    (r'^dhclient', {
        "status": "success",
        "output": "DHCPACK from 192.168.1.1 (bound to 192.168.1.53)",
        "return_code": 0,
    }),
    (r'^enum4linux', {
        "status": "success",
        "output": (
            "=========================================\n"
            "|    Target Information    |\n"
            "=========================================\n"
            "Target ........... 192.168.1.10\n"
            "Username ......... ''\n"
            "Password ......... ''\n\n"
            "Domain Name: TESTLAB\n"
            "Domain SID: S-1-5-21-1234567890-1234567890-1234567890\n"
            "Users found: Administrator, svc_backup, jdoe, admin"
        ),
        "return_code": 0,
    }),
    (r'^hydra\s', {
        "status": "success",
        "output": (
            "[22][ssh] host: 192.168.1.15  login: admin  password: admin123\n"
            "1 of 1 target completed, 1 valid password found"
        ),
        "return_code": 0,
    }),
]


class MockKaliServer:
    """Simulates kali-server-mcp responses for dry-run testing."""

    def __init__(self, scenario_file: str = None):
        self.scenario = None
        if scenario_file:
            try:
                with open(scenario_file) as f:
                    self.scenario = json.load(f)
            except (IOError, json.JSONDecodeError):
                pass

    def execute(self, command: str) -> dict:
        """Return mock response for a command."""
        # Check scenario overrides first
        if self.scenario:
            for entry in self.scenario.get("responses", []):
                if re.search(entry["pattern"], command):
                    return entry["response"]

        # Fall back to built-in mocks
        for pattern, response in MOCK_RESPONSES:
            if re.search(pattern, command):
                return dict(response)

        # Generic fallback
        return {
            "status": "success",
            "output": f"[MOCK] Executed: {command}",
            "return_code": 0,
        }


@app.route("/execute", methods=["POST"])
def handle_execute():
    data = request.json or {}
    command = data.get("command", "")
    mock = MockKaliServer()
    result = mock.execute(command)
    return jsonify(result)


@app.route("/health", methods=["GET"])
def handle_health():
    return jsonify({"status": "ok", "service": "mock-kali-server"})


def run_mock_server(port: int = 5000):
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    run_mock_server(port)
