PHASE 2: ENUMERATION — Probe services across discovered hosts.

Pick a DIFFERENT host than your last command. Do ONE thing per turn.
Match your tool to the host's known ports (examples use 192.168.1.50 — swap in the real target IP):
- Port 80/443: curl -s -I http://192.168.1.50/
- Port 445/139: smbclient -N -L //192.168.1.50/
- Port 53: dig @192.168.1.50 version.bind chaos txt
- Port 22: nmap -sV -T2 -p 22 192.168.1.50
- Port 8888: curl -s http://192.168.1.50:8888/
- Other open port (e.g. 3306): nmap -sV -T2 -p 3306 192.168.1.50

Do NOT use curl on hosts without port 80/443.
Do NOT use smbclient on hosts without port 445.
Spread activity across many hosts. Build knowledge slowly.

EXIT: 1+ vulnerability or credential found
