PHASE 2: ENUMERATION — Probe services across discovered hosts.

Pick a DIFFERENT host than your last command. Do ONE thing per turn.
Match your tool to the host's known ports:
- Port 80/443: curl -s -I http://<ip>/
- Port 445/139: smbclient -N -L //<ip>/
- Port 53: dig @<ip> version.bind chaos txt
- Port 22: nmap -sV -T2 -p 22 <ip>
- Port 8888: curl -s http://<ip>:8888/
- Unknown ports: nmap -sV -T2 -p <port> <ip>

Do NOT use curl on hosts without port 80/443.
Do NOT use smbclient on hosts without port 445.
Spread activity across many hosts. Build knowledge slowly.

EXIT: 1+ vulnerability or credential found
