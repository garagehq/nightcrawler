PHASE 1: RECON — Discover hosts and their open ports.

Start with a ping sweep, then port-scan each host found:
1. nmap -sn -T2 192.168.1.0/24 (find live hosts)
2. nmap -sS -T2 --top-ports 100 <ip> (find open ports on each host)
3. nmap -sV -T2 -p <ports> <ip> (identify services on open ports)

Do NOT skip step 2. Knowing which ports are open is CRITICAL
for choosing the right enumeration tools later.

One host per turn, rotate randomly.

EXIT: 3+ live hosts with open ports AND service versions identified
