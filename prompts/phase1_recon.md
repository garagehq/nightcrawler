PHASE 1: RECON — Discover hosts and their open ports. One host per turn.

Choose your command by what you already know (swap in the real target IP):
- Ports unknown on a host -> nmap -sS -T2 --top-ports 100 192.168.1.80
- Ports known (e.g. 22,80) -> nmap -sV -T2 -p 22,80 192.168.1.80
- Look for new live hosts -> nmap -sn -T2 192.168.1.0/24

Knowing which ports are open is CRITICAL for choosing the right
enumeration tools later. Rotate hosts randomly, never repeat the last IP.

EXIT: 3+ live hosts with open ports AND service versions identified
