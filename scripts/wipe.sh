#!/bin/bash
# Nightcrawler — Secure wipe all mission data
NC_HOME="${NC_HOME:-/opt/nightcrawler}"
R="\033[1;31m"; G="\033[1;32m"; N="\033[0m"

echo -e "${R}╔═══════════════════════════════════════╗${N}"
echo -e "${R}║  SECURE WIPE INITIATED               ║${N}"
echo -e "${R}╚═══════════════════════════════════════╝${N}"

bash "$NC_HOME/scripts/stop.sh"

for pass in 1 2 3; do
    echo -ne "[WIPE] Overwriting logs (pass $pass/3)... "
    if [ "$pass" -eq 3 ]; then
        find "$NC_HOME/logs" -type f -exec shred -n1 -z -u {} \; 2>/dev/null
    else
        find "$NC_HOME/logs" -type f -exec shred -n1 -z {} \; 2>/dev/null
    fi
    echo -e "${G}OK${N}"
done

find /tmp -name "*.cap" -o -name "*.hccapx" -o -name "*.pcap" 2>/dev/null | xargs rm -f 2>/dev/null
rm -rf /tmp/nc-* /tmp/aircrack-* /tmp/capture-* /tmp/wpa.conf 2>/dev/null
mkdir -p "$NC_HOME/logs"
fstrim / 2>/dev/null

echo -e "${G}[WIPE] All mission data destroyed.${N}"
