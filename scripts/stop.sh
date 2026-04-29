#!/bin/bash
# Nightcrawler — Graceful shutdown
G="\033[1;32m"; R="\033[0m"

echo -e "${G}[STOP] Graceful shutdown...${R}"

for pidfile in /tmp/nc-agent.pid /tmp/proxy.pid /tmp/kali-mcp.pid /tmp/llama.pid; do
    name=$(basename "$pidfile" .pid)
    echo -ne "[STOP] Stopping $name... "
    if [ -f "$pidfile" ]; then
        kill $(cat "$pidfile") 2>/dev/null && rm -f "$pidfile"
        echo -e "${G}OK${R}"
    else
        echo -e "not running"
    fi
done

echo "nightcrawler" > /sys/power/wake_unlock 2>/dev/null
dumpsys deviceidle enable > /dev/null 2>&1
tmux kill-session -t nightcrawler 2>/dev/null

echo -e "${G}[STOP] Shutdown complete.${R}"
