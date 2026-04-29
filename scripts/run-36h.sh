#!/bin/bash
# Nightcrawler — 36-hour sustained autonomous run
# Starts all services with crash-restart loops in tmux
set -e

NC_HOME="/root/nightcrawler"
SESSION="nightcrawler"

G="\033[1;32m"; R="\033[1;31m"; Y="\033[1;33m"; N="\033[0m"

echo -e "${G}[■■■■■■■■■■] NIGHTCRAWLER v0.1.0 — 36h AUTONOMOUS RUN${N}"

# ── Pre-flight ──────────────────────────────────────
echo -ne "[PRE] llama-server health... "
for i in $(seq 1 60); do
    if curl -s http://127.0.0.1:8080/health 2>/dev/null | grep -q "ok"; then
        echo -e "${G}OK${N}"
        break
    fi
    [ "$i" -eq 60 ] && { echo -e "${R}FAIL — start llama-server first${N}"; exit 1; }
    sleep 5
done

# ── Wake lock ───────────────────────────────────────
echo "nightcrawler" > /sys/power/wake_lock 2>/dev/null || true
dumpsys deviceidle disable > /dev/null 2>&1 || true

# ── Kill existing session ───────────────────────────
tmux kill-session -t "$SESSION" 2>/dev/null || true
sleep 1

# ── Create tmux session ─────────────────────────────
tmux new-session -d -s "$SESSION" -n executor

# Window 0: Real command executor
tmux send-keys -t "$SESSION:executor" "cd $NC_HOME; while true; do echo \"[\$(date)] Starting executor...\"; python3 kali_executor.py --port 5000 --timeout 300; echo \"[\$(date)] Executor died, restarting in 5s\"; sleep 5; done" Enter

sleep 2

# Window 1: Scope proxy
tmux new-window -t "$SESSION" -n proxy
tmux send-keys -t "$SESSION:proxy" "cd $NC_HOME; while true; do echo \"[\$(date)] Starting proxy...\"; python3 scope_proxy.py --config config.yaml --port 8800 --upstream http://127.0.0.1:5000; echo \"[\$(date)] Proxy died, restarting in 5s\"; sleep 5; done" Enter

sleep 2

# Window 2: Web UI
tmux new-window -t "$SESSION" -n webui
tmux send-keys -t "$SESSION:webui" "cd $NC_HOME; bash scripts/webui-daemon.sh restart; tail -f /var/log/nightcrawler-webui.log 2>/dev/null || echo 'WebUI started'" Enter

sleep 2

# Window 3: Agent (with backoff on rapid crashes)
tmux new-window -t "$SESSION" -n agent
tmux send-keys -t "$SESSION:agent" "cd $NC_HOME; CRASH_COUNT=0; COOLDOWN=10; while true; do echo \"[\$(date)] Starting agent (crash #\$CRASH_COUNT)...\"; python3 main.py; EXIT=\$?; CRASH_COUNT=\$((CRASH_COUNT+1)); if [ \$CRASH_COUNT -ge 5 ]; then echo \"[\$(date)] 5 crashes, cooling down 5min\"; sleep 300; CRASH_COUNT=0; else sleep \$COOLDOWN; fi; done" Enter

# Window 4: Agent watchdog (restarts agent if hung >40min)
tmux new-window -t "$SESSION" -n watchdog
tmux send-keys -t "$SESSION:watchdog" "cd $NC_HOME; bash scripts/agent-watchdog.sh" Enter

# Window 5: Log monitor
tmux new-window -t "$SESSION" -n logs
tmux send-keys -t "$SESSION:logs" "cd $NC_HOME; tail -f logs/commands.jsonl logs/timeline.jsonl 2>/dev/null || echo 'Waiting for logs...'" Enter

# Window 5: Shell
tmux new-window -t "$SESSION" -n shell
tmux send-keys -t "$SESSION:shell" "cd $NC_HOME" Enter

# ── Select agent window ─────────────────────────────
tmux select-window -t "$SESSION:agent"

echo ""
echo -e "${G}╔═══════════════════════════════════════════════════════╗${N}"
echo -e "${G}║  NIGHTCRAWLER 36h RUN STARTED                        ║${N}"
echo -e "${G}║  tmux attach -t nightcrawler                         ║${N}"
echo -e "${G}╚═══════════════════════════════════════════════════════╝${N}"
echo ""
echo "  Windows: executor | proxy | webui | agent | logs | shell"
echo ""

# Attach
tmux attach-session -t "$SESSION"
