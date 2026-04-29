#!/bin/bash
# Nightcrawler health check — run via cron every 10 minutes
# Checks all services, auto-recovers, logs to health.log + finetuning-logs.md

NC_HOME="/root/nightcrawler"
LOG_DIR="$NC_HOME/logs"
HEALTH_LOG="$LOG_DIR/health.log"
FINETUNE_LOG="$NC_HOME/nightcrawler-finetuning-logs.md"

mkdir -p "$LOG_DIR"

TS=$(date '+%Y-%m-%d %H:%M:%S')
echo "=== Health Check: $TS ===" >> "$HEALTH_LOG"

SERVICES_OK=0
SERVICES_FAIL=0
NOTES=""

# ── 0. Kill duplicate processes (memory leak prevention) ──
# Uses [b]racket trick in grep to avoid matching the grep itself
dedup_process() {
    local pattern="$1"
    local label="$2"
    local PIDS=$(ps aux | grep "$pattern" | grep -v grep | awk '{print $2}' | sort -n)
    local COUNT=$(echo "$PIDS" | wc -w)
    if [ "$COUNT" -gt 1 ]; then
        local KEEP=$(echo "$PIDS" | tail -1)
        echo "  [WARN] ${COUNT} ${label} processes — keeping PID $KEEP" >> "$HEALTH_LOG"
        for pid in $PIDS; do
            [ "$pid" != "$KEEP" ] && kill -9 "$pid" 2>/dev/null
        done
        NOTES="${NOTES}killed-dup-${label} "
    fi
}
dedup_process "python3 main.py" "agent"
dedup_process "kali_server.py" "mcp"
dedup_process "scope_proxy.py" "proxy"

# Drop caches periodically
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null

# ── 1. llama-server ──────────────────────────────────
LLAMA_COUNT=$(pgrep -c llama-server 2>/dev/null || echo 0)
if [ "$LLAMA_COUNT" -gt 1 ]; then
    echo "  [CRITICAL] $LLAMA_COUNT llama-server processes! OOM risk!" >> "$HEALTH_LOG"
    NOTES="${NOTES}DUAL-LLAMA-${LLAMA_COUNT} "
    SERVICES_FAIL=$((SERVICES_FAIL+1))
elif curl -s http://127.0.0.1:8080/health 2>/dev/null | grep -q "ok"; then
    echo "  [OK] llama-server :8080 (${LLAMA_COUNT} proc)" >> "$HEALTH_LOG"
    SERVICES_OK=$((SERVICES_OK+1))
else
    echo "  [FAIL] llama-server :8080" >> "$HEALTH_LOG"
    SERVICES_FAIL=$((SERVICES_FAIL+1))
    NOTES="${NOTES}llm-down "
fi

# ── 2. kali-server-mcp (:5000) ───────────────────────
if curl -s http://127.0.0.1:5000/health 2>/dev/null | grep -qE "ok|healthy"; then
    echo "  [OK] kali-server-mcp :5000" >> "$HEALTH_LOG"
    SERVICES_OK=$((SERVICES_OK+1))
else
    echo "  [FAIL] kali-server-mcp :5000" >> "$HEALTH_LOG"
    SERVICES_FAIL=$((SERVICES_FAIL+1))
    NOTES="${NOTES}mcp-down "
fi

# ── 3. Scope proxy ───────────────────────────────────
if curl -s http://127.0.0.1:8800/health 2>/dev/null | grep -q "ok"; then
    echo "  [OK] proxy :8800" >> "$HEALTH_LOG"
    SERVICES_OK=$((SERVICES_OK+1))
else
    echo "  [FAIL] proxy :8800" >> "$HEALTH_LOG"
    SERVICES_FAIL=$((SERVICES_FAIL+1))
    NOTES="${NOTES}proxy-down "
fi

# ── 4. WebUI ─────────────────────────────────────────
TS_IP=$(ip -4 addr show tailscale0 2>/dev/null | grep -oP 'inet \K[\d.]+' || echo "127.0.0.1")
if curl -sk "https://${TS_IP}:8888/api/state" 2>/dev/null | grep -q "phase"; then
    echo "  [OK] webui :8888" >> "$HEALTH_LOG"
    SERVICES_OK=$((SERVICES_OK+1))
else
    echo "  [FAIL] webui :8888 — restarting" >> "$HEALTH_LOG"
    SERVICES_FAIL=$((SERVICES_FAIL+1))
    NOTES="${NOTES}webui-down "
    cd "$NC_HOME" && bash scripts/webui-daemon.sh restart >> "$HEALTH_LOG" 2>&1
fi

# ── 4b. llama-server memory tracking ─────────────────
LLAMA_PID=$(pgrep llama-server 2>/dev/null | head -1)
if [ -n "$LLAMA_PID" ]; then
    LLAMA_RSS=$(ps -o rss= -p "$LLAMA_PID" 2>/dev/null | tr -d ' ')
    LLAMA_RSS_MB=$((LLAMA_RSS / 1024))
    echo "  [INFO] llama-server RSS: ${LLAMA_RSS_MB}MB" >> "$HEALTH_LOG"
    if [ "$LLAMA_RSS_MB" -gt 5000 ]; then
        echo "  [WARN] llama-server growing: ${LLAMA_RSS_MB}MB (>5GB)" >> "$HEALTH_LOG"
        NOTES="${NOTES}llama-${LLAMA_RSS_MB}M "
    fi
fi

# ── 5. Agent process ─────────────────────────────────
if pgrep -f "python3 main.py" > /dev/null 2>&1; then
    echo "  [OK] agent process" >> "$HEALTH_LOG"
    SERVICES_OK=$((SERVICES_OK+1))
else
    echo "  [FAIL] agent process not running" >> "$HEALTH_LOG"
    SERVICES_FAIL=$((SERVICES_FAIL+1))
    NOTES="${NOTES}agent-down "
fi

# ── 5b. Agent memory leak detection ──────────────────
AGENT_PID=$(pgrep -f "python3 main.py" 2>/dev/null | head -1)
AGENT_RSS=0
if [ -n "$AGENT_PID" ]; then
    AGENT_RSS=$(ps -o rss= -p "$AGENT_PID" 2>/dev/null | tr -d ' ')
    AGENT_RSS_MB=$((AGENT_RSS / 1024))
    echo "  [INFO] agent RSS: ${AGENT_RSS_MB}MB (PID $AGENT_PID)" >> "$HEALTH_LOG"
    if [ "$AGENT_RSS_MB" -gt 200 ]; then
        echo "  [WARN] agent memory leak: ${AGENT_RSS_MB}MB > 200MB" >> "$HEALTH_LOG"
        NOTES="${NOTES}memleak-${AGENT_RSS_MB}M "
    fi
fi

# ── 6. Agent progress (stall detection + auto-restart) ──
TIMELINE="$LOG_DIR/timeline.jsonl"
if [ -f "$TIMELINE" ]; then
    LAST_MOD=$(stat -c %Y "$TIMELINE" 2>/dev/null || echo 0)
    NOW=$(date +%s)
    AGE=$(( (NOW - LAST_MOD) / 60 ))
    if [ "$AGE" -gt 30 ]; then
        echo "  [WARN] timeline stale ${AGE}m — auto-restarting agent" >> "$HEALTH_LOG"
        NOTES="${NOTES}auto-restart-stale-${AGE}m "
        # Auto-restart: kill agent, clear timeline, restart
        pkill -9 -f "python3 main.py" 2>/dev/null
        sleep 2
        cd "$NC_HOME"
        : > "$TIMELINE"  # clear stale timeline
        nohup python3 main.py >> /tmp/nc-agent.log 2>&1 &
        echo "  [INFO] agent restarted (PID $!)" >> "$HEALTH_LOG"
    elif [ "$AGE" -gt 15 ]; then
        echo "  [WARN] timeline.jsonl stale (${AGE}m old)" >> "$HEALTH_LOG"
        NOTES="${NOTES}stale-${AGE}m "
    fi
    ITER_COUNT=$(wc -l < "$TIMELINE" 2>/dev/null || echo 0)
else
    ITER_COUNT=0
fi

# ── 7. Findings ──────────────────────────────────────
FINDINGS="$LOG_DIR/findings.json"
HOSTS=0; CREDS=0; VULNS=0; PHASE="?"
if [ -f "$FINDINGS" ]; then
    HOSTS=$(python3 -c "import json; d=json.load(open('$FINDINGS')); print(d.get('live_hosts',0))" 2>/dev/null || echo 0)
    CREDS=$(python3 -c "import json; d=json.load(open('$FINDINGS')); print(d.get('credentials',0))" 2>/dev/null || echo 0)
    VULNS=$(python3 -c "import json; d=json.load(open('$FINDINGS')); print(d.get('vulnerabilities',0))" 2>/dev/null || echo 0)
fi

# Get phase from webui state
PHASE=$(curl -sk "https://${TS_IP}:8888/api/state" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('phase','?'))" 2>/dev/null || echo "?")

# ── 8. Disk + Memory ─────────────────────────────────
DISK_PCT=$(df / | awk 'NR==2{gsub(/%/,""); print $5}')
MEM_FREE=$(free -m | awk '/Mem:/{print $4}')
if [ "$DISK_PCT" -gt 90 ]; then
    NOTES="${NOTES}disk-${DISK_PCT}% "
fi
if [ "$MEM_FREE" -lt 500 ]; then
    NOTES="${NOTES}lowmem-${MEM_FREE}M "
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
fi

# ── 9. Garbage rate ──────────────────────────────────
CMDS_LOG="$LOG_DIR/commands.jsonl"
TOTAL_CMDS=0
if [ -f "$CMDS_LOG" ]; then
    TOTAL_CMDS=$(wc -l < "$CMDS_LOG" 2>/dev/null || echo 0)
fi

# ── Summary line ─────────────────────────────────────
STATUS="${SERVICES_OK}ok/${SERVICES_FAIL}fail"
[ -z "$NOTES" ] && NOTES="nominal"

echo "  Summary: $STATUS | iter=$ITER_COUNT hosts=$HOSTS creds=$CREDS vulns=$VULNS phase=$PHASE cmds=$TOTAL_CMDS disk=${DISK_PCT}% mem=${MEM_FREE}M" >> "$HEALTH_LOG"
echo "" >> "$HEALTH_LOG"

# ── Append to finetuning log ─────────────────────────
echo "| $TS | $ITER_COUNT | $PHASE | $HOSTS | $CREDS | $VULNS | $TOTAL_CMDS | $STATUS | $NOTES |" >> "$FINETUNE_LOG"
