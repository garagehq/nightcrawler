#!/bin/bash
# Agent Watchdog — restarts the Nightcrawler agent if it hangs
#
# Checks if the agent log file has been modified recently.
# If no update in HANG_TIMEOUT seconds, kills and restarts the agent.
# Runs alongside the agent, not inside it.
#
# Usage: bash scripts/agent-watchdog.sh &

HANG_TIMEOUT=2400  # 40 minutes
CHECK_INTERVAL=60  # check every 60s
AGENT_LOG="/tmp/nc-agent.log"
AGENT_CMD="python3 main.py"
WATCHDOG_LOG="/tmp/nc-agent-watchdog.log"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S %Z') - $1" >> "$WATCHDOG_LOG"
}

log "Agent watchdog started (hang timeout=${HANG_TIMEOUT}s / $(( HANG_TIMEOUT / 60 ))min)"

while true; do
    sleep "$CHECK_INTERVAL"

    # Check pause file — skip restart if delete/maintenance in progress
    if [ -f /tmp/nc-agent-pause ]; then
        log "Pause file exists — skipping (delete/maintenance in progress)"
        continue
    fi

    # Check if agent is running at all
    AGENT_PID=$(pgrep -f "$AGENT_CMD" | head -1)
    if [ -z "$AGENT_PID" ]; then
        log "Agent not running — starting fresh"
        cd "$PROJECT_DIR"
        $AGENT_CMD > "$AGENT_LOG" 2>&1 &
        NEW_PID=$!
        log "Agent started (PID $NEW_PID)"
        curl -sk -X POST https://127.0.0.1:8888/api/feed \
            -H "Content-Type: application/json" \
            -d '{"type":"system","content":"[WATCHDOG] Agent restarted (not running)"}' \
            2>/dev/null || true
        sleep 10
        continue
    fi

    # Check log freshness
    if [ ! -f "$AGENT_LOG" ]; then
        continue
    fi

    LOG_AGE=$(( $(date +%s) - $(stat -c %Y "$AGENT_LOG" 2>/dev/null || echo 0) ))

    if [ "$LOG_AGE" -ge "$HANG_TIMEOUT" ]; then
        log "HANG DETECTED: log stale for ${LOG_AGE}s (PID $AGENT_PID) — restarting"
        kill -9 "$AGENT_PID" 2>/dev/null
        sleep 3

        # Verify kill
        if kill -0 "$AGENT_PID" 2>/dev/null; then
            log "WARN: agent still alive after SIGKILL"
            kill -9 "$AGENT_PID" 2>/dev/null
            sleep 2
        fi

        cd "$PROJECT_DIR"
        $AGENT_CMD > "$AGENT_LOG" 2>&1 &
        NEW_PID=$!
        log "Agent restarted (PID $NEW_PID)"
        curl -sk -X POST https://127.0.0.1:8888/api/feed \
            -H "Content-Type: application/json" \
            -d "{\"type\":\"system\",\"content\":\"[WATCHDOG] Agent restarted (hung ${LOG_AGE}s)\"}" \
            2>/dev/null || true
    fi
done
