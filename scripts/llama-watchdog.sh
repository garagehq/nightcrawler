#!/bin/bash
# llama-server watchdog with PID file enforcement
# Guarantees exactly ONE llama-server process at all times
#
# Usage:
#   bash llama-watchdog.sh start    # start server + watchdog
#   bash llama-watchdog.sh stop     # kill server + watchdog
#   bash llama-watchdog.sh status   # check status

TERMUX_HOME=/data/data/com.termux/files/home
KERNEL_DIR=${TERMUX_HOME}/llama.cpp/ggml/src/ggml-opencl/kernels
MODEL=${TERMUX_HOME}/models/LFM2.5-1.2B-Instruct-Heretic.Q8_0.gguf
PORT=8080
PIDFILE=/data/local/tmp/var/run/llama-server.pid
WATCHDOG_PIDFILE=/data/local/tmp/var/run/llama-watchdog.pid
LLAMA_LOG=/data/local/tmp/var/log/llama-server.log
WATCHDOG_LOG=/data/local/tmp/var/log/llama-watchdog.log
REFRESH_INTERVAL=18000  # 5 hours
CRASH_COOLDOWN=1200     # 20 min
KILL_WAIT=20            # seconds to wait after kill

mkdir -p /data/local/tmp/var/run /data/local/tmp/var/log

kill_server() {
    # Kill by PID file first, then by pattern as fallback
    if [ -f "$PIDFILE" ]; then
        PID=$(cat "$PIDFILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null
            sleep 5
            kill -9 "$PID" 2>/dev/null
        fi
        rm -f "$PIDFILE"
    fi
    # Fallback: kill any remaining llama-server on our port
    pkill -9 -f "llama-server.*--port ${PORT}" 2>/dev/null
    sleep ${KILL_WAIT}

    # VERIFY nothing is left
    REMAINING=$(pgrep -f "llama-server.*--port ${PORT}" 2>/dev/null | wc -l)
    if [ "$REMAINING" -gt 0 ]; then
        echo "$(date) - WARNING: $REMAINING zombie processes, force killing"
        pgrep -f "llama-server.*--port ${PORT}" 2>/dev/null | xargs kill -9 2>/dev/null
        sleep 5
    fi
}

start_server() {
    # ALWAYS kill first - never start without confirming old one is dead
    kill_server

    # Free RAM
    am kill-all 2>/dev/null
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
    sleep 2

    # Verify zero processes before starting
    COUNT=$(pgrep -f "llama-server.*--port ${PORT}" 2>/dev/null | wc -l)
    if [ "$COUNT" -gt 0 ]; then
        echo "$(date) - FATAL: still $COUNT processes after kill. Aborting start."
        return 1
    fi

    export LD_LIBRARY_PATH=${TERMUX_HOME}/../usr/lib:/vendor/lib64
    export GGML_OPENCL_PLATFORM=0
    export GGML_OPENCL_DEVICE=0
    cd ${KERNEL_DIR}

    ${TERMUX_HOME}/llama.cpp/build-fast/bin/llama-server \
        -m ${MODEL} -ngl 99 -c 8192 -t 4 -np 1 \
        --port ${PORT} --host 0.0.0.0 \
        --jinja --reasoning off --log-disable \
        > ${LLAMA_LOG} 2>&1 &
    
    SERVER_PID=$!
    echo "$SERVER_PID" > "$PIDFILE"
    echo "$(date) - Started PID $SERVER_PID"

    # Verify exactly 1 process
    sleep 2
    COUNT=$(pgrep -f "llama-server.*--port ${PORT}" 2>/dev/null | wc -l)
    if [ "$COUNT" -ne 1 ]; then
        echo "$(date) - ERROR: expected 1 process, found $COUNT. Killing all and retrying."
        kill_server
        return 1
    fi

    # Wait for healthy
    for i in $(seq 1 60); do
        sleep 5
        if wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok"; then
            echo "$(date) - Healthy after $((i*5))s (PID $SERVER_PID)"
            return 0
        fi
        # Check if our PID died
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "$(date) - PID $SERVER_PID died during startup"
            rm -f "$PIDFILE"
            return 1
        fi
    done
    echo "$(date) - Timeout waiting for healthy"
    return 1
}

run_watchdog() {
    echo "$$" > "$WATCHDOG_PIDFILE"
    echo "$(date) - Watchdog PID $$ (refresh every $((REFRESH_INTERVAL/3600))h)"

    LAST_START=$(date +%s)
    start_server

    while true; do
        sleep 30

        # Check pause file — skip all actions if offline mode or maintenance
        PAUSE_FILE="/data/local/tmp/nc-llama-pause"
        if [ -f "$PAUSE_FILE" ]; then
            # Kill server if running (free RAM for offline mode)
            if pgrep -f "llama-server.*--port ${PORT}" > /dev/null 2>&1; then
                echo "$(date) - Pause file exists — killing server for offline mode"
                kill_server
            fi
            continue
        fi

        NOW=$(date +%s)
        UPTIME=$(( NOW - LAST_START ))

        # If server isn't running (e.g. after pause removal), restart it
        if ! pgrep -f "llama-server.*--port ${PORT}" > /dev/null 2>&1; then
            echo "$(date) - Server not running — starting"
            start_server
            LAST_START=$(date +%s)
            continue
        fi

        # Scheduled refresh
        if [ ${UPTIME} -ge ${REFRESH_INTERVAL} ]; then
            echo "$(date) - Scheduled refresh ($((UPTIME/3600))h uptime)"
            start_server
            LAST_START=$(date +%s)
            continue
        fi

        # Health check
        if wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok"; then
            continue
        fi
        sleep 5
        if wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok"; then
            continue
        fi

        # Crashed
        echo "$(date) - CRASHED (uptime $((UPTIME/60))m)"
        start_server
        LAST_START=$(date +%s)
        if [ $? -ne 0 ]; then
            echo "$(date) - Restart failed, cooldown ${CRASH_COOLDOWN}s"
            sleep ${CRASH_COOLDOWN}
        fi
    done
}

case "${1:-start}" in
    start)
        # Kill any existing watchdog first
        if [ -f "$WATCHDOG_PIDFILE" ]; then
            OLD_WD=$(cat "$WATCHDOG_PIDFILE")
            kill "$OLD_WD" 2>/dev/null
            kill -9 "$OLD_WD" 2>/dev/null
            rm -f "$WATCHDOG_PIDFILE"
        fi
        run_watchdog >> "$WATCHDOG_LOG" 2>&1 &
        echo "Watchdog started (PID $!)"
        ;;
    stop)
        if [ -f "$WATCHDOG_PIDFILE" ]; then
            kill -9 $(cat "$WATCHDOG_PIDFILE") 2>/dev/null
            rm -f "$WATCHDOG_PIDFILE"
        fi
        kill_server
        echo "Stopped"
        ;;
    status)
        echo "=== Watchdog ==="
        if [ -f "$WATCHDOG_PIDFILE" ] && kill -0 $(cat "$WATCHDOG_PIDFILE") 2>/dev/null; then
            echo "Running (PID $(cat $WATCHDOG_PIDFILE))"
        else
            echo "Not running"
        fi
        echo "=== Server ==="
        if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
            echo "Running (PID $(cat $PIDFILE))"
            wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null
        else
            echo "Not running"
        fi
        echo "=== Process count ==="
        echo "$(pgrep -f 'llama-server.*--port 8080' 2>/dev/null | wc -l) llama-server processes"
        ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        ;;
esac
