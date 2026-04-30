#!/bin/bash
# Nightcrawler WebUI daemon
# Runs as a proper background process that survives SSH disconnects
#
# Usage:
#   /root/nightcrawler/scripts/webui-daemon.sh start
#   /root/nightcrawler/scripts/webui-daemon.sh stop
#   /root/nightcrawler/scripts/webui-daemon.sh status

PIDFILE="/var/run/nightcrawler-webui.pid"
LOGFILE="/var/log/nightcrawler-webui.log"
WORKDIR="/root/nightcrawler"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Verify that the PID in $PIDFILE belongs to our webui process.
# Just checking `kill -0` isn't enough — PIDs get reused after reboots.
is_webui_alive() {
    [ -f "$PIDFILE" ] || return 1
    local pid=$(cat "$PIDFILE" 2>/dev/null)
    [ -n "$pid" ] || return 1
    [ -r "/proc/$pid/cmdline" ] || return 1
    grep -q "webui.server" "/proc/$pid/cmdline" 2>/dev/null
}

start() {
    if is_webui_alive; then
        echo "WebUI already running (PID $(cat $PIDFILE))"
        return 0
    fi

    # Stale PID file (process gone or PID reused by something else) — clean up.
    if [ -f "$PIDFILE" ]; then
        echo "Removing stale PID file (PID $(cat $PIDFILE) is not our webui)"
        rm -f "$PIDFILE"
    fi

    echo "Starting Nightcrawler WebUI..."
    cd "$WORKDIR"

    # Use setsid + nohup to fully detach from terminal
    setsid nohup python3 -c "
from webui.server import run_webui
import time, os, signal

# Write PID
with open('$PIDFILE', 'w') as f:
    f.write(str(os.getpid()))

def cleanup(sig, frame):
    os.remove('$PIDFILE') if os.path.exists('$PIDFILE') else None
    exit(0)
signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)

t = run_webui()
while True:
    time.sleep(3600)
" > "$LOGFILE" 2>&1 &

    # Wait for startup — verify both the PID is our webui AND port 8888 is bound.
    for i in 1 2 3 4 5; do
        sleep 1
        if is_webui_alive && (ss -tln 2>/dev/null | grep -q ':8888 '); then
            echo "WebUI started (PID $(cat $PIDFILE))"
            head -3 "$LOGFILE"
            return 0
        fi
    done

    echo "FAILED to start (no listener on :8888 after 5s). Check $LOGFILE"
    tail -20 "$LOGFILE"
    return 1
}

stop() {
    if is_webui_alive; then
        local pid=$(cat "$PIDFILE")
        echo "Stopping WebUI (PID $pid)..."
        kill "$pid"
        sleep 2
        kill -9 "$pid" 2>/dev/null
        rm -f "$PIDFILE"
        echo "Stopped"
    elif [ -f "$PIDFILE" ]; then
        echo "Stale PID file (process not our webui), cleaning up"
        rm -f "$PIDFILE"
        # Also kill any orphaned webui processes we can find
        pkill -f "webui.server" 2>/dev/null && echo "Killed orphaned webui process(es)"
    else
        echo "Not running"
        # Best-effort cleanup of any orphaned webui processes
        pkill -f "webui.server" 2>/dev/null
    fi
}

status() {
    if is_webui_alive; then
        echo "WebUI running (PID $(cat $PIDFILE))"
        ss -tln 2>/dev/null | grep ':8888 ' || netstat -tln 2>/dev/null | grep ':8888 '
    else
        if [ -f "$PIDFILE" ]; then
            echo "WebUI not running (stale PID file at $PIDFILE — run 'start' to clear)"
        else
            echo "WebUI not running"
        fi
        return 1
    fi
}

case "$1" in
    start)  start ;;
    stop)   stop ;;
    status) status ;;
    restart) stop; sleep 1; start ;;
    *)
        echo "Usage: $0 {start|stop|status|restart}"
        exit 1
        ;;
esac
