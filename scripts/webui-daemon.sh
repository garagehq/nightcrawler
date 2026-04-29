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

start() {
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "WebUI already running (PID $(cat $PIDFILE))"
        return 0
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

    sleep 2
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "WebUI started (PID $(cat $PIDFILE))"
        head -3 "$LOGFILE"
    else
        echo "FAILED to start. Check $LOGFILE"
        cat "$LOGFILE"
    fi
}

stop() {
    if [ -f "$PIDFILE" ]; then
        PID=$(cat "$PIDFILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Stopping WebUI (PID $PID)..."
            kill "$PID"
            sleep 2
            kill -9 "$PID" 2>/dev/null
            rm -f "$PIDFILE"
            echo "Stopped"
        else
            echo "PID $PID not running, cleaning up"
            rm -f "$PIDFILE"
        fi
    else
        echo "No PID file found"
        # Kill by name as fallback
        pkill -f "webui.server" 2>/dev/null
    fi
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "WebUI running (PID $(cat $PIDFILE))"
        netstat -tlnp 2>/dev/null | grep 8888 || ss -tlnp | grep 8888 2>/dev/null
    else
        echo "WebUI not running"
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
