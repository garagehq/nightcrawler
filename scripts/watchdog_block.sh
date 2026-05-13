# SSH Firewall — restrict SSH ports to localhost + Tailscale only
# Re-applies every 60s to survive Android firewall resets and network changes
(
    sleep 5
    while true; do
        # Clear any stale rules for our ports first
        iptables -D INPUT -p tcp --dport 9022 -j DROP 2>/dev/null
        iptables -D INPUT -p tcp --dport 8022 -j DROP 2>/dev/null

        # Insert ACCEPT rules at top (before Android's chains)
        # Check if already present to avoid duplicates
        if ! iptables -C INPUT -i lo -p tcp --dport 9022 -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -i lo -p tcp --dport 9022 -j ACCEPT 2>/dev/null
        fi
        if ! iptables -C INPUT -i lo -p tcp --dport 8022 -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -i lo -p tcp --dport 8022 -j ACCEPT 2>/dev/null
        fi
        if ! iptables -C INPUT -s 100.0.0.0/8 -p tcp --dport 9022 -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -s 100.0.0.0/8 -p tcp --dport 9022 -j ACCEPT 2>/dev/null
        fi
        if ! iptables -C INPUT -s 100.0.0.0/8 -p tcp --dport 8022 -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -s 100.0.0.0/8 -p tcp --dport 8022 -j ACCEPT 2>/dev/null
        fi

        # Append DROP rules at bottom
        iptables -A INPUT -p tcp --dport 9022 -j DROP 2>/dev/null
        iptables -A INPUT -p tcp --dport 8022 -j DROP 2>/dev/null

        sleep 60
    done
) &
echo "$(date) - SSH firewall daemon started (re-applies every 60s)"

# Early offline detection — 2 min after boot
# Creates pause files BEFORE llama-server or services try to start
# This prevents the race condition where llama starts then gets killed
(
    sleep 120
    LOG=/data/local/tmp/var/log/nightcrawler-autostart.log
    CHROOT=/data/local/nhsystem/kalifs
    USB_WIFI=$(lsusb 2>/dev/null | grep -E "7392:d811|7392:b811|7392:7811|148f:3572")
    WLAN0_IP=$(ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}')
    if [ -n "$USB_WIFI" ]; then
        echo "$(date) - Early detect: USB WiFi adapter found: $USB_WIFI" >> $LOG
        echo "offline" > /data/local/tmp/nc-llama-pause
        /system/bin/chroot $CHROOT /bin/bash -c 'echo "offline-mode" > /tmp/nc-agent-pause' 2>/dev/null
        echo "$(date) - Early detect: pause files created (llama+agent)" >> $LOG
    elif [ -z "$WLAN0_IP" ]; then
        echo "$(date) - Early detect: no WiFi connected (wlan0 has no IP)" >> $LOG
        echo "no-wifi" > /data/local/tmp/nc-llama-pause
        /system/bin/chroot $CHROOT /bin/bash -c 'echo "no-wifi" > /tmp/nc-agent-pause' 2>/dev/null
        echo "$(date) - Early detect: pause files created (no network to pentest)" >> $LOG
    else
        # Online mode — remove any stale pause files from previous boot
        rm -f /data/local/tmp/nc-llama-pause
        /system/bin/chroot $CHROOT /bin/bash -c 'rm -f /tmp/nc-agent-pause' 2>/dev/null
        echo "$(date) - Early detect: WiFi connected ($WLAN0_IP), online mode (stale pause files cleared)" >> $LOG
    fi
) &
echo "$(date) - Early offline detection launched (2min delay)"

# Nightcrawler auto-start — 5 min after boot, self-healing watchdog
# Why a loop instead of (sleep 300; cmd) &?  Android kills idle subshells
# that sleep too long. A short-sleep watchdog loop survives. It also self-
# heals: if the webui dies later, this re-runs autostart.sh to bring it back.
LOG=/data/local/tmp/var/log/nightcrawler-autostart.log
CHROOT=/data/local/nhsystem/kalifs
TRIGGER_DELAY=300   # 5 min after boot
CHECK_INTERVAL=60   # re-check every 60s

setsid nohup sh -c "
BOOT_TIME=\$(date +%s)
AUTOSTART_RAN=false
LOG=$LOG
while true; do
    UPTIME=\$((\$(date +%s) - BOOT_TIME))
    if [ \"\$AUTOSTART_RAN\" != 'true' ] && [ \$UPTIME -ge $TRIGGER_DELAY ]; then
        echo \"\$(date) - Watchdog: triggering autostart at +\${UPTIME}s\" >> \$LOG
        /system/bin/chroot $CHROOT /bin/bash -c 'exec /bin/bash /root/nightcrawler/scripts/autostart.sh' >> \$LOG 2>&1
        AUTOSTART_RAN=true
    fi
    if [ \"\$AUTOSTART_RAN\" = 'true' ]; then
        # If webui is down, restart it directly. autostart.sh's 'Already running'
        # guard would skip it if the agent is up, so call webui-daemon.sh instead.
        if ! netstat -tln 2>/dev/null | grep -q ':8888 '; then
            echo \"\$(date) - Watchdog: webui :8888 not bound, restarting webui-daemon\" >> \$LOG
            /system/bin/chroot $CHROOT /bin/bash -c 'bash /root/nightcrawler/scripts/webui-daemon.sh start' >> \$LOG 2>&1
        fi
    fi
    sleep $CHECK_INTERVAL
done
" </dev/null >/dev/null 2>&1 &
echo "$(date) - Nightcrawler auto-start watchdog launched (5min trigger, self-healing)"

# GPU Governor — 3 min delay, then force performance mode every 60s
(
    sleep 180
    GPU_GOV="/sys/class/kgsl/kgsl-3d0/devfreq/governor"
    GPU_MIN="/sys/class/kgsl/kgsl-3d0/devfreq/min_freq"
    GPU_MAX="/sys/class/kgsl/kgsl-3d0/devfreq/max_freq"
    BATTERY_CAP="/sys/class/power_supply/battery/capacity"
    BATTERY_STATUS="/sys/class/power_supply/battery/status"
    LOGFILE="/data/local/tmp/var/log/gpu-governor.log"
    MAX_FREQ=$(cat $GPU_MAX 2>/dev/null || echo "587000000")
    echo "$(date) - GPU governor started (3min delay, threshold=15%)" >> $LOGFILE
    while true; do
        CAP=$(cat $BATTERY_CAP 2>/dev/null || echo "50")
        STAT=$(cat $BATTERY_STATUS 2>/dev/null || echo "Unknown")
        if [ "$CAP" -le 15 ] && [ "$STAT" != "Charging" ]; then
            echo "msm-adreno-tz" > $GPU_GOV 2>/dev/null
        else
            # Force-set EVERY cycle — GPU driver can reset between checks
            echo "performance" > $GPU_GOV 2>/dev/null
            echo "$MAX_FREQ" > $GPU_MIN 2>/dev/null
        fi
        sleep 60
    done
) &
echo "$(date) - GPU governor launched (3min delay)"

# llama-server watchdog (5 min initial delay, random 1.75-2.5h refresh)
# Checks pause file BEFORE first start — won't waste time if offline mode
(
    TERMUX_HOME=/data/data/com.termux/files/home
    PORT=8080
    INITIAL_DELAY=300
    CRASH_COOLDOWN=1200
    LOGFILE=/data/local/tmp/var/log/llama-watchdog.log

    exec 1>>$LOGFILE 2>&1

    # Random refresh between 6300-9000s (1.75-2.5h)
    get_refresh() {
        echo $(( 6300 + (RANDOM % 2700) ))
    }

    REFRESH=$(get_refresh)
    echo "$(date) - Watchdog started (refresh=${REFRESH}s / ~$(( REFRESH / 3600 ))h$(( (REFRESH % 3600) / 60 ))m)"
    sleep $INITIAL_DELAY

    LAST_START=0

    while true; do
        # Check pause file — offline mode or maintenance
        PAUSE_FILE="/data/local/tmp/nc-llama-pause"
        if [ -f "$PAUSE_FILE" ]; then
            if pgrep -f "llama-server.*${PORT}" > /dev/null 2>&1; then
                echo "$(date) - Pause file exists — killing server for offline mode"
                pkill -9 -f "llama-server.*${PORT}" 2>/dev/null
            fi
            sleep 30
            continue
        fi

        NOW=$(date +%s)
        UPTIME=$(( NOW - LAST_START ))

        HEALTHY=false
        if wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok"; then
            HEALTHY=true
        else
            sleep 5
            if wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok"; then
                HEALTHY=true
            fi
        fi

        if [ "${HEALTHY}" = "true" ] && [ ${LAST_START} -gt 0 ] && [ ${UPTIME} -lt ${REFRESH} ]; then
            sleep 30
            continue
        fi

        if [ ${LAST_START} -gt 0 ] && [ ${UPTIME} -ge ${REFRESH} ]; then
            REFRESH=$(get_refresh)
            echo "$(date) - Refresh (was ${UPTIME}s, next ${REFRESH}s / ~$(( REFRESH / 60 ))min)"
        elif [ ${LAST_START} -gt 0 ]; then
            echo "$(date) - CRASH detected (healthy=${HEALTHY}, uptime=${UPTIME}s)"
        else
            echo "$(date) - Initial start"
        fi

        pkill -9 -f "llama-server.*${PORT}" 2>/dev/null
        sleep 3
        if pgrep -f "llama-server.*${PORT}" >/dev/null 2>&1; then
            echo "$(date) - WARN: still alive, retrying"
            pkill -9 -f "llama-server" 2>/dev/null
            sleep 5
        fi

        COUNT=$(pgrep -c llama-server 2>/dev/null || echo 0)
        if [ "$COUNT" != "0" ]; then
            echo "$(date) - ERROR: ${COUNT} still running"
            sleep 60
            continue
        fi

        am kill-all 2>/dev/null
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        sleep 3

        export LD_LIBRARY_PATH=${TERMUX_HOME}/../usr/lib:/vendor/lib64
        export GGML_OPENCL_PLATFORM=0 GGML_OPENCL_DEVICE=0
        cd ${TERMUX_HOME}/llama.cpp/ggml/src/ggml-opencl/kernels

        nohup ${TERMUX_HOME}/llama.cpp/build-fast/bin/llama-server \
            -m ${TERMUX_HOME}/models/Qwen3.5-2B-Unredacted-MAX.Q8_0.gguf \
            -ngl 99 -c 8192 -t 4 -np 1 \
            --port ${PORT} --host 127.0.0.1 \
            --jinja --reasoning off --log-disable \
            > /data/local/tmp/var/log/llama-server.log 2>&1 &

        NEW_PID=$!
        echo "$NEW_PID" > /data/local/tmp/var/run/llama-server.pid
        echo "$(date) - Started PID ${NEW_PID}"

        GOT_HEALTHY=false
        for i in $(seq 1 60); do
            sleep 5
            if wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok"; then
                echo "$(date) - Healthy after $((i*5))s (PID ${NEW_PID})"
                GOT_HEALTHY=true
                break
            fi
        done

        if [ "${GOT_HEALTHY}" != "true" ]; then
            echo "$(date) - ERROR: not healthy after 300s"
        fi

        LAST_START=$(date +%s)

        if [ "${HEALTHY}" != "true" ] && [ ${UPTIME} -lt ${REFRESH} ]; then
            echo "$(date) - Crash cooldown ${CRASH_COOLDOWN}s"
            sleep ${CRASH_COOLDOWN}
        fi
    done
) &
echo "$(date) - Watchdog launched (random 1.75-2.5h refresh)"
