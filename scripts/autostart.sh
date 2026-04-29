#!/bin/bash
# Nightcrawler autostart — runs INSIDE the Kali chroot via bash
# Called from watchdog_block.sh: chroot ... /bin/bash /root/nightcrawler/scripts/autostart.sh
# All commands run directly (no nested chroot calls needed)

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LOG=/data/local/tmp/var/log/nightcrawler-autostart.log

echo "" >> $LOG
echo "========== BOOT $(date) ==========" >> $LOG
echo "$(date) - Auto-start check (8min)" >> $LOG

# Check USB WiFi adapter and WiFi connectivity (these work from chroot — shared kernel)
USB_WIFI=$(lsusb 2>/dev/null | grep -E "7392:d811|7392:b811|7392:7811|148f:3572")
WLAN0_IP=$(ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}')

if [ -n "$USB_WIFI" ]; then
    echo "$(date) - USB WiFi adapter detected: $USB_WIFI" >> $LOG
    echo "$(date) - Entering OFFLINE mode (skipping agent+llama)" >> $LOG
    echo "offline" > /data/local/tmp/nc-llama-pause
    echo "offline-mode" > /tmp/nc-agent-pause
    echo "$(date) - Watchdogs paused" >> $LOG
    nohup kali-server-mcp --port 5000 </dev/null >/dev/null 2>&1 &
    sleep 3
    cd /root/nightcrawler
    nohup python3 scope_proxy.py --config config.yaml --port 8800 --upstream http://127.0.0.1:5000 </dev/null >/dev/null 2>&1 &
    sleep 3
    bash scripts/webui-daemon.sh start
    echo "$(date) - Offline services started (webui+mcp+proxy only)" >> $LOG
elif [ -z "$WLAN0_IP" ]; then
    echo "$(date) - No WiFi connected (wlan0 has no IP)" >> $LOG
    echo "$(date) - Entering DISCONNECTED mode (webui only, no agent/llama)" >> $LOG
    echo "no-wifi" > /data/local/tmp/nc-llama-pause
    echo "no-wifi" > /tmp/nc-agent-pause
    cd /root/nightcrawler
    bash scripts/webui-daemon.sh start
    echo "$(date) - Disconnected services started (webui only)" >> $LOG
elif pgrep -f 'python3 main.py' > /dev/null 2>&1; then
    echo "$(date) - Already running" >> $LOG
else
    # Ensure no stale pause files (belt-and-suspenders with early detect)
    rm -f /data/local/tmp/nc-llama-pause /tmp/nc-agent-pause
    echo "$(date) - Starting services (online mode, WiFi: $WLAN0_IP)..." >> $LOG
    nohup kali-server-mcp --port 5000 </dev/null >/dev/null 2>&1 &
    sleep 3
    cd /root/nightcrawler
    nohup python3 scope_proxy.py --config config.yaml --port 8800 --upstream http://127.0.0.1:5000 </dev/null >/dev/null 2>&1 &
    sleep 3
    bash scripts/webui-daemon.sh start
    sleep 3
    nohup python3 main.py >>/tmp/nc-agent.log 2>&1 &
    sleep 3
    nohup bash scripts/agent-watchdog.sh >>/tmp/nc-agent-watchdog.log 2>&1 &
    echo "$(date) - All started (online mode)" >> $LOG
fi
