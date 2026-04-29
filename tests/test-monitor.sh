#!/bin/bash
# Test monitor mode on wlan0 — runs for 30s then restores connectivity.
# Run from Android root shell (Termux or adb):
#   sh /data/local/nhsystem/kalifs/root/nightcrawler/scripts/test-monitor.sh
#
# Or from Kali chroot:
#   bash /root/nightcrawler/scripts/test-monitor.sh
#
# Log output: /data/local/tmp/nc-monitor-test.log
# Scan results: /data/local/tmp/nc-monitor-scan-01.csv (if airodump works)

LOG=/data/local/tmp/nc-monitor-test.log
SCAN_PREFIX=/data/local/tmp/nc-monitor-scan
DURATION=30

echo "$(date) === MONITOR MODE TEST ===" > $LOG
echo "$(date) Duration: ${DURATION}s" >> $LOG

# Step 1: Kill interfering processes
echo "$(date) Step 1: killing wpa_supplicant..." >> $LOG
pkill -9 wpa_supplicant 2>/dev/null
sleep 1

# Step 2: Record current state
echo "$(date) Step 2: current wlan0 state:" >> $LOG
ip link show wlan0 >> $LOG 2>&1
cat /sys/class/net/wlan0/type >> $LOG 2>&1
echo "" >> $LOG

# Step 3: Try to set monitor mode
echo "$(date) Step 3: setting monitor mode..." >> $LOG
ip link set wlan0 down >> $LOG 2>&1
echo "  down rc=$?" >> $LOG

# Try iw first (available in Kali chroot)
if command -v iw >/dev/null 2>&1; then
    iw dev wlan0 set type monitor >> $LOG 2>&1
    echo "  iw set monitor rc=$?" >> $LOG
else
    # Android side — use ip link
    ip link set wlan0 type monitor >> $LOG 2>&1
    echo "  ip type monitor rc=$?" >> $LOG
fi

ip link set wlan0 up >> $LOG 2>&1
echo "  up rc=$?" >> $LOG

# Step 4: Verify
echo "$(date) Step 4: verify monitor mode:" >> $LOG
ip link show wlan0 >> $LOG 2>&1
TYPE=$(cat /sys/class/net/wlan0/type 2>/dev/null)
echo "  /sys type=$TYPE (1=managed, 803=monitor)" >> $LOG

if command -v iw >/dev/null 2>&1; then
    iw dev wlan0 info >> $LOG 2>&1
fi

# Step 5: Try airodump-ng for DURATION seconds
echo "$(date) Step 5: running airodump-ng for ${DURATION}s..." >> $LOG

# Clean old scan files
rm -f ${SCAN_PREFIX}*.csv ${SCAN_PREFIX}*.cap 2>/dev/null

if command -v airodump-ng >/dev/null 2>&1; then
    airodump-ng wlan0 --write-interval 3 --output-format csv -w $SCAN_PREFIX >> $LOG 2>&1 &
    DUMP_PID=$!
    echo "  airodump-ng PID=$DUMP_PID" >> $LOG
    sleep $DURATION
    kill $DUMP_PID 2>/dev/null
    sleep 2
    kill -9 $DUMP_PID 2>/dev/null

    # Check results
    if ls ${SCAN_PREFIX}*.csv 1>/dev/null 2>&1; then
        LINES=$(wc -l < ${SCAN_PREFIX}-01.csv 2>/dev/null || echo 0)
        echo "$(date) Step 5 RESULT: CSV has $LINES lines" >> $LOG
        echo "  First 30 lines:" >> $LOG
        head -30 ${SCAN_PREFIX}-01.csv >> $LOG 2>&1
    else
        echo "$(date) Step 5 RESULT: No CSV file created — airodump may have failed" >> $LOG
    fi
else
    echo "  airodump-ng not found — skipping scan test" >> $LOG
    sleep $DURATION
fi

# Step 6: RESTORE managed mode (CRITICAL)
echo "$(date) Step 6: restoring managed mode..." >> $LOG
ip link set wlan0 down >> $LOG 2>&1

if command -v iw >/dev/null 2>&1; then
    iw dev wlan0 set type managed >> $LOG 2>&1
    echo "  iw set managed rc=$?" >> $LOG
else
    ip link set wlan0 type managed >> $LOG 2>&1
    echo "  ip type managed rc=$?" >> $LOG
fi

ip link set wlan0 up >> $LOG 2>&1
echo "  up rc=$?" >> $LOG

# Restart wpa_supplicant so Android reconnects
if command -v wpa_supplicant >/dev/null 2>&1; then
    # Find the Android wpa config
    WPA_CONF=$(find /data/misc/wifi -name "wpa_supplicant.conf" 2>/dev/null | head -1)
    if [ -n "$WPA_CONF" ]; then
        wpa_supplicant -B -i wlan0 -c "$WPA_CONF" >> $LOG 2>&1
        echo "  wpa_supplicant restarted with $WPA_CONF" >> $LOG
    fi
fi

# Android will likely restart wpa_supplicant on its own via ConnectivityManager
echo "$(date) Step 6: wlan0 restored. Android should reconnect automatically." >> $LOG

# Final state
echo "$(date) Final wlan0 state:" >> $LOG
ip link show wlan0 >> $LOG 2>&1
echo "  type=$(cat /sys/class/net/wlan0/type 2>/dev/null)" >> $LOG

echo "$(date) === TEST COMPLETE ===" >> $LOG
echo ""
echo "Done. Results in $LOG"
echo "Scan CSV in ${SCAN_PREFIX}-01.csv (if created)"
cat $LOG
