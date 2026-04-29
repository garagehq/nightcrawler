#!/bin/bash
# Test PMKID capture with hcxdumptool — handles monitor mode internally.
# Run from Kali chroot:
#   bash /root/nightcrawler/scripts/test-pmkid.sh
#
# Or from Android root shell:
#   chroot /data/local/nhsystem/kalifs bash /root/nightcrawler/scripts/test-pmkid.sh
#
# Log: /data/local/tmp/nc-pmkid-test.log
# Capture: /data/local/tmp/nc-pmkid-test.pcapng

LOG=/data/local/tmp/nc-pmkid-test.log
CAPTURE=/data/local/tmp/nc-pmkid-test.pcapng
DURATION=30

echo "$(date) === PMKID CAPTURE TEST ===" > $LOG
echo "$(date) Duration: ${DURATION}s" >> $LOG
echo "$(date) hcxdumptool handles monitor mode internally" >> $LOG

# Step 1: Kill interfering processes
echo "$(date) Step 1: killing wpa_supplicant..." >> $LOG
pkill -9 wpa_supplicant 2>/dev/null
sleep 1

# Step 2: Check interface
echo "$(date) Step 2: interface check" >> $LOG
hcxdumptool -I wlan0 >> $LOG 2>&1
echo "" >> $LOG

# Step 3: Remove old capture
rm -f $CAPTURE

# Step 4: Run hcxdumptool (it sets monitor mode itself)
echo "$(date) Step 3: running hcxdumptool for ${DURATION}s..." >> $LOG
echo "$(date) Command: hcxdumptool -i wlan0 -w $CAPTURE -c 1a,6a,11a -t 5" >> $LOG

timeout $DURATION hcxdumptool -i wlan0 -w $CAPTURE -c 1a,6a,11a -t 5 >> $LOG 2>&1
HCXRC=$?
echo "$(date) hcxdumptool exit code: $HCXRC" >> $LOG

# Step 5: Check results
echo "$(date) Step 4: checking results..." >> $LOG
if [ -f "$CAPTURE" ]; then
    SIZE=$(stat -c%s "$CAPTURE" 2>/dev/null || wc -c < "$CAPTURE")
    echo "  Capture file: $CAPTURE ($SIZE bytes)" >> $LOG

    # Convert to hash format for cracking
    if command -v hcxpcapngtool >/dev/null 2>&1; then
        hcxpcapngtool -o /data/local/tmp/nc-pmkid-hash.22000 $CAPTURE >> $LOG 2>&1
        echo "" >> $LOG
        if [ -f /data/local/tmp/nc-pmkid-hash.22000 ]; then
            HASHES=$(wc -l < /data/local/tmp/nc-pmkid-hash.22000)
            echo "  PMKID/EAPOL hashes extracted: $HASHES" >> $LOG
            echo "  First 5 hashes:" >> $LOG
            head -5 /data/local/tmp/nc-pmkid-hash.22000 >> $LOG
        else
            echo "  No PMKID/EAPOL hashes found in capture" >> $LOG
        fi
    fi
else
    echo "  No capture file created — hcxdumptool may have failed" >> $LOG
fi

# Step 6: Restore managed mode (hcxdumptool should do this on exit, but just in case)
echo "$(date) Step 5: restoring wlan0..." >> $LOG
ip link set wlan0 down 2>/dev/null
iw dev wlan0 set type managed 2>/dev/null
ip link set wlan0 up 2>/dev/null
echo "  wlan0 restored" >> $LOG

echo "$(date) === TEST COMPLETE ===" >> $LOG
echo ""
echo "Done. Log: $LOG"
echo "Capture: $CAPTURE"
cat $LOG
