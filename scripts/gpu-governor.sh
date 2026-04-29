#!/system/bin/sh
# GPU Power Governor Override for Nightcrawler
#
# Keeps GPU at max frequency (587MHz) regardless of charging state.
# Automatically throttles back to power-saving when battery < 15%.
# Run on Android side: sh /data/local/nhsystem/kalifs/root/nightcrawler/scripts/gpu-governor.sh
#
# Requires root (Magisk).

GPU_GOV="/sys/class/kgsl/kgsl-3d0/devfreq/governor"
GPU_MIN="/sys/class/kgsl/kgsl-3d0/devfreq/min_freq"
GPU_MAX="/sys/class/kgsl/kgsl-3d0/devfreq/max_freq"
BATTERY_CAP="/sys/class/power_supply/battery/capacity"
BATTERY_STATUS="/sys/class/power_supply/battery/status"
LOGFILE="/data/local/tmp/var/log/gpu-governor.log"
LOW_BATTERY_THRESHOLD=15
CHECK_INTERVAL=60

# Max freq from sysfs
MAX_FREQ=$(cat $GPU_MAX 2>/dev/null || echo "587000000")
DEFAULT_GOV="msm-adreno-tz"
PERF_GOV="performance"

echo "$(date) - GPU governor started (threshold=${LOW_BATTERY_THRESHOLD}%)" >> $LOGFILE

CURRENT_MODE="unknown"

while true; do
    CAPACITY=$(cat $BATTERY_CAP 2>/dev/null || echo "50")
    STATUS=$(cat $BATTERY_STATUS 2>/dev/null || echo "Unknown")
    GOV=$(cat $GPU_GOV 2>/dev/null || echo "unknown")

    if [ "$CAPACITY" -le "$LOW_BATTERY_THRESHOLD" ] && [ "$STATUS" != "Charging" ]; then
        # Low battery + not charging: restore default governor to save power
        if [ "$CURRENT_MODE" != "powersave" ]; then
            echo "$DEFAULT_GOV" > $GPU_GOV 2>/dev/null
            echo "$(date) - LOW BATTERY (${CAPACITY}%) - restored ${DEFAULT_GOV} governor" >> $LOGFILE
            CURRENT_MODE="powersave"
        fi
    else
        # Battery OK or charging: lock GPU to max performance
        if [ "$CURRENT_MODE" != "performance" ]; then
            echo "$PERF_GOV" > $GPU_GOV 2>/dev/null
            echo "$MAX_FREQ" > $GPU_MIN 2>/dev/null
            echo "$(date) - PERFORMANCE MODE (${CAPACITY}%, ${STATUS}) - GPU locked to ${MAX_FREQ}Hz" >> $LOGFILE
            CURRENT_MODE="performance"
        fi
    fi

    sleep $CHECK_INTERVAL
done
