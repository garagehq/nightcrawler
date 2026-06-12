#!/system/bin/sh
TRACE_FILE="/data/local/tmp/start_sshd.trace.log"
LOGFILE="/data/local/tmp/var/log/sshd.log"
PARAMETER_FILE="/data/local/tmp/home/.ssh/sshd_parameter"
START_SEMAPHOR="/data/local/tmp/home/start_sshd"
PIDFILE=/data/local/tmp/var/run/llama-server.pid
exec 1>${TRACE_FILE} 2>&1
echo "$(date) - service.sh starting"
mkdir -p /data/local/tmp/var/log /data/local/tmp/var/run /data/local/tmp/var/empty
sleep 10
if [ -r ${START_SEMAPHOR} ] ; then
    CUR_SSHD_PARAMETER=""
    if [ -r "${PARAMETER_FILE}" ] ; then
        CUR_SSHD_PARAMETER="${CUR_SSHD_PARAMETER} $( grep -vE "^#|^$" "${PARAMETER_FILE}" | tr "\n" " ")"
    fi
    touch ${LOGFILE}; chmod 644 ${LOGFILE}
    CUR_SSHD_PARAMETER="${CUR_SSHD_PARAMETER} -E ${LOGFILE}"
    /system/bin/sshd ${CUR_SSHD_PARAMETER}
    echo "$(date) - Android sshd 9022: $?"
    sleep 2
    CHROOT=/data/local/nhsystem/kalifs
    if [ -d "${CHROOT}" ] && [ ! -f "${CHROOT}/vendor/lib64/libOpenCL.so" ]; then
        mkdir -p ${CHROOT}/vendor; mount --bind /vendor ${CHROOT}/vendor
        echo "$(date) - Mounted /vendor"
    fi
    if [ -d "${CHROOT}" ]; then
        mkdir -p ${CHROOT}/run/sshd; chmod 755 ${CHROOT}/run/sshd
        /system/bin/chroot ${CHROOT} /usr/sbin/sshd
        echo "$(date) - Kali sshd 8022: $?"
        ( for _i in 1 2 3 4 5 6 7 8 9 10; do sleep 30; netstat -tlnp 2>/dev/null | grep -q ":8022 " || /system/bin/chroot ${CHROOT} /usr/sbin/sshd 2>/dev/null; done ) &
    fi
    (
        TERMUX_HOME=/data/data/com.termux/files/home
        KERNEL_DIR=${TERMUX_HOME}/llama.cpp/ggml/src/ggml-opencl/kernels
        MODEL=${TERMUX_HOME}/models/LFM2.5-1.2B-Instruct-Heretic.Q8_0.gguf
        PORT=8080
        REFRESH=14400
        COOLDOWN=1200
        KILLWAIT=20
        exec 1>/data/local/tmp/var/log/llama-watchdog.log 2>&1
        echo "$(date) - Watchdog waiting 1200s"
        sleep 1200
        start_svr() {
            if [ -f "$PIDFILE" ]; then kill $(cat $PIDFILE) 2>/dev/null; sleep 5; kill -9 $(cat $PIDFILE) 2>/dev/null; rm -f $PIDFILE; fi
            pkill -9 -f "llama-server.*--port ${PORT}" 2>/dev/null
            sleep $KILLWAIT
            C=$(pgrep -f "llama-server.*--port ${PORT}" 2>/dev/null | wc -l)
            [ "$C" -gt 0 ] && { pgrep -f "llama-server.*--port ${PORT}" | xargs kill -9 2>/dev/null; sleep 5; }
            am kill-all 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 2
            C=$(pgrep -f "llama-server.*--port ${PORT}" 2>/dev/null | wc -l)
            [ "$C" -gt 0 ] && { echo "$(date) - FATAL: $C zombies after kill"; return 1; }
            export LD_LIBRARY_PATH=${TERMUX_HOME}/../usr/lib:/vendor/lib64
            export GGML_OPENCL_PLATFORM=0 GGML_OPENCL_DEVICE=0
            cd ${KERNEL_DIR}
            ${TERMUX_HOME}/llama.cpp/build-fast/bin/llama-server -m ${MODEL} -ngl 99 -c 8192 -t 4 -np 1 --port ${PORT} --host 127.0.0.1 --jinja --reasoning off --log-disable > /data/local/tmp/var/log/llama-server.log 2>&1 &
            echo "$!" > $PIDFILE; echo "$(date) - PID $!"
            for i in $(seq 1 60); do
                sleep 5
                wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok" && { echo "$(date) - Healthy after $((i*5))s"; return 0; }
                kill -0 $(cat $PIDFILE 2>/dev/null) 2>/dev/null || { echo "$(date) - Died during startup"; rm -f $PIDFILE; return 1; }
            done
            return 1
        }
        start_svr; LAST=$(date +%s)
        while true; do
            sleep 30
            # Check pause file — offline mode or maintenance
            if [ -f "/data/local/tmp/nc-llama-pause" ]; then
                if pgrep -f "llama-server.*--port ${PORT}" > /dev/null 2>&1; then
                    echo "$(date) - Pause file — killing for offline mode"
                    pkill -9 -f "llama-server.*--port ${PORT}" 2>/dev/null
                fi
                continue
            fi
            UP=$(( $(date +%s) - LAST ))
            [ $UP -ge $REFRESH ] && { echo "$(date) - Refresh ($((UP/3600))h)"; start_svr; LAST=$(date +%s); continue; }
            wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok" && continue
            sleep 5; wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok" && continue
            # Check if process is actually dead before restarting
            if [ -f "$PIDFILE" ] && kill -0 $(cat $PIDFILE) 2>/dev/null; then
                echo "$(date) - Health failed but PID $(cat $PIDFILE) alive, skipping"
                continue
            fi
            C=$(pgrep -f "llama-server.*--port ${PORT}" 2>/dev/null | wc -l)
            if [ "$C" -gt 0 ]; then
                echo "$(date) - Health failed but $C process(es) running, skipping"
                continue
            fi
            echo "$(date) - CRASHED (process dead)"; start_svr; LAST=$(date +%s)
            [ $? -ne 0 ] && { echo "$(date) - Cooldown ${COOLDOWN}s"; sleep $COOLDOWN; }
        done
    ) &
    echo "$(date) - Watchdog launched"
fi
# Source Nightcrawler extensions (iptables, GPU governor, auto-start)
if [ -f /data/local/tmp/watchdog_block.sh ]; then
    sh /data/local/tmp/watchdog_block.sh
    echo "$(date) - Sourced watchdog_block.sh"
fi
echo "$(date) - service.sh finished"
