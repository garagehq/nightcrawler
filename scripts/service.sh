#!/system/bin/sh
TRACE_FILE="/data/local/tmp/start_sshd.trace.log"
LOGFILE="/data/local/tmp/var/log/sshd.log"
PARAMETER_FILE="/data/local/tmp/home/.ssh/sshd_parameter"
START_SEMAPHOR="/data/local/tmp/home/start_sshd"
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
    echo "$(date) - SSH started (llama-server managed by watchdog_block.sh)"
fi
# Source Nightcrawler extensions (iptables, GPU governor, llama watchdog, auto-start)
if [ -f /data/local/tmp/watchdog_block.sh ]; then
    sh /data/local/tmp/watchdog_block.sh
    echo "$(date) - Sourced watchdog_block.sh"
fi
echo "$(date) - service.sh finished"
