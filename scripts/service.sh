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
        # Kali sshd needs a real /dev inside the chroot. /data is mounted nodev, so a
        # device node created on it (the chroot's /dev/null) does not function, and
        # sshd's daemon() reopens stdio onto /dev/null and dies with
        # "daemon() failed: No such device" — port 8022 then never comes up.
        # Bind the real /dev /proc /sys (+ devpts) into the chroot. Guards are
        # effect-based on purpose: /proc/mounts does NOT reflect these binds under
        # Magisk's mount namespace, so a /proc/mounts grep would re-mount forever.
        [ -c ${CHROOT}/dev/null ]     || mount --bind /dev  ${CHROOT}/dev
        [ -e ${CHROOT}/dev/pts/ptmx ] || mount -t devpts devpts ${CHROOT}/dev/pts 2>/dev/null
        [ -e ${CHROOT}/proc/self ]    || mount --bind /proc ${CHROOT}/proc
        [ -e ${CHROOT}/sys/kernel ]   || mount --bind /sys  ${CHROOT}/sys
        mkdir -p ${CHROOT}/run/sshd; chmod 755 ${CHROOT}/run/sshd
        /system/bin/chroot ${CHROOT} /usr/sbin/sshd
        echo "$(date) - Kali sshd 8022: $?"
        # Persistent keepalive: revive Kali sshd if it ever dies (OOM, scheduled
        # restart, etc.), re-ensuring the /dev+devpts binds first, so port 8022 is
        # always reachable. Runs in service.sh's mount namespace (binds visible).
        ( while true; do
            sleep 30
            netstat -tlnp 2>/dev/null | grep -q ":8022 " && continue
            [ -c ${CHROOT}/dev/null ]     || mount --bind /dev  ${CHROOT}/dev
            [ -e ${CHROOT}/dev/pts/ptmx ] || mount -t devpts devpts ${CHROOT}/dev/pts 2>/dev/null
            /system/bin/chroot ${CHROOT} /usr/sbin/sshd 2>/dev/null
          done ) &
    fi
    echo "$(date) - SSH started (llama-server managed by watchdog_block.sh)"
fi
# Source Nightcrawler extensions (iptables, GPU governor, llama watchdog, auto-start)
if [ -f /data/local/tmp/watchdog_block.sh ]; then
    sh /data/local/tmp/watchdog_block.sh
    echo "$(date) - Sourced watchdog_block.sh"
fi
echo "$(date) - service.sh finished"
