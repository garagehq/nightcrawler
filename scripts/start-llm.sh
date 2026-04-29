#!/bin/bash
# Start llama-server on GPU (OpenCL)
#
# MUST be run from the Android root shell (port 9022), NOT from Kali chroot.
# Runs as root (not Termux user) because su 10393 can't bind ports.
#
# Usage:
#   bash /data/local/nhsystem/kalifs/root/nightcrawler/scripts/start-llm.sh
#   bash /data/local/nhsystem/kalifs/root/nightcrawler/scripts/start-llm.sh [model_path] [port]
#
# From Kali chroot SSH session, start via:
#   ssh -p 9022 shell@127.0.0.1 "bash /data/local/nhsystem/kalifs/root/nightcrawler/scripts/start-llm.sh"

TERMUX_HOME=/data/data/com.termux/files/home
KERNEL_DIR=${TERMUX_HOME}/llama.cpp/ggml/src/ggml-opencl/kernels
MODEL=${1:-${TERMUX_HOME}/models/Qwen3.5-2B-Unredacted-MAX.Q8_0.gguf}
PORT=${2:-8080}
LLAMA_LOG=/data/local/tmp/var/log/llama-server.log

# Check if already running
if wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok"; then
    echo "[+] llama-server already healthy on port ${PORT}"
    exit 0
fi

echo "[*] Starting llama-server on GPU (port ${PORT})..."
echo "[*] Model: $(basename ${MODEL})"
echo "[*] Context: 4096 tokens"

# Kill old instances (SIGKILL — graceful SIGTERM doesn't work reliably
# when llama-server is doing GPU/OpenCL work, causing dual-process OOM)
pkill -9 -f "llama-server.*${PORT}" 2>/dev/null
sleep 2
# Verify kill succeeded — retry if still alive
if pgrep -f "llama-server.*${PORT}" >/dev/null 2>&1; then
    echo "[!] llama-server still alive after SIGKILL, retrying..."
    pkill -9 -f "llama-server" 2>/dev/null
    sleep 3
fi

# Free RAM
am kill-all 2>/dev/null
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 1

export LD_LIBRARY_PATH=${TERMUX_HOME}/../usr/lib:/vendor/lib64
export GGML_OPENCL_PLATFORM=0
export GGML_OPENCL_DEVICE=0
cd ${KERNEL_DIR}

nohup ${TERMUX_HOME}/llama.cpp/build-fast/bin/llama-server \
    -m ${MODEL} -ngl 99 -c 8192 -t 4 \
    -np 1 \
    --port ${PORT} --host 127.0.0.1 \
    --jinja --reasoning off --log-disable \
    > ${LLAMA_LOG} 2>&1 &

PIDFILE=/data/local/tmp/var/run/llama-server.pid
echo "$!" > ${PIDFILE}
echo "[*] Launched PID $! (written to ${PIDFILE}). Waiting for health..."
for i in $(seq 1 60); do
    sleep 5
    if wget -qO- http://127.0.0.1:${PORT}/health 2>/dev/null | grep -q "ok"; then
        echo "[+] llama-server HEALTHY on port ${PORT} after $((i*5))s"
        exit 0
    fi
    printf "."
done
echo ""
echo "[-] Timeout. Check ${LLAMA_LOG}"
exit 1
