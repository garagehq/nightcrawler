# Nightcrawler Quick Reference Commands

## SSH Access
```bash
# Android shell (from Kali chroot)
ssh -p 9022 shell@127.0.0.1

# Kali root shell (via Tailscale)
ssh -p 8022 root@<tailscale-ip>

# Android shell (via Tailscale)
ssh -p 9022 shell@<tailscale-ip>

# Enter Kali chroot
/data/data/com.offsec.nhterm/files/usr/bin_aarch64/kali
```

## GPU Inference (OpenCL - Recommended)

### Run LFM2.5-1.2B Q8_0 on GPU (production model — fastest + best balance)
```bash
TERMUX_HOME=/data/data/com.termux/files/home
su 10393 -c "export LD_LIBRARY_PATH=/vendor/lib64; \
  export GGML_OPENCL_PLATFORM=0; export GGML_OPENCL_DEVICE=0; \
  cd $TERMUX_HOME/llama.cpp/ggml/src/ggml-opencl/kernels; \
  $TERMUX_HOME/llama.cpp/build-fast/bin/llama-cli \
  -m $TERMUX_HOME/models/LFM2.5-1.2B-Instruct-Heretic.Q8_0.gguf \
  -ngl 99 -c 512 -n 200 -no-cnv \
  -p 'Your prompt here'"
```

### Run 0.8B Q8_0 on GPU (fastest)
```bash
TERMUX_HOME=/data/data/com.termux/files/home
su 10393 -c "export LD_LIBRARY_PATH=/vendor/lib64; \
  export GGML_OPENCL_PLATFORM=0; export GGML_OPENCL_DEVICE=0; \
  cd $TERMUX_HOME/llama.cpp/ggml/src/ggml-opencl/kernels; \
  $TERMUX_HOME/llama.cpp/build-fast/bin/llama-cli \
  -m $TERMUX_HOME/models/Qwen3.5-0.8B-Q8_0.gguf \
  -ngl 99 -c 512 -n 200 -no-cnv \
  -p 'Your prompt here'"
```

### Run 4B Q4_0 on GPU (best quality, slower)
```bash
TERMUX_HOME=/data/data/com.termux/files/home
su 10393 -c "export LD_LIBRARY_PATH=/vendor/lib64; \
  export GGML_OPENCL_PLATFORM=0; export GGML_OPENCL_DEVICE=0; \
  cd $TERMUX_HOME/llama.cpp/ggml/src/ggml-opencl/kernels; \
  $TERMUX_HOME/llama.cpp/build-fast/bin/llama-cli \
  -m $TERMUX_HOME/models/Qwen3.5-4B-Q4_0.gguf \
  -ngl 99 -c 512 -n 200 -no-cnv \
  -p 'Your prompt here'"
```

## CPU Inference (ollama — legacy fallback only)
Production runs LFM2.5-1.2B on the GPU (see above). ollama/CPU is a legacy
fallback; the Qwen tag below is kept only as an example.
```bash
# Enter Kali chroot first, then:
export TMPDIR=/tmp OLLAMA_VULKAN=0 OLLAMA_KEEP_ALIVE=1m
ollama serve &
ollama run qwen3.5:2b "Your prompt"
ollama stop qwen3.5:2b   # ALWAYS stop when done
```

## Memory Management
```bash
# Free RAM (run from Android root shell, not chroot)
am kill-all
echo 3 > /proc/sys/vm/drop_caches

# Check available memory
cat /proc/meminfo | grep MemAvail

# Kill any running llama processes
ps -ef | grep llama-cli | grep -v grep | awk '{print $2}' | xargs kill -9
```

## Performance Summary
| Model | Quant | GPU Gen | GPU Prompt | Use Case |
|-------|-------|---------|------------|----------|
| **LFM2.5-1.2B-Instruct-Heretic** | Q8_0 | **13 t/s** | **115 t/s** | **Production** — fastest + best balance |
| Qwen3.5-0.8B | Q8_0 | 6.3 t/s | 30.5 t/s | Legacy alt, quick tasks |
| Qwen3.5-4B | Q4_0 | 2.0 t/s | 10.1 t/s | Legacy alt, best Qwen quality |

## Useful Flags
```
-ngl 99          # Offload all layers to GPU
-c 512           # Context size (keep small for memory)
-n 200           # Max tokens to generate
-no-cnv          # Non-conversation mode (single prompt, exit after)
--no-display-prompt  # Don't echo the prompt back
-e               # Enable escape sequences in prompt
-p "..."         # The prompt
```

## llama-server Management

### Start llama-server (from Android shell, port 9022)
```bash
bash /data/local/nhsystem/kalifs/root/nightcrawler/scripts/start-llm.sh
```

### Start llama-server from a Kali SSH session
```bash
ssh -p 9022 shell@127.0.0.1 "bash /data/local/nhsystem/kalifs/root/nightcrawler/scripts/start-llm.sh"
```

### Check health
```bash
curl -s http://127.0.0.1:8080/health
# Returns: {"status":"ok"}
```

### Stop llama-server
```bash
ssh -p 9022 shell@127.0.0.1 "pkill -f llama-server"
```

### Auto-start behavior
- Magisk watchdog starts llama-server 5 min after boot (checks pause file first)
- If it crashes, watchdog restarts after 20 min cooldown
- Health checked every 30s when running
- Logs: /data/local/tmp/var/log/llama-server.log
- Watchdog log: /data/local/tmp/var/log/llama-watchdog.log

## WebUI Management

### Start WebUI daemon
```bash
/root/nightcrawler/scripts/webui-daemon.sh start
```

### Access WebUI
```
https://<tailscale-hostname>:8888
```
Self-signed cert — accept the browser warning.

### Stop/restart WebUI
```bash
/root/nightcrawler/scripts/webui-daemon.sh stop
/root/nightcrawler/scripts/webui-daemon.sh restart
/root/nightcrawler/scripts/webui-daemon.sh status
```
