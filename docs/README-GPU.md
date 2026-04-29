# Cyberclaw - Local LLM Inference on Android (Adreno 650 GPU)

GPU-accelerated local LLM inference on a rooted Android phone using OpenCL.

## Hardware
- **Phone**: OnePlus 8 (Snapdragon 865)
- **GPU**: Qualcomm Adreno 650 (OpenCL 2.0)
- **RAM**: 12GB (shared CPU/GPU)
- **OS**: Android 12 (Nameless AOSP) + Kali NetHunter chroot

## Performance

| Model | Quant | GPU Prompt | GPU Generation | vs CPU |
|-------|-------|------------|----------------|--------|
| **Qwen3.5-0.8B** | Q8_0 | 30.5 t/s | **6.3 t/s** | +62% |
| **Qwen3.5-2B** | Q8_0 | 23.3 t/s | **4.8 t/s** | +45% |
| **Qwen3.5-4B** | Q4_0 | 10.1 t/s | **2.0 t/s** | GPU only |

*Generation = tokens per second when the model is "talking back." 4.8 t/s ≈ 4-5 words/sec.*

## How It Works

1. **llama.cpp** compiled in Termux with Qualcomm's Adreno-optimized OpenCL kernels
2. **Qualcomm vendor OpenCL driver** (v819.2, E031.50) installed via Magisk module
3. Patches applied for Adreno 650 CL2.0 device compatibility (see `patches/`)
4. Models run entirely on the mobile GPU via OpenCL compute

## Quick Start

```bash
# SSH into the phone
ssh -p 9022 shell@<phone-ip>

# Run 2B model on GPU (best quality/speed balance)
TERMUX_HOME=/data/data/com.termux/files/home
su 10393 -c "export LD_LIBRARY_PATH=/vendor/lib64; \
  export GGML_OPENCL_PLATFORM=0; export GGML_OPENCL_DEVICE=0; \
  cd $TERMUX_HOME/llama.cpp/ggml/src/ggml-opencl/kernels; \
  $TERMUX_HOME/llama.cpp/build-fast/bin/llama-cli \
  -m $TERMUX_HOME/models/Qwen3.5-2B-Q8_0.gguf \
  -ngl 99 -c 512 -n 200 -no-cnv -p 'Your prompt'"
```

See `docs/COMMANDS.md` for all model commands.

## Setup Requirements

### Magisk Modules
| Module | Purpose | Source |
|--------|---------|--------|
| openssh | SSH access (ports 9022 + 22) | Magisk repo |
| adreno-650_819v2 | Updated GPU driver | [XDA Forums](https://xdaforums.com/t/4739196/) |
| nethunter | Kali Linux chroot | NetHunter installer |

### Software Stack
- **Termux**: clang, cmake, ninja, git, python, shaderc, opencl-headers
- **Kali chroot**: ollama (CPU inference), Mesa Turnip (Vulkan/KGSL)
- **llama.cpp**: Custom build with OpenCL patches for Adreno 650

### Key Insight: Quantization Matters
- **Q8_0**: Fastest on GPU for models that fit in memory (< ~2GB)
- **Q4_0**: Required for larger models (4B). Adreno kernels optimized for Q4_0 blocks
- **Q4_K_M**: AVOID on GPU - mixed quantization falls back to slow generic kernels (10x slower)

## Architecture

```
┌─────────────────────────────────────────────┐
│ Android (Bionic libc)                       │
│                                             │
│  Termux (OpenCL GPU inference)              │
│  ├── llama.cpp/build-fast/bin/llama-cli     │
│  ├── links to /vendor/lib64/libOpenCL.so    │
│  └── Adreno-optimized CL kernels           │
│                                             │
│  /vendor/lib64/ (Qualcomm v819.2 driver)    │
│  └── libOpenCL.so, libgsl.so, libCB.so     │
│                                             │
├─────────────────────────────────────────────┤
│ Kali NetHunter Chroot (glibc)              │
│  ├── ollama (CPU inference)                 │
│  ├── Mesa Turnip (Vulkan, limited use)      │
│  └── /root/cyberclaw/ (this repo)           │
├─────────────────────────────────────────────┤
│ Kernel: KGSL (/dev/kgsl-3d0)              │
│ Hardware: Adreno 650 GPU                    │
└─────────────────────────────────────────────┘
```

**Why Termux?** The vendor OpenCL driver is Android/bionic-linked.
Kali's glibc can't load it. Termux uses bionic natively.

**Why not Vulkan?** Vendor Vulkan is 1.1 (llama.cpp needs 1.2).
Mesa Turnip crashes with DeviceLostError during inference.

## The Journey (E031.37 → E031.50)

| Stage | 0.8B Gen | 2B Gen |
|-------|----------|--------|
| CPU only (ollama) | 2.2 t/s | 3.3 t/s |
| Vulkan (Mesa Turnip) | 2.1 t/s | crashed |
| OpenCL generic + old driver | 3.6 t/s | 0.2 t/s |
| OpenCL generic + v819 driver | 4.6 t/s | 1.8 t/s |
| **OpenCL Adreno + v819 driver** | **6.3 t/s** | **4.8 t/s** |

## Files

```
cyberclaw/
├── CLAUDE.md                    # Claude Code quick reference
├── docs/
│   ├── COMMANDS.md              # Copy-paste inference commands
│   ├── INSTALL.sh               # Reproducible setup script
│   └── README.md                # This file
├── patches/
│   └── llama-cpp-opencl-adreno650.patch
├── backups/
│   ├── magisk-openssh/          # SSH service configs
│   ├── magisk-adreno/           # GPU driver module info
│   └── kali-env/                # Kali environment config
└── models/                      # .gitignored (too large)
    ├── Qwen3.5-0.8B-Q8_0.gguf
    ├── Qwen3.5-2B-Q8_0.gguf
    └── Qwen3.5-4B-Q4_0.gguf
```

## After Reboot
Everything persists. No recompilation needed.
1. SSH auto-starts on ports 9022 and 22
2. `/vendor` auto-mounted in Kali chroot
3. First GPU inference: ~3 min kernel JIT (then cached)

## Memory Safety
- Free RAM before big models: `am kill-all && echo 3 > /proc/sys/vm/drop_caches`
- Always kill llama-cli when done
- 4B Q8_0 (4.2GB) won't load - exceeds 1GB per-allocation limit
- 9B+ models will OOM the phone
