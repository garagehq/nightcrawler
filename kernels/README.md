# Kernel & WiFi Driver Modules

## Custom Kernel (v4)

Built from Nameless AOSP source tree with MAC80211 wireless stack enabled.

- **Kernel**: 4.19.297-perf-g8228d522e928-dirty
- **Device**: OnePlus 8T (kebab), Snapdragon 865 (sm8250)
- **Key additions**: CONFIG_MAC80211=y, CONFIG_WIREGUARD=y, CONFIG_NF_TABLES=y
- **Module signing**: Disabled (CONFIG_MODULE_SIG not set, CONFIG_MODVERSIONS not set)
- **Build source**: https://github.com/garagehq/kernel_oneplus_sm8250_nethunter
- **Original upstream**: https://github.com/Nameless-AOSP-OSS/kernel_oneplus_sm8250 branch `thirteen`
- **vermagic**: `4.19.297-perf-g8228d522e928-dirty SMP preempt mod_unload aarch64` — modules must match this (or MODVERSIONS disabled as it is now)
- **"Internal hardware" warning**: Cosmetic only (dismiss it). If persistent across reboots, verify AnyKernel3 `02-no-verity-opt-encrypt` patch applied correctly.

Kernel images (boot.img, .zip) are gitignored due to size — stored on device at `/sdcard/nightcrawler-kernels/`.

## WiFi Driver Modules (`modules/`)

These .ko files are compiled for kernel 4.19.297-perf and can be loaded with `insmod`.

| Module | Size | Chipset | Adapters | Monitor Mode | Source |
|--------|------|---------|----------|-------------|--------|
| **rt2800usb.ko** (+ rt2x00lib, rt2x00usb, rt2800lib) | ~280KB total | **RT3572** | **Ralink RT3572 (148f:3572)** | **Yes — PMKID + full injection** | Built on-device from kernel source tree |
| **8821cu.ko** | 2.4MB | RTL8821CU | Edimax AC600 (7392:d811) | Yes — 55 networks in 15s (no PMKID) | https://github.com/morrownr/8821cu-20210916 (built on-device) |
| 88XXau.ko | 4.5MB | RTL8812AU/8821AU | ALFA AWUS036ACH, various | Yes (not for 8821CU chips) | https://github.com/aircrack-ng/rtl8812au (built on-device) |
| 8188eu.ko | 1.9MB | RTL8188EUS | Edimax N150 (7392:b811), EW-7811Un (7392:7811) | Yes — 28 networks in 15s | Cross-compiled from WSL |

### Loading Modules

```bash
# RT3572 (primary — PMKID + full injection) — must load in order
# Requires: apt install firmware-misc-nonfree (provides rt2870.bin)
cd /root/nightcrawler/kernels/modules
insmod rt2x00lib.ko
insmod rt2x00usb.ko
insmod rt2800lib.ko
insmod rt2800usb.ko

# RTL8821CU (secondary — scanning + basic deauth)
insmod /root/nightcrawler/kernels/modules/8821cu.ko

# Other adapters
insmod /root/nightcrawler/kernels/modules/8188eu.ko    # Edimax N150
insmod /root/nightcrawler/kernels/modules/88XXau.ko    # ALFA adapters

# Verify
lsmod | grep -E "rt2800usb|8821cu|8188eu|88XXau"
ip link show | grep wlan

# Make persistent across reboots
mkdir -p /lib/modules/$(uname -r)
cp /root/nightcrawler/kernels/modules/*.ko /lib/modules/$(uname -r)/
depmod -a
echo "rt2800usb" >> /etc/modules  # or whichever driver you need
```

### Key Discovery: Edimax AC600 is RTL8821CU

The Edimax Industrial AC600 (USB ID 7392:d811) was widely assumed to be RTL8811AU.
It is actually **RTL8821CU** — a completely different chipset. The rtl8812au driver
creates an interface but the radio never initializes (0 rx_packets). Only the
rtl8821cu driver works.

### Build Notes (on-device compilation)

**On-device builds are preferred** for ABI compatibility. Cross-compiled modules
(e.g., from another machine's kernel tree) often have wrong vermagic — for example,
an earlier cross-compile produced `g40c8aa96b8dc` instead of `g8228d522e928-dirty`,
causing `insmod` to reject the module.

Modules can be compiled directly in the Kali chroot with kernel headers installed:

```bash
# Kernel headers at /lib/modules/$(uname -r)/build/
# Host tools (modpost, fixdep) rebuilt for arm64

# Build any out-of-tree driver:
cd /path/to/driver
make -j4 ARCH=arm64 KSRC=/lib/modules/$(uname -r)/build CONFIG_<NAME>=m modules
```

Critical fixes for on-device builds:
- Rebuild `scripts/mod/modpost` and `scripts/basic/fixdep` natively (headers ship with x86 binaries)
- Create `arch/arm64/kernel/module.lds` linker script
- Install `bc` package (`apt install bc`)
- For rtl8821cu: comment out `EXTRA_CFLAGS += $(ccflags-y)` (recursive variable)
- For RT3572 (in-tree modules): match vermagic with `LOCALVERSION="-perf-g8228d522e928-dirty"` and
  a `.scmversion` file override in the kernel source to prevent git from auto-generating a different suffix

### Module Inventory

7 modules total (4 RT3572 + 3 Realtek):

| Module | Size | Built |
|--------|------|-------|
| rt2x00lib.ko | 78KB | On-device (kernel tree) |
| rt2x00usb.ko | 25KB | On-device (kernel tree) |
| rt2800lib.ko | 118KB | On-device (kernel tree) |
| rt2800usb.ko | 62KB | On-device (kernel tree) |
| 8821cu.ko | 2.4MB | On-device (morrownr fork) |
| 88XXau.ko | 4.5MB | On-device (aircrack-ng fork) |
| 8188eu.ko | 1.9MB | Cross-compiled from WSL |

## Recovery

Boot backup at `/sdcard/nightcrawler-kernels/boot-backup-20260324.img` (96MB).

If kernel doesn't boot:
1. Hold Power + Volume Down → FASTBOOT MODE
2. `fastboot flash boot_b boot-backup-20260324.img && fastboot reboot`
