# Limits_droper

Tools for reading/writing Intel package power limits, CPU ratios, and core voltage offset via MCHBAR MMIO and MSRs. Includes a Qt GUI (Wayland/COSMIC friendly via polkit), CLI utilities, and a privileged helper.

## Purpose

This project was made to bypass enforced power limits on a specific test setup by directly adjusting package power limit registers over MSR and MCHBAR MMIO. It has only been tested on an ES i7-13700HX (Q1K3) on an ASUS PRIME B660M-K D4, to bypass 55W (PL1) and 157W (PL2) limits. Other CPUs, steppings, or boards may behave differently.

## What’s here

- `mchbar_read.c`: read a few MCHBAR registers (including the package power limit window at 0x59A0).
- `mchbar_pl_write.c`: write the MCHBAR package power limit register (0x59A0).
- `limits_ui.c`: interactive CLI UI to view/set PL1/PL2 in watts and sync MSR <-> MMIO.
- `qt_ui/`: Qt Widgets GUI with buttons for read/set/sync, ratio control, and core voltage offset.
- `helper/`: privileged helper + polkit policy for running the Qt GUI as your user (Wayland/COSMIC friendly).

## Features

- Read/write PL1/PL2 in watts (MSR 0x610 and MCHBAR 0x59A0).
- Sync MSR <-> MMIO power limit values.
- P-core / E-core ratio targets (IA32_PERF_CTL 0x199) with current ratio display (IA32_PERF_STATUS 0x198).
- Core voltage offset (OC mailbox MSR 0x150, core plane).
- Basic CPU info panel in the GUI (model, microcode, core counts, P/E MHz).

## Requirements

- Linux with access to `/dev/mem` (root).
- MSR driver for `/dev/cpu/0/msr` (load with `modprobe msr`).
- Root privileges for reads/writes (helper uses polkit).
- Qt6 or Qt5 Widgets development package (for `qt_ui`).
- Qt tools / build tools (Qt CMake tooling) for the GUI build.
- Polkit (`pkexec`) for the Qt GUI helper on Wayland.

## Build

```bash
gcc -std=c11 -Wall -Wextra -O2 -o mchbar_read mchbar_read.c
gcc -std=c11 -Wall -Wextra -O2 -o mchbar_pl_write mchbar_pl_write.c
gcc -std=c11 -Wall -Wextra -O2 -o limits_ui limits_ui.c -lm
```

Qt UI build:
```bash
cd qt_ui
cmake -S . -B build
cmake --build build
```

Helper build:
```bash
gcc -std=c11 -Wall -Wextra -O2 -o limits_helper helper/limits_helper.c -lm
```

Install helper + polkit policy (required on Wayland/COSMIC):
```bash
sudo install -m 0755 limits_helper /usr/local/bin/limits_helper
sudo install -m 0644 helper/com.limits_droper.helper.policy /usr/share/polkit-1/actions/
```
If you install the helper somewhere else, update the policy `exec.path` to match and export `LIMITS_HELPER_PATH`.

## Usage

Read MCHBAR values:
```bash
sudo ./mchbar_read
```

Write MCHBAR package limits (PL1/PL2):
```bash
sudo ./mchbar_pl_write --set 150 170
sudo ./mchbar_pl_write --restore 0x004284e800df81b8
```

Interactive UI (read/set/sync MSR + MMIO):
```bash
sudo ./limits_ui
```

Qt UI:
```bash
./qt_ui/build/limits_ui_qt
```
If you `cd qt_ui` first, run `./build/limits_ui_qt`.
The GUI uses polkit via `pkexec`, so it should be run as your user (no `sudo`). You can override the helper path with `LIMITS_HELPER_PATH`.

## Notes

- MCHBAR base is assumed to be `0xFEDC0000`, package power limit register at offset `0x59A0`.
- MSR power unit is taken from `IA32_RAPL_POWER_UNIT` (0x606) and applied when converting watts.
- Power limits are written to `IA32_PKG_POWER_LIMIT` (0x610) and/or MCHBAR 0x59A0.
- Ratio targets are shown from `IA32_PERF_CTL` (0x199); current ratios are read from `IA32_PERF_STATUS` (0x198).
- P/E detection uses CPUID leaf 0x1A core type when available.
- Core voltage offset uses the OC mailbox (MSR 0x150) with a core-plane offset (mV). Use with caution.
- Tested only on ES i7-13700HX (Q1K3) on PRIME B660M-K D4, used to bypass 55W and 157W limits. Other CPUs/boards may differ.

## Troubleshooting

- GUI shows permission errors: make sure the helper is installed and the polkit policy is in place, then run the GUI as your user (not `sudo`).
- Verify helper output:
  ```bash
  pkexec /usr/local/bin/limits_helper --read
  ```
- P/E lists empty: CPUID 0x1A may be unavailable. Use “Set All” ratio or add a manual mapping.

## Credits

- Intel SDM (MSR/CPUID documentation): [Intel® 64 and IA-32 Architectures Software Developer’s Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).
- `linux-intel-undervolt` project for the OC mailbox offset encoding approach: [mihic/linux-intel-undervolt](https://github.com/mihic/linux-intel-undervolt).
- Qt for the GUI: [Qt](https://www.qt.io/).
- PolicyKit for privilege separation: [PolicyKit](https://www.freedesktop.org/wiki/Software/polkit/).

## Safety

Writing MSRs/MMIO can destabilize a system or damage hardware. Use at your own risk.
