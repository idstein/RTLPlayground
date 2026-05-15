# KP-9000-9XHPML-X-EU / -AC firmware reverse-engineering report

This is the consolidated reverse-engineering output for the OEM firmware
of the keepLink KP-9000-9XHPML-X — managed 8× 2.5 GbE 802.3bt PoE+ +
1× 10 G SFP+, RTL8373 SoC, RTL8224/8226B PHY, HiSilicon (HiSi /
`haisi`) PSE controller on a separate "Itender" daughter board.

The `-EU` and `-AC` SKUs are the **same hardware** — only the bundled
AC mains plug differs (EU plug vs the generic AC plug). They share the
same OEM firmware (`KP-9000-9XHPML-X-AC_V100.9.5.bin`).

A second firmware, `SL-SWTGW0108P-1.9.1.bin`, was also analyzed during
this session for completeness. **It is a different OEM product**
(Hasivo brand, different board revision) sharing the same RTL8373 + PoE
chip family. Its analysis is preserved in the "Companion firmware"
appendix at the bottom; the primary findings (everything outside that
appendix) describe the KP-9000-9XHPML-X-EU/AC device.

## Primary OEM firmware

`KP-9000-9XHPML-X-AC_V100.9.5.bin` — MD5 `1f7ca7727f105a4aa8719bc38a92736e`,
**2 097 152 bytes** (= full W25Q16 = 16 Mbit flash dump, not an upgrade
payload). Used content ends at `0x1FEA6C`; remainder is `0xFF` flash
padding.

## Hardware (factory-confirmed from this dump)

The flash dump's factory-config sector (`0x1FD000..0x1FD140`)
self-identifies the device:

| Field | Value |
|-------|-------|
| Device model | `KP-9000-9XHPML-X-AC` |
| **Hardware version** | **`V1.1`** |
| Default IP | `192.168.1.168` |
| Default mask | `255.255.255.0` |
| Default gateway | `192.168.1.1` |
| Management URL | `http://192.168.1.168/` |
| Admin user | `admin` |
| Obfuscated admin password | `<m>=899ij0ian317z-|*}-(~t prt"sw` |
| Chip family tag | `RTL8373` (factory sector `0x1FEA52`) |

Code-section evidence of the rest of the hardware:

| Component | Source of evidence |
|-----------|--------------------|
| RTL8373 SoC | Strings `..\dal\rtl8373\dal_rtl8373_acl.c`, `RTL8373:`, `RTL8373` |
| Realtek IC family tag | `RTL8367N` (Realtek's family-marketing string for RTL8373) at `0x1E487`, `0x1E496` |
| RTL8221B/RTL8226B PHY | Strings `Rtl8226b_rtct_start need linkdown to trig RTCT`, `rtl8221b and go init flow...` |
| HiSilicon PSE controller | Strings `HS PSE haisi_pse_cfg.bt_no=%ld`, `..power_bank=%ld` |
| 802.3bt PoE class support | UI strings `HiPoE(Class5)`, `HiPoE(Class6)`, `HiPoE(Class7)` |
| Flash | Winbond W25Q16 (user-reported, matches 2 MB dump size) |
| Firmware version | String `V100.9.5` @ `0x5EF9A` |
| Bootloader / sub-version | String `V0.2` @ `0xDF48` |
| Realtek SDK version tag | String `V3.0.0` @ `0x61502` |
| Image asset build date | Adobe Photoshop XMP at `0x2C34E`: `2020-05-18T10:32:52+08:00` |

## Image format

Raw `rtlplayground.bin`-compatible flash image (NOT an OEM upgrade
wrapper — that's the SL firmware's format, see appendix):

```
file 0x0000..0x0001    prefetch size (= 0x4000, little-endian byte order)
file 0x0002..0x3FFE    common code (0x3FFD bytes) -> 8051 code 0x0000..0x3FFD
file 0x4000..0xFFFF    bank 1 (0xC000 bytes) -> code 0x4000..0xFFFF (overlay)
file 0x10000..0x1BFFF  bank 2 (same overlay) ... and so on, 41 more banks
file 0x1FEA6C..0x200000  unused, 0xFF flash padding
file 0x1FC000..0x1FFFFF  factory- and user-config sectors (overlap with padding)
```

To load this image into Ghidra, use the **raw flash image** path
documented in `doc/ghidra.md` (load from offset `0x0002` into memory
`0x0000`, processor `8051:BE:16:default`); the OEM-upgrade-wrapper
loader script (`tools/ghidra/LoadRTL837xOEM.py`) does **not** apply to
this image.

## 8051 firmware layout

| Range | Purpose |
|-------|---------|
| `common:0x0000..0x002A` | 8051 vector table: reset → `LJMP 0x0D0B`, INT0 inline 8 bytes, T0 → `LJMP 0x0E64`, … |
| `common:0x000E` | Inline bank trampoline: `MOV PSBANK,R7 ; RET` |
| `common:0x0D0B` | `reset_entry` from the reset vector |
| `common:0x1018..0x1071` | Generic 32-bit `reg_write_m` helper using SFR_EXEC_GO (SFR 0xA0=3) |
| `common:0x107B..0x10A0` | Companion `reg_read_m` (SFR 0xA0=1) |
| `common:0x114E..0x1195` | GPIO 32..63 OUTPUT (reg `0x0040`) read-modify-write helper |
| `common:0x1196..0x11D0` | GPIO 32..63 INPUT  (reg `0x0048`) read helper |
| `common:0x11CE..0x121F` | GPIO 32..63 DIRECTION (reg `0x0050`) read-modify-write helper |
| `bank_03:0x6325` | One of the chip-init functions (sets HADDR=0, writes `[0x6CE3]=0x6D`, `[0x6CE4]=0x03`, chains into sub-inits) |
| `bank_01:0x46DB` | Second chip-init function (same prologue, different sub-inits) |
| `bank_01:0xDF93..0xDFEC` | Per-bank copy of `reg_write_m` (chip-control register `0x02F4`) |
| `bank_09:0x4040..0x40C8` | **PIN_MUX / HW_CONF init routine** (two-mode, R5-selected) |

## Register-access mechanism

The firmware uses the SFR_EXEC_GO mechanism (RTLPlayground-compatible)
for register accesses that need byte-level control:

- `SFR 0xA2:0xA3` (`SFR_REG_ADDR_U16`, per `rtl837x_sfr.h:4`) ← 16-bit
  register address.
- `SFR 0xA4:0xA5:0xA6:0xA7` (`SFR_DATA_U32`) ← 32-bit value.
- `SFR 0xA0` (`SFR_EXEC_GO`) ← `3` to write, `1` to read.

There are **4 WRITE_REG and 5 READ_REG sites** in the image; the
generic helpers are in common code at `0x1018` and `0x107B`, plus
specialised helpers for GPIO 32..63 (`0x0040`/`0x0048`/`0x0050`) and
the chip-control register `0x02F4`. RTLPlayground's `reg_write_m()` /
`reg_read_m()` (`rtlplayground.c:474..501`) is identical in mechanism
and will work on this hardware out of the box.

For register accesses that don't need the SFR-trigger path, the
firmware uses direct MOVX into XDATA-mapped switch registers. HADDR
(SFR `0x97`) is set to `0` once during chip init and left there
(only sites: `bank_01:0x46DB` and `bank_03:0x6335`).

## GPIO usage (confirmed from `strings -t x`)

| GPIO | Role | String evidence (file offset) |
|------|------|------------------------------|
| 30 | SFP module-detect (`OE Exist`) | `gpio30(OE Exist)=%bu` @ `0x314D6` |
| 37 | SFP RX_LOS | `gpio37(OE LOS)=%bu` @ `0x314EC` |
| 54 | reset (device + button) | `gpio54=%bu` @ `0x3167D`; `Reset button push %bu second` @ `0x3BCC` |
| – | SFP I²C path | `i2cdata reg11=…`, `…reg12=…` (SFP EEPROM A0/A2-page reads) |

These match the existing `MACHINE_KP_9000_9XHML_X_V2_2` definition
(`machine.c:103`) and confirm the `sfp_port[0].pin_detect`,
`pin_los` and `reset_pin` fields in the `MACHINE_KP_9000_9XHPML_X_EU`
machine struct.

## PIN_MUX / HW_CONF init (the `bank_09:0x4040` function)

The OEM firmware programs a specific block of registers at boot.
Recovered with `A`/`DPTR` tracking through the two-mode branch:

**Mode 1 (R5 == expected, the PoE-enabled / HP path):**

```
[0x7E01] = 0x02
[0x7E02] = 0x09
[0x7E04] = 0x00              ; A carries 0 from CLR A
[0x7E05] = 0x01
[0x7E06] = 0xFF
[0x7E07] = 0x09
[0x7F75] = 0x09
[0x7F76] = 0x09
[0x7F77] = 0x02
[0x7F78] = 0x01              ; PIN_MUX_1 byte 0 (MSB) = 0x01
[0x7F79] = 0x09
[0x7F7A] = 0x00              ; 32-bit zero via LCALL 0x2C28 helper
[0x7F7B] = 0x00
[0x7F7C] = 0x00              ; PIN_MUX_2 byte 0 = 0x00
[0x7F7D] = 0x00
[0x7F7E] = 0x09
[0x7F7F] = 0x02
[0x7F80] = 0x00
```

**Mode 2 (R5 != expected, the non-PoE / LP path):**

Differs only in the bytes affected by the variant strap:

```
[0x7E05] = 0x00              (1 -> 0)
[0x7E07] = 0x08              (9 -> 8)
[0x7F78] = 0x00              (1 -> 0)   ; PIN_MUX_1 high byte
[0x7F79] = 0x08              (9 -> 8)
[0x7F7E] = 0x08              (9 -> 8)
```

The KP-9000-9XHPML-X-EU/AC is the PoE-enabled variant and runs **Mode 1**
at production. The mode is selected by a hardware strap pin read into
`R5` early in the function.

### Reconstructed 32-bit registers (MSB at low address)

Treating each 4-byte aligned block as a 32-bit big-endian register:

| Register address (HW V1.1) | Mode 1 (PoE) | Notes |
|---------------------------|--------------|-------|
| `0x7F74` (4 bytes) | `??_09_09_02` | High byte unwritten → chip-default |
| `0x7F78` (4 bytes) | `01_09_00_00` | "PIN_MUX_1" |
| `0x7F7C` (4 bytes) | `00_00_09_02` | "PIN_MUX_2" |

### V1.1 vs the documented V1.0 register addresses

`rtl837x_regs.h:98-100` defines:

```c
#define RTL837X_PIN_MUX_0   0x7F8C
#define RTL837X_PIN_MUX_1   0x7F90
#define RTL837X_PIN_MUX_2   0x7F94
```

These are the V1.0 / V2.2-board addresses (matching the SL-SWTGW0108P
firmware in the appendix). The KP-9000-9XHPML-X HW V1.1 has its
PIN_MUX block at **0x7F74 / 0x7F78 / 0x7F7C** instead — exactly
`-0x18` (24 bytes) from the V1.0 layout. The 0x7E01..0x7E07
HW_CONF/strap block is similarly shifted from V1.0's 0x7E19..0x7E1F.

The mode selector at `R5` plus the `[0x7E07]=0x09/0x08` and
`[0x7F78]=0x01/0x00` deltas line up with PoE-vs-non-PoE board build
variants of the same hardware.

## Findings that DON'T need follow-up

The OEM firmware does **NOT** write any of the following:

- `RTL837X_REG_LED_MODE` (0x6520), `LED1_0_SETx` / `LED3_2_SETx` /
  `LED3_0_SETx` (0x6524..0x6548), `LED_PORT_SET_SEL` (0x654C),
  `LED_GLB_MUX_1..6` (0x65E0..0x65F4), `LED_GLB_ACTIVE` (0x65D8),
  `LED_GLB_IO_EN` (0x65DC).
- `RTL837X_REG_SDS_MODES` (0x7B20).
- `RTL837X_REG_SMI_PORT0_5_ADDR` / `PORT6_9_ADDR` / `SMI_CTRL`
  (0x644C / 0x6450 / 0x6454).
- `RTL837X_REG_MAC_FORCE_MODE` (0x6344).

Verified by exhaustive byte-pattern scan covering every immediate DPTR
load (`90 HH LL`), split DPH/DPL loads (`75 83 / 75 82`), DPTR loads
via working registers, and SFR-trigger paths. Zero hits.

These registers are set by chip strapping / OTP / boot ROM, not by the
8051 firmware. RTLPlayground must therefore provide its own LED config
on this hardware. The placeholder LED block in
`MACHINE_KP_9000_9XHPML_X_EU` (cloned from the related
`MACHINE_KP_9000_9XHML_X_V2_2` machine) is a reasonable starting point;
the final values should come from a runtime `leds_dump()` capture over
the serial console on first boot.

## Implications for `machine.c:103`

The current `MACHINE_KP_9000_9XHPML_X_EU` entry is **correct as
written for the fields the OEM firmware confirms**:

- `isRTL8373 = 1` ✓
- `min_port = 0`, `max_port = 8`, `n_sfp = 1` ✓ (9-port managed)
- `sfp_port[0].pin_detect = GPIO30_…` ✓ (string `gpio30(OE Exist)`)
- `sfp_port[0].pin_los = GPIO37` ✓ (string `gpio37(OE LOS)`)
- `reset_pin = GPIO54_…` ✓ (string `gpio54` + reset-button counter)
- `sfp_port[0].i2c = { GPIO39_…, GPIO40_… }` — same I²C bus as
  every other 9-port RTL8373 variant; consistent with `i2cdata
  reg11/reg12` string evidence.

Still unverified statically (the firmware doesn't write these
registers, so they aren't recoverable from the binary):

- `sfp_port[0].sds` — sds lane number for the SFP port.
- `port_led_set[]`, `led_sets[][]`, `high_leds` — LED config.
- `led_mux_custom` / `led_mux[]` — pad-level LED muxing.

These need a runtime dump over the serial console (`leds_dump()`,
`rtl837x_leds.c:28`) once the firmware is flashed onto the board.

## Companion firmware (appendix): SL-SWTGW0108P V1.9.1

`SL-SWTGW0108P-1.9.1.bin` — MD5 `e59d1282882446319ec28267cf94b4da`,
923 828 bytes, build date `Mar 19 2024`, vendor brand `hasivo` (in
code section). **This is a different OEM product**, not a KP-9000
device — included here only because it shares the same RTL8373 chip
family and produced useful comparison data while we were validating
the KP-9000 RE.

It is the OEM-upgrade-image format (the same wrapper that
`installer/updatebuilder.c` produces; see `tools/ghidra/LoadRTL837xOEM.py`
for the Ghidra loader):

```
file 0x0000..0x0013   outer header (magic 0x12345678, …, reserved 0x332255FF)
file 0x0014..0x4011   common code (0x3FFE bytes) -> 8051 code 0x0000..0x3FFD
file 0x4012..0x4025   duplicate of the outer header
file 0x4026..EOF      consecutive 0xC000-byte banks, 18 full + a 0x588E tail
```

Versions: firmware `V1.9.1`, hardware-version string `V1.0` (in code,
no factory sector available because this is an upgrade payload, not a
flash dump). Brand string `hasivo` and IP/version TLV blob at
`bank_01:0x541C`.

PIN_MUX/HW_CONF init for that device is at `bank_06:0xEFEC`. Same
logical values as the KP-9000 (`0x02`, `0x09`, `0x01`, `0x08`, `0xFF`),
but written to a register block shifted **+0x18** higher than the
KP-9000 V1.1 addresses — i.e. that device has its PIN_MUX at
`0x7E19..0x7E1F` / `0x7F8D..0x7F98` (matching the V1.0 numbering in
`rtl837x_regs.h`), whereas the KP-9000 V1.1 has it at
`0x7E01..0x7E07` / `0x7F75..0x7F80`.

Other notable SL-vs-KP-9000 differences:

- SL has only **1 SFR_EXEC_GO** site in the entire image (the
  chip-control `0x02F4` writer). KP-9000 has 4 WRITE + 5 READ via real
  helpers. So the two firmwares are built from different SDK
  configurations.
- SL bank trampoline is at code `0x0006` (`MOV PSBANK,R7 ; RET`);
  KP-9000 has it at code `0x000E`. Different SDCC build config.
- SL's main XDATA work area is at `0x8000..0x8FFF` (82% of DPTR loads);
  KP-9000 has it at `0x1000..0x1FFF` (81%). Different linker config.

LED conclusion is the same for both: chip strapping/OTP rules, neither
firmware programs the LED block.

## Tooling produced during this RE

The artefacts that came out of this session and that are reusable for
follow-up RE on other OEMs in this family:

* `tools/ghidra/LoadRTL837xOEM.py` — Ghidra loader; handles the OEM
  upgrade-image wrapper and the 0xC000-byte bank overlays. **Use only
  for OEM-upgrade-image files** (`12 34 56 78` magic at offset 0).
* `tools/ghidra/AnalyzeRTL837x.py` — seeds entry points + triggers
  auto-analysis.
* `tools/ghidra/FindRegisterAccess.py` — searches for SFR-trigger
  register-access sites and traces callers.
* `tools/ghidra/setup.sh` — one-shot headless project bootstrap using
  `pyghidraRun -H` + `uv venv`.
* `tools/ghidra/run.sh` — GUI launcher.
* `doc/ghidra.md` — documents both the raw `rtlplayground.bin` layout
  (use this for the KP-9000 firmware) and the OEM upgrade-image layout
  (use this for the SL appendix firmware).
