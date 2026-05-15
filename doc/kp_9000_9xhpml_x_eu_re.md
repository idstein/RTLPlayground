# KP-9000-9XHPML-X-EU / SL-SWTGW0108P firmware reverse-engineering report

This is the consolidated reverse-engineering output for the OEM firmware
`SL-SWTGW0108P-1.9.1.bin` (MD5 `e59d1282882446319ec28267cf94b4da`,
923 828 bytes, build date `Mar 19 2024`). The OEM device is sold as the
**Sailing-L SL-SWTGW0108P** but is the same OEM hardware as the
**keepLink KP-9000-9XHPML-X-EU** — managed 8x 2.5 GbE 802.3at PoE+ + 1x
10 G SFP+, RTL8373 SoC, RTL8224/8226B PHY, HiSilicon (HiSi/`haisi`) PSE
controller on a separate "Itender" daughter board.

## Hardware

| Component | Source of evidence |
|-----------|--------------------|
| RTL8373 SoC | Strings `..\dal\rtl8373\dal_rtl8373_acl.c`, `..\dal\rtl8373\dal_rtl8373_isolation.c`, `..\dal\rtl8373\dal_rtl8373_trunk.c` |
| Realtek IC family | TLV blob `bank_01:0x5481..0x5483` contains `RTL8367N` (Realtek family marketing tag for RTL8373) |
| RTL8221B/RTL8226B PHY | Strings `Rtl8226b_rtct_start need linkdown to trig RTCT`, `rtl8221b and go init flow...` |
| HiSilicon PSE | Strings `===============HS PSE haisi_pse_cfg.bt_no=%ld.===============`, `..power_bank=%ld..` |
| PoE class support | UI strings `HiPoE(Class5)`, `HiPoE(Class6)`, `HiPoE(Class7)` (= 802.3bt class 5–7) |
| Flash | Winbond W25Q16 — 2 MB (user-reported) |
| Default IP/GW | TLV blob at `bank_01:0x543C..0x5453` contains `192.168.1.1` (gateway) and `192.168.1.20` (device) |
| Build date | TLV blob at `bank_01:0x5468..0x5472` = `Mar 19 2024` |
| Firmware version | Strings `V1.9.1`, hardware version `V3.0.0` |

## Image format

The OEM `.bin` uses the same upgrade-image format that
`installer/updatebuilder.c` in this repo produces:

```
file 0x0000..0x0013   outer header (magic 0x12345678, payload-len, hdr-cksum,
                       payload-cksum, reserved 0x332255FF)
file 0x0014..0x4011   common code (0x3FFE bytes) -> 8051 code 0x0000..0x3FFD
file 0x4012..0x4025   duplicate of the outer header
file 0x4026..EOF      consecutive 0xC000-byte banks, each mapped to 0x4000
                       as an overlay; 18 full banks + a partial 19th (0x588E).
```

Header fields verified for this binary:

| Offset | Field | Value |
|--------|-------|-------|
| 0x00 | magic | `0x12345678` |
| 0x04 | payload length | `0x000E18A0` = file size - 0x14 |
| 0x08 | header checksum | `0x000004E0` |
| 0x0C | payload checksum | `0x0477CC16` |
| 0x10 | reserved | `0x332255FF` |

## 8051 firmware layout

| Range | Purpose |
|-------|---------|
| common:0x0000..0x002A | Vector table: reset (LJMP 0x1016), INT0 (LJMP 0x3B11), T0 (LJMP 0x38F5), INT1 (LJMP 0x10DB) |
| common:0x0006        | Inline bank trampoline: `MOV PSBANK,R7 ; RET` |
| common:0x002B..0x002F | Boot prologue ending `MOV PSBANK,#3 ; LJMP 0x105A` |
| common:0x0103..0x025F | **Per-bank shim table**, 12 bytes/entry, banks 3..31 (29 entries). Each shim: `MOV 0xBB,0x96 ; MOV PSBANK,#N ; ACALL 0x025C ; MOV 0x96,0xBB ; RET`. Shim 0x025C = `CLR A ; JMP @A+DPTR ; RET` — caller stages DPTR with the bank-local target before LCALLing the shim. |
| common:0x025F..0x1300 | Huge **banked-function trampoline table**. Each 6-byte entry: `MOV DPTR,#bank_local_addr ; LJMP <dispatcher>`. Dispatchers at 0x1100, 0x1118, 0x113C, 0x1148, 0x1154, 0x1184, 0x1190, 0x11C0 route to specific banks. |
| common:0x1016        | `reset_entry` — entry point from the reset vector |
| bank_01:0x5320..     | Top-level **chip init function** (HADDR=0, register writes, 9 LCALLs into sub-inits) |
| bank_01:0x541C..     | **TLV configuration blob** (version, build date, default IP, gateway, chip family tag) |
| bank_06:0xEFEC..0xF0BF | **PIN_MUX / HW_CONF init routine**, two-mode (selected by R5) |
| bank_11:0x6A03       | Single `MOV 0xA0,#3` (WRITE_REG trigger): writes register `0x02F4` (chip-control, one-shot at boot) |
| bank_11:0x6A2D       | Single `MOV 0xA0,#1` (READ_REG trigger) for the same register |

## Register-access mechanism

The OEM firmware uses **direct XDATA MMIO via MOVX, not the SFR
`SFR_EXEC_GO`/`SFR_REG_ADDR_U16` mechanism that RTLPlayground uses**:

* `SFR 0x97` (`HADDR` per `rtl837x_sfr.h:53`) is set to **0** by the chip
  init routine and stays there. There is only one `MOV 0x97,A` site
  (`bank_01:0x532D`) plus the cluster of `8E 97` bytes in HTML data that
  byte-search false-positives on.
* Switch registers (0x0000..0xFFFF address space) are written by
  `MOV DPTR,#regaddr ; MOV A,#val ; MOVX @DPTR,A` against the chip's
  XDATA window.
* The `SFR_EXEC_GO=3` trigger appears **exactly once** in the entire
  firmware (`bank_11:0x6A03`) and writes register `0x02F4` only. This
  matches the rtl837x convention of using the SFR-trigger path only for
  the chip-control register subset.

This means RTLPlayground's `reg_write_m()` SFR-based access still works
on the silicon — RTLPlayground's mechanism and the OEM's mechanism just
target the chip differently. The hardware supports both.

## What the OEM does **not** program

Static analysis shows the OEM firmware **does not write any of**:

* `RTL837X_REG_LED_MODE` (0x6520)
* `RTL837X_REG_LED1_0_SETx` / `LED3_2_SETx` / `LED3_0_SETx` (0x6524..0x6548)
* `RTL837X_LED_PORT_SET_SEL` (0x654C)
* `RTL837X_REG_LED_GLB_MUX_1..6` (0x65E0..0x65F4)
* `RTL837X_REG_LED_GLB_ACTIVE` / `LED_GLB_IO_EN` (0x65D8/0x65DC)
* `RTL837X_REG_SDS_MODES` (0x7B20)
* `RTL837X_REG_SMI_PORT0_5_ADDR` / `PORT6_9_ADDR` / `SMI_CTRL`
  (0x644C/0x6450/0x6454)
* `RTL837X_REG_MAC_FORCE_MODE` (0x6344)

Verification covered every direct DPTR load encoding (`90 HH LL`), split
loads via DPH/DPL SFRs (`75 83 HH ; 75 82 LL`), DPTR loads via working
registers (`MOV Rn,#0x65 ; MOV DPH,Rn`), and SFR-trigger paths. There
are **zero** writes to those addresses across the entire 902 KB image.

**Conclusion**: the LED matrix and port/PHY/SDS routing are governed by
the chip's hardware defaults (set by strapping pins and OTP at boot)
plus values pulled from the TLV configuration blob in flash, not by the
firmware. RTLPlayground must therefore *provide* its own LED config;
matching the OEM's LED behaviour by static-RE alone is impossible
because the values aren't *in* the firmware.

## What the OEM **does** program — PIN_MUX/HW_CONF

`bank_06:0xEFEC..0xF0BF` is the pin-mux/hardware-control init routine.
It selects between two modes via `R5` (likely a board-strap input):

### Mode 1 (`R5==expected`, the high-power / PoE-enabled path)

```
[0x7E19] = 0x02
[0x7E1A] = 0x09
[0x7E1B] = 0x00
[0x7E1C] = 0x00
[0x7E1D] = 0x01
[0x7E1E] = 0xFF
[0x7E1F] = 0x09           ; HW-config / "PoE on"
[0x7F8D] = 0x09           ; PIN_MUX_0 byte 1
[0x7F8E] = 0x09           ; PIN_MUX_0 byte 2
[0x7F8F] = 0x02           ; PIN_MUX_0 byte 3 (LSB if MSB-at-low-addr)
[0x7F90] = 0x01           ; PIN_MUX_1 byte 0 (MSB)
[0x7F91] = 0x09           ; PIN_MUX_1 byte 1
[0x7F92] = 0x00           ; PIN_MUX_1 byte 2 (set via 32-bit zero helper)
[0x7F93] = 0x00           ; PIN_MUX_1 byte 3
[0x7F96] = 0x09           ; PIN_MUX_2 byte 2
[0x7F97] = 0x02           ; PIN_MUX_2 byte 3 (LSB)
[0x7F98] = 0x00           ; PIN_MUX_3 byte 0 (or next reg)
```

### Mode 2 (`R5==other`, the no-PoE / low-power path)

Same shape, but:

```
[0x7E1D] = 0x00           (1 -> 0)
[0x7E1F] = 0x08           (9 -> 8)
[0x7F90] = 0x00           (1 -> 0; PIN_MUX_1 byte 0)
[0x7F91] = 0x08           (9 -> 8)
```

So the only mode-dependent bits sit in `PIN_MUX_1[31:24]/[23:16]` and
the `0x7E1D/0x7E1F` HW-control bytes. The KP-9000-9XHPML-X-EU is the
PoE-enabled variant, so the firmware in production runs **mode 1**.

Reconstructed 32-bit register values (MSB at low address):

| Register | Mode 1 | Mode 2 | Notes |
|----------|--------|--------|-------|
| `PIN_MUX_0` @ 0x7F8C | `??_09_09_02` | `??_09_09_02` | MSB unwritten — chip-default |
| `PIN_MUX_1` @ 0x7F90 | `01_09_00_00` | `00_08_00_00` | High byte is the variant select |
| `PIN_MUX_2` @ 0x7F94 | `??_??_??_02` | `??_??_??_02` | Only LSB explicitly written |

## GPIO usage (confirmed from `strings -t x`)

| GPIO | Role | String evidence (file offset) |
|------|------|------------------------------|
| 30 | SFP module-detect (`OE Exist`) | `gpio30(OE Exist)=%bu` @ `0x18723` |
| 37 | SFP RX_LOS | `gpio37(OE LOS)=%bu` @ `0x18739` |
| 54 | reset (device + button) | `gpio54=%bu` @ `0x188A0`; `Reset button push %bu second` @ `0x2D4F` |
| – | SFP I²C path | `i2cdata reg11=…`, `…reg12=…` (SFP EEPROM A0/A2-page reads) |

These three pins match the existing `MACHINE_KP_9000_9XHML_X_V2_2`
definition (`machine.c:103`) exactly, so the V2.2-derived starter
machine struct we already committed is correct on the SFP/reset side.

## What's not recoverable statically

Two things would require either runtime help (serial console + `leds_dump`)
or a multi-day Ghidra effort with a custom cross-bank analyzer:

1. The chip's actual LED config (because the OEM doesn't program it; the
   values live in OTP/strapping or are board-default).
2. The port → PHY / SDS-lane mapping (because the OEM doesn't write
   SDS_MODES/SMI_CTRL either; same default-driven mechanism).

Both can be dumped in under a minute over UART once RTLPlayground is
flashed onto the board, using existing helpers (`rtl837x_leds.c`
`leds_dump()`, `rtl837x_init.c` `print_reg`).

## Updated machine entry recommendation

Take the existing `MACHINE_KP_9000_9XHPML_X_V2_2`-cloned struct in
`machine.c:103`, keep the SFP detect/LOS/reset pins (confirmed by the
OEM), and apply the V2.2 LED config as the placeholder until a runtime
register dump replaces it. The high-byte difference in `PIN_MUX_1`
(0x01 in PoE mode vs. 0x00 otherwise) lines up with this board being
the PoE variant.

## Tooling produced during this RE

The artefacts that came out of this session and that are reusable for
follow-up RE on other OEMs in this family:

* `tools/ghidra/LoadRTL837xOEM.py` — Ghidra loader; handles the OEM
  upgrade-image wrapper and the 0xC000-byte bank overlays.
* `tools/ghidra/AnalyzeRTL837x.py` — seeds entry points + triggers
  auto-analysis.
* `tools/ghidra/FindRegisterAccess.py` — searches for SFR-trigger
  register-access sites and traces callers.
* `tools/ghidra/setup.sh` — one-shot headless project bootstrap using
  `pyghidraRun -H` + `uv venv`.
* `tools/ghidra/run.sh` — GUI launcher.
* `doc/ghidra.md` — documents both the raw `rtlplayground.bin` layout
  and the OEM upgrade-image layout.
