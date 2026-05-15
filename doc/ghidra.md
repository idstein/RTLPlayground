# Understanding the image using ghidra

There are two image formats you might want to load:

1. A raw `rtlplayground.bin` (output of the top-level `make`) — instructions
   in this section.
2. An OEM upgrade image (any file produced by `installer/updatebuilder.c`,
   including stock vendor firmware that uses the same format). For that case,
   see [Loading an OEM upgrade image](#loading-an-oem-upgrade-image) below.

## Loading a raw rtlplayground.bin

Start ghidra, load file starting from offset 0x0002 into
memory starting at 0x0000. The lengthe is 0x10000. Select generic 8051, big
endian.

After loading, the boot vector is at 0x0000, which will jump to 0x0100 for
the boot routine.

The firmware uses only bank 1 of the RTL837x since it is quite short.
Otherwise the firmware would be organized as follows
```
--------------------------- 0x0000 ---------------------------------
Boot-Vector
ISRs
Common Code
Trampoline for inter-bank calls
Inter-bank calls, calling trampoline, one for each callable function

----- Bank 1 0x4000 ------   ---- Bank 2 0x4000 -----  -------- .....
Overlay 1                    Overlay 2                 Overlay n

--------- 0xffff ---------   -------- 0xffff --------  -------- 0xffff
```
The RTL837x firmware images are organized as follows:
The first 2 bytes of the image give the size of the prefetched data at the
start of the CPU power up. The default is 0x4000 (bytes: 0x00 0x40), which
means that the entire shared area of the code memory in all banks,
0x4000 bytes is read immediately into the code RAM.

Common code starts at
0x0002 in the image and has length 0x3ffd, the first bank starts at 0x4000
in the image, is mapped to 0x4000 and has length 0xc000. The second bank
starts at 0x10000, is mapped to 0x4000 and has length 0xc000. The third
bank would start at 0x1c000 and would again be mapped to 0x4000.
There are about 30 banks in use for managed switches, unmanaged ones use
2-3, while the hardware would allow to use 0x3f banks, i.e. up to 4 MB of
flash.

The current image uses Common BANK0 and the first BANK1 via sdccs __banked
function keyword and custom banking trampoline code for the RTL837x in
assembler.

## Loading an OEM upgrade image

OEM upgrade images (the format `installer/updatebuilder.c` produces, also used
by some stock vendor firmwares) prepend a 20-byte header and embed a second
copy of that header just before the actual firmware payload:

```
file 0x0000..0x0013   outer header (magic 0x12345678, reserved 0x332255FF)
file 0x0014..0x4011   common code (0x3FFE bytes) -> 8051 code 0x0000
file 0x4012..0x4025   duplicate header (skip)
file 0x4026..EOF      consecutive 0xC000-byte banks, each mapped to 0x4000
                       as an overlay; the last bank may be partial.
```

To set this up in Ghidra without doing the maths by hand, use the loader
script in [`tools/ghidra/LoadRTL837xOEM.py`](../tools/ghidra/LoadRTL837xOEM.py).

Requirements:

* Ghidra 12.x. Ghidra 12 dropped the bundled Jython, so the script runs under
  PyGhidra (Python 3.10+ via JPype). On Apple Silicon, the bundled `jpype1`
  cp39 wheel is x86_64-only — use a 3.10+ interpreter (the setup script pins
  3.13 via `uv`).
* `uv` for managing the PyGhidra venv (`brew install uv`).

Headless one-shot (creates a project under `ghidra_proj/`, imports the OEM
image, runs the loader, saves):

```
GHIDRA_HOME=/path/to/ghidra_12.1_PUBLIC OEM_BIN=/path/to/firmware.bin \
    tools/ghidra/setup.sh
```

The first run will use `uv venv --python 3.13` to create a Ghidra-managed
venv at `~/Library/ghidra/ghidra_12.1_PUBLIC/venv` and `uv pip install` the
`pyghidra` + `jpype1` wheels shipped under
`$GHIDRA_HOME/Ghidra/Features/PyGhidra/pypkg/dist/`. Subsequent runs reuse
the venv.

Open the resulting project in the GUI with `tools/ghidra/run.sh`.

Interactive (no setup script): in Ghidra, `File → Import File`, choose Raw
Binary, processor `8051:BE:16:default`, give the loader options a 1-byte
block at base `0x0`. Open the program, then run `LoadRTL837xOEM.py` from the
Script Manager (it lives in `~/ghidra_scripts/` if you installed via the
repo's tools dir) and select the same OEM `.bin` when prompted. The script
validates the header magic, clears the placeholder CODE block (leaving the
architecture-defined INTMEM/SFR/BITS blocks alone), creates `common` at
`0x0000`, and adds one overlay block per 0xC000-byte bank at `0x4000`.

After loading, the 8051 reset vector at `0x0000` and the standard interrupt
vectors are labelled (`vec_RESET`, `vec_INT0`, `vec_T0`, ...). The
inter-bank trampoline observed at `0x0006` (`MOV PSBANK,R7 ; RET`) is
labelled `bank_trampoline` to make banked-call sites easier to spot.
