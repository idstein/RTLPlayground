# RTLPlayground — Ghidra loader for an RTL837x OEM upgrade-format image.
#
# Wraps the layout produced by RTLPlayground's `installer/updatebuilder.c`:
#
#   file 0x0000..0x0013   outer OEM upgrade header (HEADER_LENGTH = 0x14)
#   file 0x0014..0x4011   common code (length 0x3FFE) → maps to 8051 code 0x0000
#   file 0x4012..0x4025   second copy of the OEM upgrade header (HEADER_LENGTH)
#   file 0x4026..EOF      consecutive 0xC000-byte banks, each mapped to 0x4000
#                          as an overlay (last bank may be partial).
#
# Workflow:
#   1. File → Import File → pick the OEM .bin
#         Format: Raw Binary
#         Language: Intel 8051   (Variant: default, Endian: big, Size: 16)
#         Options: Block name=`tmp`, Base address=0x0000, File offset=0,
#                  Length=0x1                  (just enough to create the program)
#   2. Open the imported program.
#   3. Window → Script Manager → run LoadRTL837xOEM.py.
#   4. Pick the same .bin when prompted (the script re-reads the file to populate
#      common + every bank).
#
# Headless equivalent (one-shot):
#   $GHIDRA/support/analyzeHeadless <proj-dir> <proj-name> \
#       -import <oem.bin> \
#       -loader BinaryLoader \
#       -loader-blockName=tmp -loader-baseAddr=0x0 \
#       -loader-fileOffset=0 -loader-length=0x1 \
#       -processor 8051:BE:16:default \
#       -postScript LoadRTL837xOEM.py <oem.bin>
#
# @author  RTLPlayground tooling
# @category RTL837x
# @runtime PyGhidra

import os
import struct
from java.io import FileInputStream

OEM_HEADER_LEN    = 0x14
COMMON_LEN        = 0x3FFE
SECOND_HEADER_LEN = 0x14
BANK_LEN          = 0xC000
BANK_BASE         = 0x4000

HEADER_MAGIC      = 0x12345678
HEADER_RESERVED   = 0x332255FF


def get_oem_path():
    args = getScriptArgs()
    if args:
        return args[0]
    f = askFile("Select RTL837x OEM upgrade .bin", "Load")
    return f.getAbsolutePath()


def verify_oem_header(path):
    with open(path, 'rb') as fh:
        head = fh.read(OEM_HEADER_LEN)
    magic    = struct.unpack('>I', head[0x00:0x04])[0]
    payload  = struct.unpack('>I', head[0x04:0x08])[0]
    hdr_sum  = struct.unpack('>I', head[0x08:0x0C])[0]
    pl_sum   = struct.unpack('>I', head[0x0C:0x10])[0]
    reserved = struct.unpack('>I', head[0x10:0x14])[0]
    print("OEM header:")
    print("  magic     = 0x%08x %s" % (magic,    "OK"  if magic    == HEADER_MAGIC    else "MISMATCH"))
    print("  payload   = 0x%08x (file size - 0x14 expected)" % payload)
    print("  hdr_sum   = 0x%08x" % hdr_sum)
    print("  pl_sum    = 0x%08x" % pl_sum)
    print("  reserved  = 0x%08x %s" % (reserved, "OK"  if reserved == HEADER_RESERVED else "MISMATCH"))
    if magic != HEADER_MAGIC or reserved != HEADER_RESERVED:
        raise Exception("File does not look like an RTL837x OEM upgrade image")
    return payload


def make_file_bytes(path):
    size = os.path.getsize(path)
    fis = FileInputStream(path)
    try:
        return currentProgram.getMemory().createFileBytes(
            os.path.basename(path), 0, size, fis, monitor)
    finally:
        fis.close()


def remove_code_blocks():
    """Drop the placeholder block(s) in the CODE space without touching the
    8051 architecture-defined INTMEM/SFR/BITS blocks."""
    mem = currentProgram.getMemory()
    code_space = currentProgram.getAddressFactory().getAddressSpace("CODE")
    for b in list(mem.getBlocks()):
        if b.getStart().getAddressSpace() == code_space:
            print("  removing %-12s @ %s (len 0x%x)" % (b.getName(), b.getStart(), b.getSize()))
            mem.removeBlock(b, monitor)


def code_space():
    return currentProgram.getAddressFactory().getAddressSpace("CODE")


def add_block(name, addr, fb, file_off, length, overlay=False, writable=False):
    blk = currentProgram.getMemory().createInitializedBlock(
        name, code_space().getAddress(addr), fb, file_off, length, overlay)
    blk.setRead(True)
    blk.setWrite(writable)
    blk.setExecute(True)
    return blk


def label(addr, name):
    createLabel(code_space().getAddress(addr), name, True)


def run():
    oem_path = get_oem_path()
    print("OEM image: %s" % oem_path)

    payload = verify_oem_header(oem_path)
    file_size = os.path.getsize(oem_path)
    print("  file size = 0x%x (header.payload + 0x14 = 0x%x)" % (file_size, payload + 0x14))

    fb = make_file_bytes(oem_path)
    print("Created FileBytes (size 0x%x)" % fb.getSize())

    print("Clearing CODE-space placeholder blocks:")
    remove_code_blocks()

    common_file_off = OEM_HEADER_LEN
    banks_file_off  = OEM_HEADER_LEN + COMMON_LEN + SECOND_HEADER_LEN
    remaining       = file_size - banks_file_off
    n_full_banks    = remaining // BANK_LEN
    tail            = remaining - n_full_banks * BANK_LEN

    print("Layout plan:")
    print("  common      : code 0x0000..0x%04x  <-  file 0x%04x..0x%04x  (%d bytes)" % (
        COMMON_LEN - 1, common_file_off, common_file_off + COMMON_LEN - 1, COMMON_LEN))
    print("  banks       : %d full x 0x%x + tail 0x%x at file 0x%x" % (
        n_full_banks, BANK_LEN, tail, banks_file_off))

    add_block("common", 0x0000, fb, common_file_off, COMMON_LEN, overlay=False)
    print("  + common @ 0x0000")

    for i in range(n_full_banks):
        off = banks_file_off + i * BANK_LEN
        add_block("bank_%02d" % (i + 1), BANK_BASE, fb, off, BANK_LEN, overlay=True)
    if tail > 0:
        off = banks_file_off + n_full_banks * BANK_LEN
        add_block("bank_%02d" % (n_full_banks + 1), BANK_BASE, fb, off, tail, overlay=True)
    print("  + %d overlay bank block(s) at 0x4000" % (n_full_banks + (1 if tail else 0)))

    # 8051 reset and standard interrupt vectors.
    for off, nm in [(0x0000, "RESET"), (0x0003, "INT0"), (0x000B, "T0"),
                    (0x0013, "INT1"), (0x001B, "T1"), (0x0023, "SERIAL"),
                    (0x002B, "T2")]:
        try:
            label(off, "vec_%s" % nm)
        except Exception as e:
            print("  (label %s @ 0x%04x skipped: %s)" % (nm, off, e))

    # Annotate the bank-trampoline SFR per existing rtl837x_sfr.h (PSBANK @ 0x96)
    try:
        # The trampoline writes a bank number to SFR 0x96 before returning.
        # Mark address 0x0006 as the trampoline entry, matching the inline
        # `MOV 0x96, R7 ; RET` pattern observed at file offset 0x14+0x06.
        label(0x0006, "bank_trampoline")
    except Exception as e:
        print("  (bank_trampoline label skipped: %s)" % e)

    # Disassemble the reset vector so the listing has an entry-point.
    disassemble(code_space().getAddress(0x0000))

    print("Done. Use 'Symbol Tree' to navigate to vec_RESET / vec_*.")


run()
