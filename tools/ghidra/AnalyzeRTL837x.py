# RTLPlayground — kick off auto-analysis with boot-vector hints.
#
# Run from the Script Manager AFTER LoadRTL837xOEM.py has built the memory map.
# It disassembles the targets of the 8051 reset / INT0 / T0 LJMP entries (read
# straight out of the file by LoadRTL837xOEM at 0x0000 / 0x0003 / 0x000B),
# marks them as functions so Ghidra's analyzer treats them as entry points,
# and then triggers a full auto-analysis pass. With banking + 0xC000 overlays
# this still won't follow cross-bank LJMPs perfectly, but it's a big step up
# from "nothing has functions".
#
# @author  RTLPlayground tooling
# @category RTL837x
# @runtime PyGhidra

import time
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.program.model.listing import Function


def code_space():
    return currentProgram.getAddressFactory().getAddressSpace("CODE")


def ljmp_target(addr_off):
    """Read a 16-bit big-endian operand from the byte after an 8051 LJMP (0x02)."""
    mem = currentProgram.getMemory()
    base = code_space().getAddress(addr_off)
    if mem.getByte(base) & 0xff != 0x02:
        return None
    hi = mem.getByte(base.add(1)) & 0xff
    lo = mem.getByte(base.add(2)) & 0xff
    return (hi << 8) | lo


def disasm(addr_off):
    addr = code_space().getAddress(addr_off)
    if currentProgram.getMemory().contains(addr):
        try:
            disassemble(addr)
        except Exception:
            pass


def ensure_function(addr_off, name):
    addr = code_space().getAddress(addr_off)
    if not currentProgram.getMemory().contains(addr):
        print("  (0x%04x out of range, skipped)" % addr_off)
        return
    disasm(addr_off)
    fn = currentProgram.getFunctionManager().getFunctionAt(addr)
    if fn is None:
        try:
            fn = createFunction(addr, name)
        except Exception as e:
            print("  createFunction(0x%04x, %s) failed: %s" % (addr_off, name, e))
            return
    else:
        try:
            fn.setName(name, fn.getSymbol().getSource())
        except Exception:
            pass
    print("  function %-20s @ 0x%04x" % (name, addr_off))


def run():
    print("Disassembling boot/IRQ vectors at 0x0000..0x002B")
    for off in [0x0000, 0x0003, 0x000B, 0x0013, 0x001B, 0x0023, 0x002B]:
        disasm(off)

    # Standard 8051 vector slots. We read the LJMP operand at each slot and
    # turn the target into a named function entry point.
    vectors = [
        (0x0000, "vec_RESET",  "reset_entry"),
        (0x0003, "vec_INT0",   "isr_int0"),
        (0x000B, "vec_T0",     "isr_t0"),
        (0x0013, "vec_INT1",   "isr_int1"),
        (0x001B, "vec_T1",     "isr_t1"),
        (0x0023, "vec_SERIAL", "isr_serial"),
        (0x002B, "vec_T2",     "isr_t2"),
    ]

    print("Resolving LJMP targets from the vector table:")
    for slot, vec_name, target_name in vectors:
        tgt = ljmp_target(slot)
        if tgt is None:
            print("  %-12s @ 0x%04x: not an LJMP, skipping" % (vec_name, slot))
            continue
        print("  %-12s @ 0x%04x -> 0x%04x  (will name '%s')" % (
            vec_name, slot, tgt, target_name))
        ensure_function(tgt, target_name)

    # The inline bank trampoline at 0x0006 (MOV PSBANK,R7 ; RET) — mark it
    # as a function too so cross-bank callers light up as references.
    ensure_function(0x0006, "bank_trampoline")

    print("Triggering auto-analysis... (this may take a few minutes)")
    mgr = AutoAnalysisManager.getAnalysisManager(currentProgram)
    mgr.reAnalyzeAll(None)
    mgr.startAnalysis(monitor)
    while mgr.isAnalyzing():
        monitor.checkCancelled()
        time.sleep(1)

    n_funcs = currentProgram.getFunctionManager().getFunctionCount()
    print("Auto-analysis complete. Functions defined: %d" % n_funcs)


run()
