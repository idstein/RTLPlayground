# RTLPlayground — locate the RTL837x register-write helper and every callsite
# that targets the LED / pin-mux register block.
#
# How the SoC writes a register (from rtl837x_sfr.h):
#     SFR_REG_ADDR_U16 (0xA2:0xA3)  <- 16-bit register address
#     SFR_DATA_U32     (0xA4..0xA7) <- 32-bit value
#     SFR_EXEC_GO      (0xA0) = 3   <- triggers WRITE_REG
#
# So in 8051 assembly, every reg_write helper contains the literal byte
# sequence "75 A0 03" (MOV 0xA0, #3). This script:
#     1. Scans CODE bytes for that pattern.
#     2. For each hit, finds the containing function (after auto-analysis).
#     3. Lists callers and tries to extract the immediate register address
#        passed in DPTR — i.e. the last "MOV DPTR, #imm16" before the call.
#     4. Filters the resulting (caller, reg, function) tuples for LED / pin-mux
#        registers (0x6520..0x65FC, 0x654C, 0x7F8C/0x7F90/0x7F94).
#
# @author  RTLPlayground tooling
# @category RTL837x
# @runtime PyGhidra

from ghidra.program.model.symbol import RefType


SFR_EXEC_GO    = 0xA0
SFR_EXEC_WRITE = 0x03
TRIGGER_BYTES  = bytes([0x75, SFR_EXEC_GO, SFR_EXEC_WRITE])  # MOV 0xA0, #3

INTERESTING = {
    0x6520: "LED_MODE",
    0x6524: "LED3_0_SET3", 0x6528: "LED3_0_SET1",
    0x652C: "LED3_2_SET3", 0x6530: "LED1_0_SET3",
    0x6534: "LED3_2_SET2", 0x6538: "LED1_0_SET2",
    0x653C: "LED3_2_SET1", 0x6540: "LED1_0_SET1",
    0x6544: "LED3_2_SET0", 0x6548: "LED1_0_SET0",
    0x654C: "LED_PORT_SET_SEL",
    0x65D8: "LED_GLB_ACTIVE", 0x65DC: "LED_GLB_IO_EN",
    0x65E0: "LED_GLB_MUX_1", 0x65E4: "LED_GLB_MUX_2",
    0x65E8: "LED_GLB_MUX_3", 0x65EC: "LED_GLB_MUX_4",
    0x65F0: "LED_GLB_MUX_5", 0x65F4: "LED_GLB_MUX_6",
    0x65F8: "LED_RLDP_1",    0x65FC: "LED_RLDP_2",
    0x7F8C: "PIN_MUX_0",     0x7F90: "PIN_MUX_1",     0x7F94: "PIN_MUX_2",
}


def code_space():
    return currentProgram.getAddressFactory().getAddressSpace("CODE")


def scan_trigger():
    """Return every address whose first three bytes are 75 A0 03."""
    mem = currentProgram.getMemory()
    hits = []
    for blk in mem.getBlocks():
        if blk.getStart().getAddressSpace() != code_space():
            continue
        if not blk.isInitialized():
            continue
        # Use findBytes to walk the block.
        addr = blk.getStart()
        end  = blk.getEnd()
        while True:
            found = mem.findBytes(addr, end, TRIGGER_BYTES, None, True, monitor)
            if found is None:
                break
            hits.append(found)
            addr = found.add(1)
            if addr.compareTo(end) > 0:
                break
    return hits


def containing_function(addr):
    return currentProgram.getFunctionManager().getFunctionContaining(addr)


def last_dptr_load_before(call_addr, scan_back=32):
    """Walk backwards up to `scan_back` instructions; return the imm16 of
    the most recent `MOV DPTR, #imm16` (opcode 0x90) instruction."""
    listing = currentProgram.getListing()
    instr   = listing.getInstructionBefore(call_addr)
    steps   = 0
    while instr is not None and steps < scan_back:
        b0 = instr.getByte(0) & 0xff
        if b0 == 0x90:
            hi = instr.getByte(1) & 0xff
            lo = instr.getByte(2) & 0xff
            return (hi << 8) | lo, instr.getAddress()
        instr = instr.getPrevious()
        steps += 1
    return None, None


def run():
    print("Scanning for MOV 0xA0,#3 (WRITE_REG trigger)...")
    triggers = scan_trigger()
    print("  found %d trigger sites" % len(triggers))

    helpers = {}
    for t in triggers:
        fn = containing_function(t)
        if fn is None:
            # Probably inlined or in a region without function bounds; skip.
            continue
        helpers.setdefault(fn.getEntryPoint(), fn)

    print("Candidate register-write helpers (functions containing the trigger):")
    for entry, fn in helpers.items():
        nrefs = len(list(currentProgram.getReferenceManager()
                         .getReferencesTo(fn.getEntryPoint())))
        print("  %s  @ %s   xrefs=%d" % (fn.getName(), entry, nrefs))

    rows = []  # (helper_name, caller_fn, call_addr, reg, dptr_addr)
    rm = currentProgram.getReferenceManager()
    for entry, fn in helpers.items():
        for ref in rm.getReferencesTo(entry):
            if ref.getReferenceType() not in (RefType.UNCONDITIONAL_CALL,
                                              RefType.CONDITIONAL_CALL):
                continue
            call_addr = ref.getFromAddress()
            caller    = containing_function(call_addr)
            reg, dptr_a = last_dptr_load_before(call_addr)
            rows.append((fn.getName(),
                         caller.getName() if caller else "?",
                         call_addr, reg, dptr_a))

    print("\nAll callers (truncated to first 40):")
    for h, c, a, reg, _ in rows[:40]:
        reg_s = "0x%04x" % reg if reg is not None else "<no-imm>"
        print("  %s called from %s @ %s   DPTR=%s" % (h, c, a, reg_s))

    print("\nMatches in LED / pin-mux register block:")
    matches = [r for r in rows if r[3] in INTERESTING]
    for h, c, a, reg, dptr_a in matches:
        print("  reg 0x%04x %-18s  caller=%s  call@%s  dptr@%s" % (
            reg, INTERESTING[reg], c, a, dptr_a))
    print("\nTotal LED/pin-mux hits: %d" % len(matches))


run()
