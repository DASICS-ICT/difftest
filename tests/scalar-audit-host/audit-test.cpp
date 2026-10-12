#include <cstdint>

struct DiffTestState {
  struct { uint64_t value[32]; } regs_int{};
  struct { uint64_t cycle; } uit_clock{};
  struct { bool valid; uint64_t addr, data; uint8_t mask; uint64_t pc; uint16_t robidx; } store[2]{};
  struct { bool hasTrap; uint64_t pc, code, cycleCnt, instrCnt; } trap{};
  struct { bool valid; uint64_t exceptionPC; uint32_t exception, interrupt; } event{};
  struct { bool valid; uint64_t pc; uint32_t instr; bool skip; uint8_t nFused; uint16_t robIdx = 0; } commit[2]{};
};

#include "dasics_scalar_audit.h"

#ifndef SCALAR_AUDIT_GUARD_ONLY
static void require(bool condition) {
  if (!condition) exit(91);
}

static void observe(const DiffTestState &frame) {
  const auto original = frame;
  DasicsScalarAudit::observe(frame);
  require(!memcmp(&original, &frame, sizeof(frame)));
}

int main(int argc, char **argv) {
  require(argc == 2);
  const char *name = argv[1];
  const auto is = [name](const char *value) { return !strcmp(name, value); };
  const bool no_diff = is("no-diff") || is("load-in-no-diff") || is("incomplete-no-diff") || is("store-no-diff");
  DiffTestState frame{};
  if (is("observe-before-init")) observe(frame);
  if (is("load-before-init")) DasicsScalarAudit::mark_reference_loaded();
  DasicsScalarAudit::initialize(!no_diff);
  if (is("duplicate-init")) DasicsScalarAudit::initialize(!no_diff);
  if (!no_diff || is("load-in-no-diff")) {
    DasicsScalarAudit::mark_reference_loaded();
    if (is("duplicate-load")) DasicsScalarAudit::mark_reference_loaded();
    fputs(",\"path\":", DasicsScalarAudit::event("loaded"));
    DasicsScalarAudit::string(DasicsScalarAudit::state().stream, "fake-\"reference\\\n");
    DasicsScalarAudit::flush();
  }
  if (is("incomplete-diff") || is("incomplete-no-diff")) {
    observe(frame);
    DasicsScalarAudit::finish();
    return 0;
  }
  // A normal trap before the terminal packet remains an architectural event.
  frame.event = {true, 0x800000ab, 25, 0};
  observe(frame);
  frame.event.valid = false;
  frame.commit[0] = {true, 0x80000008, 0x13, false, 0};
  frame.commit[0].robIdx = 147;
  const bool store_case = !strncmp(name, "store-", 6);
  if (store_case) {
    frame.uit_clock.cycle = 223;
    frame.store[1] = {true, 0x800006a0, 0x0000221100000000,
                     static_cast<uint8_t>(is("store-zero-mask") ? 0 : 0x30), 0x80000024, 147};
    if (is("store-two-slots")) frame.store[0] = frame.store[1];
  }
  observe(frame);
  frame.commit[0].valid = false;
  frame.store[0].valid = frame.store[1].valid = false;
  if (!is("missing-trap")) frame.trap = {true, 0x80000010, 3, 73, 19};
  if (is("commit-before-trap")) {
    frame.trap.hasTrap = false;
    frame.commit[0] = {true, 0x80000010, 0x5006b, false, 0};
  }
  if (is("store-identical-packets")) { frame.store[1].valid = true; frame.uit_clock.cycle++; }
  observe(frame);
  frame.store[1].valid = false;
  if (is("duplicate-trap")) observe(frame);
  frame.trap.hasTrap = false;
  if (is("event-during-terminal")) {
    frame.event = {true, 0x80000010, 25, 0};
    observe(frame);
  }
  const unsigned delay = is("max-delay") ? 16 : is("terminal-timeout") ? 17 : 3;
  for (unsigned i = 1; i < delay; ++i) observe(frame);
  for (unsigned i = 0; i < 32; ++i) frame.regs_int.value[i] = 0xa700000000000000ULL + i;
  frame.commit[0] = {true, is("wrong-terminal-pc") ? 0x80000014ULL : 0x80000010ULL,
                     is("wrong-terminal-instruction") ? 0x13U : 0x5006bU,
                     is("terminal-skip"), static_cast<uint8_t>(is("terminal-fused"))};
  if (is("younger-retirement")) frame.commit[1] = {true, 0x80000014, 0x13, false, 0};
  if (is("store-at-terminal")) { frame.store[1].valid = true; frame.uit_clock.cycle++; }
  observe(frame);
  frame.store[1].valid = false;
  require(DasicsScalarAudit::state().terminal_seen && DasicsScalarAudit::state().terminal_code == 3);
  require(DasicsScalarAudit::state().trap_frame == 3);
  require(DasicsScalarAudit::state().terminal_retire_frame == 3 + delay);
  frame.commit[0].valid = false;
  frame.regs_int.value[10] = 0;
  // Empty frames are valid while the reference drains its retained UIT frames.
  if (is("store-after-terminal") || is("store-zero-after-terminal")) {
    frame.store[1].valid = true;
    if (is("store-zero-after-terminal")) frame.store[1].mask = 0;
  }
  observe(frame);
  require(DasicsScalarAudit::state().raw_gpr[10] == 0xa70000000000000aULL);
  if (is("retire-after-terminal")) {
    frame.commit[0] = {true, 0x80000014, 0x13, false, 0};
    observe(frame);
  }
  if (is("trap-after-terminal")) {
    frame.trap.hasTrap = true;
    observe(frame);
  }
  DasicsScalarAudit::finish();
  if (is("observe-after-finish")) observe(frame);
  if (is("duplicate-finish")) DasicsScalarAudit::finish();
  if (is("load-after-finish")) DasicsScalarAudit::mark_reference_loaded();
  return 0;
}
#endif
