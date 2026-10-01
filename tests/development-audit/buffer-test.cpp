#include "common.h"
#include "dasics_development_audit.h"
#include "difftest-dpic.h"

static void require(bool condition) {
  if (!condition) exit(91);
}

static void publish(unsigned slot, uint64_t pc, uint32_t instruction) {
  // Call the actual generated producer, including its valid-only publication.
  v_difftest_InstrCommit(0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        pc, instruction, 0, 0, 0, 0, 0, 0, 0, 0, slot);
}

static unsigned consume() {
  auto *frame = diffstate_buffer[0]->next();
  DasicsDevelopment::begin_frame(frame->regs_int.value);
  unsigned observed = 0;
  for (unsigned slot = 0; slot < CONFIG_DIFF_COMMIT_WIDTH; ++slot) {
    const auto &commit = frame->commit[slot];
    if (commit.valid) {
      DasicsDevelopment::retire(slot, commit.pc, commit.instr, commit.skip,
                                commit.nFused, frame->regs_int.value);
      ++observed;
    }
  }
  DasicsDevelopment::consume_no_diff(frame);
  require(!frame->event.valid && frame->regs_int.value[18] == 0x1234);
  return observed;
}

int main() {
  static_assert(CONFIG_DIFFTEST_BUFLEN == 1 && CONFIG_DIFFTEST_ZONESIZE == 1,
                "This test exercises the ordinary one-slot direct-DPIC buffer");
  DasicsDevelopment::initialize(false);
  diffstate_buffer_init();
  auto *buffer = diffstate_buffer[0]->get(0, 0);
  buffer->regs_int.value[18] = 0x1234;

  publish(1, 0x80000004, 0x13);
  v_difftest_ArchEvent(0, 2, 0x80000008, 0x73, 0, 0, 0, 0, 0, 0, 0);
  require(buffer->event.valid && consume() == 1);
  // No callback means no new retirement, including on later buffer reuse.
  require(consume() == 0 && consume() == 0);
  // Identical consecutive transactions must each be observed exactly once.
  publish(0, 0x80000000, 0x13);
  require(consume() == 1);
  publish(0, 0x80000000, 0x13);
  require(consume() == 1);
  require(consume() == 0);

  DasicsDevelopment::latch_trap(0x80000010, 0, 20, 4);
  require(consume() == 0);
  publish(0, 0x80000010, 0x0005006b);
  require(consume() == 1 && DasicsDevelopment::terminal());
  require(buffer->commit[0].pc == 0x80000010 && buffer->regs_int.value[18] == 0x1234);
  DasicsDevelopment::finish();
  diffstate_buffer_free();
  return 0;
}
