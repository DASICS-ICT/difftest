#include "refproxy.h"
#include "dasics_development_audit.h"
#include <array>
#include <cstdarg>

bool sim_verbose = false;
int eprintf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  const int rc = vfprintf(stderr, format, args);
  va_end(args);
  return rc;
}

static void require(bool condition) {
  if (!condition) exit(91);
}

int main(int argc, char **argv) {
  require(argc == 3);
  const bool no_diff = !strncmp(argv[2], "no-diff", 7);
  DasicsDevelopment::initialize(!no_diff);
  std::array<uint64_t, 32> gpr{};
  if (!no_diff) {
    difftest_ref_so = argv[1];
    NemuProxy proxy(0, 0);
    DiffTestState dut{};
    std::array<uint64_t, 175> words;
    for (size_t i = 0; i < words.size(); ++i) words[i] = UINT64_C(0xa700000000000000) + i;
    memcpy(&dut.regs_int, words.data(), 256);
    memcpy(&dut.regs_fp, words.data() + 32, 256);
    memcpy(&dut.csr, words.data() + 64, 144);
    dut.commit[0].pc = words[82];
    memcpy(&dut.hcsr, words.data() + 83, 136);
    memcpy(&dut.regs_vec, words.data() + 100, 512);
    memcpy(&dut.vcsr, words.data() + 164, 56);
    memcpy(&dut.fcsr, words.data() + 171, 8);
    memcpy(&dut.triggercsr, words.data() + 172, 24);
    proxy.regcpy(&dut);
    if (!strcmp(argv[2], "runtime-import")) proxy.sync(true);
    proxy.sync();
    require(proxy.get_reg_size() == 1400);
    require(proxy.pc == UINT64_C(0xb800000000000000) + 82);
    require(proxy.regs_vec.value[63] == UINT64_C(0xb800000000000000) + 163);
    require(proxy.triggercsr.tinfo == UINT64_C(0xb800000000000000) + 174);
    for (size_t i = 0; i < gpr.size(); ++i) {
      require(proxy.regs_int.value[i] == UINT64_C(0xb800000000000000) + i);
      gpr[i] = proxy.regs_int.value[i];
    }
  }
  DasicsDevelopment::begin_frame(gpr.data());
  if (strcmp(argv[2], "missing-trap")) DasicsDevelopment::latch_trap(0x80000000, 0, 12, 4);
  if (!strcmp(argv[2], "duplicate-trap")) DasicsDevelopment::latch_trap(0x80000000, 0, 12, 4);
  // An unrelated successful comparison cannot consume an early trap packet.
  if (!no_diff) DasicsDevelopment::comparison(0x7ffffffc, 0x7ffffffc, 0x7ffffffc, false,
                                             true, gpr.data(), gpr.data());
  require(!DasicsDevelopment::terminal());
  const unsigned delay = !strcmp(argv[2], "terminal-timeout") ? 17 :
                         !strcmp(argv[2], "max-delay") ? 16 : 3;
  for (unsigned i = 0; i < delay; ++i) DasicsDevelopment::begin_frame(gpr.data());
  const uint64_t terminal_pc = !strcmp(argv[2], "wrong-terminal-pc") ? 0x80000004 : 0x80000000;
  const uint32_t terminal_instruction = !strcmp(argv[2], "wrong-terminal-instruction") ? 0x13 : 0x0005006b;
  DasicsDevelopment::retire(0, terminal_pc, terminal_instruction,
                            !strcmp(argv[2], "terminal-skip"), !strcmp(argv[2], "terminal-fused"), gpr.data());
  if (!strcmp(argv[2], "younger-retirement"))
    DasicsDevelopment::retire(1, 0x80000004, 0x13, false, 0, gpr.data());
  if (!no_diff) {
    if (strcmp(argv[2], "missing-terminal-exec"))
      DasicsDevelopment::ref_exec(0, 0x80000000, 0x0005006b, 0, 0);
    DasicsDevelopment::comparison(0x80000000, 0x80000000, 0x80000000, false,
                                  strcmp(argv[2], "failed-compare") != 0, gpr.data(), gpr.data(),
                                  !strcmp(argv[2], "state-adjusted"));
    if (!strcmp(argv[2], "stale-compare")) --DasicsDevelopment::state().compare_frame;
  }
  require(DasicsDevelopment::terminal());
  require(DasicsDevelopment::state().trap_frame == 1 &&
          DasicsDevelopment::state().terminal_retire_frame == 1 + delay);
  DasicsDevelopment::finish();
  return 0;
}
