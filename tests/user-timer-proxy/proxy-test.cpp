#include "refproxy.h"
#include <array>
#include <cstdarg>

bool sim_verbose = false;
int eprintf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  const int result = vfprintf(stderr, format, args);
  va_end(args);
  return result;
}

static void require(bool condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "PROXY_UNIT_FAILURE: %s\n", message);
    exit(91);
  }
}

static void initialize_dut(DiffTestState &dut) {
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
}

static void check_export(const void *input, size_t bytes, size_t first) {
  const auto *words = static_cast<const uint64_t *>(input);
  for (size_t i = 0; i < bytes / sizeof(uint64_t); ++i)
    require(words[i] == UINT64_C(0xb800000000000000) + first + i, "legacy export word");
}

static void reference_snapshot(const RefProxy &proxy, DiffTestState &snapshot) {
  snapshot.regs_int = proxy.regs_int;
  snapshot.regs_fp = proxy.regs_fp;
  snapshot.regs_vec = proxy.regs_vec;
  snapshot.csr = proxy.csr;
  snapshot.hcsr = proxy.hcsr;
  snapshot.vcsr = proxy.vcsr;
  snapshot.fcsr = proxy.fcsr;
  snapshot.triggercsr = proxy.triggercsr;
  snapshot.commit[0].pc = proxy.pc;
}

int main(int argc, char **argv) {
  require(argc == 3, "expected shared library path and case");
  difftest_ref_so = argv[1];
  const char *test = argv[2];
  const int hart = !strcmp(test, "bad_hart") ? 1 : 0;
  NemuProxy proxy(hart, 0);
  if (!strcmp(test, "constructor")) return 0;

  char *resolved = realpath(argv[1], nullptr);
  require(resolved && proxy.reference_path() == resolved, "actual reference path");
  free(resolved);
  require(proxy.uit_caps().version == DIFFTEST_UIT_VERSION && proxy.uit_caps().legacy_regcpy_bytes == 1400,
          "read-only capabilities");
  DiffTestState dut{};
  initialize_dut(dut);
  proxy.regcpy(&dut);
  require(proxy.get_reg_size() == 1400, "legacy size");
  const uint32_t required = !strcmp(test, "disabled_init") ? DIFFTEST_UIT_F_UART_TX : DIFFTEST_UIT_FEATURES;
  require(proxy.uit_init(7, required) == DIFFTEST_UIT_OK, "UIT init and initial import");
  if (!strcmp(test, "disabled_init")) {
    require(proxy.uit_caps().enabled_features == DIFFTEST_UIT_F_UART_TX, "disabled capabilities");
    puts("PROXY_ABI_UNIT_DISABLED_INIT_PASS: fake reference; no DUT or ISA execution");
    return 0;
  }
  if (!strcmp(test, "runtime_sync_import")) {
    proxy.sync(true);
    require(false, "runtime sync import accepted");
  }
  if (!strcmp(test, "runtime_regcpy_import")) {
    proxy.regcpy(&dut);
    require(false, "runtime regcpy import accepted");
  }
  proxy.sync();
  check_export(&proxy.regs_int, 256, 0);
  check_export(&proxy.regs_fp, 256, 32);
  check_export(&proxy.csr, 144, 64);
  check_export(&proxy.pc, 8, 82);
  check_export(&proxy.hcsr, 136, 83);
  check_export(&proxy.regs_vec, 512, 100);
  check_export(&proxy.vcsr, 56, 164);
  check_export(&proxy.fcsr, 8, 171);
  check_export(&proxy.triggercsr, 24, 172);

  DifftestUitExecRequest request{};
  request.version = DIFFTEST_UIT_VERSION;
  request.bytes = sizeof(request);
  request.epoch = 7;
  request.transaction_uid = 41;
  request.control_seq = 1;
  request.kind = DIFFTEST_UIT_CSR;
  request.instruction = 0x800020f3;
  request.csr = 0x800;
  request.funct3 = 2;
  request.sample_kind = DIFFTEST_UIT_TIMER_SAMPLE;
  request.sample_payload = 19;
  DifftestUitExecResult result{};
  DifftestUitHUEvent event{};
  event.version = DIFFTEST_UIT_VERSION;
  event.bytes = sizeof(event);
  event.epoch = 7;
  event.event_uid = 42;
  event.boundary_pc = 0x80000002;
  DifftestUitState state{};
  DifftestUitTx tx{};
  require(proxy.uit_exec(request, result) == 0 && result.epoch == 7 && result.transaction_uid == 41 &&
          result.control_seq == 1 && result.sample_consumed == 1, "exec request/result transfer");
  require(proxy.uit_event(event) == 0, "event request transfer");
  require(proxy.uit_state(state) == 0 && state.version == DIFFTEST_UIT_VERSION && state.bytes == sizeof(state) &&
          state.epoch == 7 && state.ustatus == 0x11 && state.uie == 0x12 && state.utvec == 0x13 &&
          state.uscratch == 0x14 && state.uepc == 0x15 && state.ucause == 0x16 && state.utval == 0x17 &&
          state.pc == 0x80000002 && state.in_handler == 1, "separate U-state output");
  require(proxy.uit_tx(tx) == 0 && tx.version == DIFFTEST_UIT_VERSION && tx.bytes == sizeof(tx) &&
          tx.epoch == 7 && tx.tx_seq == 1 && tx.address == DIFFTEST_UIT_UART_TX && tx.data == 'Z' && tx.len == 1,
          "UART output transfer");
  if (!strncmp(test, "compare_", 8)) {
    // This path invokes the production memcmp comparator, with no comparison spy.
    reference_snapshot(proxy, dut);
    DiffTestState reference_before{}, reference_after{};
    reference_snapshot(proxy, reference_before);
    const auto sample_before = request;
    require(proxy.compare(&dut) == 0, "matching architectural snapshot before mutation");
    if (!strcmp(test, "compare_gpr")) dut.regs_int.value[1] ^= 1;
    else if (!strcmp(test, "compare_fp")) dut.regs_fp.value[1] ^= 1;
    else if (!strcmp(test, "compare_vector")) dut.regs_vec.value[2] ^= 1;
    else if (!strcmp(test, "compare_csr")) dut.csr.mscratch ^= 1;
    else if (!strcmp(test, "compare_hcsr")) dut.hcsr.hstatus ^= 1;
    else if (!strcmp(test, "compare_vcsr")) dut.vcsr.vstart ^= 1;
    else if (!strcmp(test, "compare_fcsr")) dut.fcsr.fcsr ^= 1;
    else if (!strcmp(test, "compare_trigger")) dut.triggercsr.tdata1 ^= 1;
    else require(false, "known production comparison case");
    const int comparison = proxy.compare(&dut);
    reference_snapshot(proxy, reference_after);
    require(comparison == 1, "production comparator rejects changed DUT architecture");
    require(!memcmp(&request, &sample_before, sizeof(request)), "previously submitted controlled sample unchanged");
    require(!memcmp(&reference_before, &reference_after, sizeof(reference_before)), "reference state unchanged");
    fprintf(stderr, "REAL_REFPROXY_COMPARE_REJECT: %s sample_unchanged=true reference_unchanged=true\n", test);
    return comparison;
  }
  check_export(&proxy.regs_int, 256, 0);
  check_export(&proxy.csr, 144, 64);
  check_export(&proxy.pc, 8, 82);
  check_export(&proxy.triggercsr, 24, 172);
  setenv("FAKE_UIT_API_RC", "-123", 1);
  require(proxy.uit_init(7) == -123 && proxy.uit_exec(request, result) == -123 &&
          proxy.uit_event(event) == -123 && proxy.uit_state(state) == -123 && proxy.uit_tx(tx) == -123,
          "int32_t error propagation");
  unsetenv("FAKE_UIT_API_RC");

  void *library = dlopen(argv[1], RTLD_NOW | RTLD_NOLOAD);
  require(library != nullptr, "loaded fake reference handle");
  const auto imports = reinterpret_cast<uint32_t (*)()>(dlsym(library, "fake_reference_imports"));
  const auto exports = reinterpret_cast<uint32_t (*)()>(dlsym(library, "fake_reference_exports"));
  require(imports && exports && imports() == 1 && exports() == 1, "exact legacy call counts");
  dlclose(library);
  puts("PROXY_ABI_UNIT_PASS: fake reference; no DUT or ISA execution");
  return 0;
}
