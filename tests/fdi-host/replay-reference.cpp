#include "refproxy.h"
#include <cstdarg>
#include <deque>
#include <fstream>
#include <iterator>

bool sim_verbose = false;
int eprintf(const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  const int result = vfprintf(stderr, format, arguments);
  va_end(arguments);
  return result;
}

static void require(bool value, const char *reason) {
  if (!value) { fprintf(stderr, "FDI_REAL_REPLAY_FAILURE: %s\n", reason); exit(1); }
}

static void words(FILE *trace, const DifftestFdiState &state) {
  fputc('[', trace);
  for (size_t word = 0; word < 52; ++word)
    fprintf(trace, "%s\"0x%016lx\"", word ? "," : "", state.words[word]);
  fputc(']', trace);
}

int main(int argc, char **argv) {
  require(argc == 5, "reference library, normalized observations, fixed program image, output trace required");
  difftest_ref_so = argv[1];
  std::ifstream input(argv[2]);
  std::ifstream binary(argv[3], std::ios::binary);
  require(input.good() && binary.good(), "open immutable replay inputs");
  const std::vector<uint8_t> image{std::istreambuf_iterator<char>(binary), std::istreambuf_iterator<char>()};
  require(image.size() == 104 * 4, "fixed CSR program contains 104 instructions");
  FILE *trace = fopen(argv[4], "wx");
  require(trace != nullptr, "new output trace required");

  // Constructing the real production proxy captures the reference's natural
  // reset before any register import. Program bytes are shared test inputs,
  // never reconstructed from the observed DUT instruction or state values.
  NemuProxy proxy(0, 0);
  proxy.mem_init(UINT64_C(0x80000000), const_cast<uint8_t *>(image.data()), image.size(), DUT_TO_REF);
  FdiLedger ledger;
  std::deque<FdiBoundary> retirements;
  bool started = false;
  uint64_t executions = 0, last_cycle = 0;

  char marker;
  while (input >> marker) {
    require(marker == 'F', "normalized frame marker");
    uint64_t cycle;
    size_t observation_count, retirement_count;
    require(bool(input >> cycle >> observation_count >> retirement_count), "frame header");
    require(cycle >= last_cycle && observation_count <= 4 && retirement_count <= 1, "local frame shape");
    last_cycle = cycle;
    std::vector<FdiObservation> observations;
    for (size_t item = 0; item < observation_count; ++item) {
      FdiObservation packet;
      unsigned kind, rob_flag, read_needed, write_needed, permitted, actual_write, illegal, virtual_fault, cancel;
      require(bool(input >> kind >> packet.epoch >> packet.uid >> packet.cycle >> packet.pc >> packet.eventSeq >>
                   packet.beforeCount >> packet.instruction >> packet.robIdx >> packet.csrAddress >> rob_flag >>
                   read_needed >> write_needed >> permitted >> actual_write >> illegal >> virtual_fault >> cancel),
              "observation metadata");
      require(kind >= FDI_RESET && kind <= FDI_CSR_POST && packet.cycle == cycle,
              "fixed M-mode replay contains only reset and CSR observations");
      packet.kind = kind; packet.robFlag = rob_flag; packet.readNeeded = read_needed; packet.writeNeeded = write_needed;
      packet.permitted = permitted; packet.actualWrite = actual_write; packet.responseIllegal = illegal;
      packet.responseVirtual = virtual_fault; packet.cancelReason = cancel;
      for (auto &word : packet.words) require(bool(input >> word), "all 52 raw words present");
      observations.push_back(packet);
    }
    require(!ledger.observe_frame(observations), "real observation frame rejected by production ledger");
    if (ledger.has_reset() && !started) {
      require(!proxy.fdi.verify_dut_reset(ledger.natural_reset(), ledger.epoch()), "independent natural resets");
      proxy.sync();
      require(proxy.csr.privilegeMode == 3, "natural reference starts in M mode");
      for (size_t reg = 0; reg < 32; ++reg) proxy.regs_int.value[reg] = 0;
      proxy.regs_int.value[1] = UINT64_MAX;
      proxy.pc = UINT64_C(0x80000000);
      proxy.sync(DUT_TO_REF);
      require(!proxy.fdi.initialize(), "bind FDI after the single ordinary startup import");
      require(proxy.uit_init(ledger.epoch(), proxy.uit_caps().enabled_features) == DIFFTEST_UIT_OK,
              "existing controlled-input initialization preserves the FDI bank");
      started = true;
      fprintf(trace, "{\"type\":\"initialization\",\"epoch\":%lu,\"initial_regcpy_imports\":1,\"fdi_imports\":0,"
              "\"reference_reset_pc\":\"0x%lx\",\"initial_pc\":\"0x80000000\",\"initial_x1\":\"0xffffffffffffffff\"}\n",
              ledger.epoch(), proxy.fdi.natural_reset_pc());
    }
    for (size_t item = 0; item < retirement_count; ++item) {
      FdiBoundary boundary;
      unsigned rob_flag;
      require(bool(input >> boundary.epoch >> boundary.uid >> boundary.pc >> boundary.instruction >> boundary.robIdx >>
                   rob_flag >> boundary.beforeCount >> boundary.afterCount), "actual retirement identity");
      boundary.robFlag = rob_flag;
      retirements.push_back(boundary);
    }
    while (!retirements.empty() && ledger.ready(retirements.front().uid, retirements.front().instruction)) {
      require(started && executions < 104, "reference execution only inside the initialized fixed program");
      const auto boundary = retirements.front();
      const size_t offset = executions * 4;
      const uint32_t instruction = uint32_t(image[offset]) | uint32_t(image[offset + 1]) << 8 |
                                   uint32_t(image[offset + 2]) << 16 | uint32_t(image[offset + 3]) << 24;
      require(boundary.pc == UINT64_C(0x80000000) + offset && boundary.instruction == instruction &&
              boundary.beforeCount == executions && boundary.afterCount == executions + 1,
              "retirement belongs to the independently loaded program image");
      DifftestFdiState before{}, after{};
      require(!proxy.fdi.read(before) && !ledger.before(boundary, before, false), "independent pre-state comparison");
      proxy.ref_exec(1);
      ++executions;
      require(!proxy.fdi.read(after), "read-only reference state after one real instruction");
      const bool equal = !ledger.after(after);
      fprintf(trace, "{\"type\":\"comparison\",\"uid\":%lu,\"pc\":\"0x%lx\",\"instruction\":\"0x%08x\","
              "\"reference_exec_calls\":%lu,\"pass\":%s,\"before\":", boundary.uid, boundary.pc,
              instruction, executions, equal ? "true" : "false");
      words(trace, before); fputs(",\"after\":", trace); words(trace, after); fputs("}\n", trace); fflush(trace);
      require(equal && after.model_pc == boundary.pc + 4, "independently executed reference post-state");
      proxy.sync();
      require(proxy.regs_int.value[1] == UINT64_MAX && proxy.csr.privilegeMode == 3,
              "program preserves its fixed source operand and M mode");
      retirements.pop_front();
    }
  }
  require(input.eof() && started && executions == 104 && retirements.empty() && !ledger.finalize(),
          "all real transactions and reference executions close exactly once");
  fprintf(trace, "{\"type\":\"summary\",\"status\":\"PASS\",\"scope\":\"real_local_CSR_observer_reference_replay\","
          "\"full_processor_execution\":false,\"retirements\":104,\"reference_exec_calls\":%lu,"
          "\"initial_regcpy_imports\":1,\"fdi_imports\":0}\n", executions);
  fclose(trace);
  puts("FDI_REAL_LOCAL_REFERENCE_REPLAY_PASS");
  return 0;
}
