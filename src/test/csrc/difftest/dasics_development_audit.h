#ifndef DASICS_DEVELOPMENT_AUDIT_H
#define DASICS_DEVELOPMENT_AUDIT_H

#ifdef DASICS_DEVELOPMENT_AUDIT
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#if defined(CONFIG_DIFFTEST_USERTIMERACCESS) || defined(CONFIG_NO_DIFFTEST) || \
    defined(BASIC_DIFFTEST_ONLY) || defined(CONFIG_DIFFTEST_SQUASH) || \
    defined(CONFIG_DIFFTEST_REPLAY) || defined(CONFIG_DIFFTEST_BATCH) || \
    defined(CONFIG_DIFFTEST_DELTA) || defined(ENABLE_RUNAHEAD) || defined(ENABLE_RUNHEAD) || \
    defined(VM_SAVABLE) || defined(DEBUG_MODE_DIFF) || defined(LINKED_REFPROXY_LIB)
#error "Development audit requires ordinary direct-DPIC with a dynamic reference"
#endif
#if NUM_CORES != 1
#error "Development audit requires one hart"
#endif

namespace DasicsDevelopment {
// One process owns one trace. Frames follow the existing diffstate buffer;
// GPR values describe the whole architectural frame, never an individual slot.
struct Audit {
  FILE *stream = nullptr;
  const char *run_id = nullptr;
  bool enabled_diff = false;
  bool terminal_seen = false;
  bool finished = false;
  uint64_t frame = 0;
  uint64_t compare_frame = 0;
  bool compare_pass = false;
  uint64_t raw_gpr[32]{};
  // TrapEvent has no source delay, while InstrCommit is delayed three cycles.
  // Retain the packet until the matching retirement and comparison arrive.
  bool trap_pending = false;
  uint64_t trap_frame = 0;
  uint64_t trap_pc = 0;
  uint64_t trap_code = 0;
  uint64_t trap_cycles = 0;
  uint64_t trap_instructions = 0;
  uint64_t terminal_retire_frame = 0;
  unsigned terminal_slot = 0;
  unsigned terminal_execs = 0;
};

inline Audit &state() {
  static Audit audit;
  return audit;
}

[[noreturn]] inline void fail(const char *message) {
  fprintf(stderr, "Development audit rejected: %s\n", message);
  exit(EXIT_FAILURE);
}

inline void string(FILE *stream, const char *value) {
  fputc('"', stream);
  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(value); *p; ++p) {
    if (*p == '"' || *p == '\\') fprintf(stream, "\\%c", *p);
    else if (*p < 0x20) fprintf(stream, "\\u%04x", *p);
    else fputc(*p, stream);
  }
  fputc('"', stream);
}

inline FILE *event(const char *name) {
  auto &audit = state();
  if (!audit.stream || audit.finished) fail("trace is not active");
  fprintf(audit.stream, "{\"schema\":1,\"event\":\"%s\",\"run_id\":", name);
  string(audit.stream, audit.run_id);
  fprintf(audit.stream, ",\"pid\":%ld,\"core\":0,\"frame\":%" PRIu64,
          static_cast<long>(getpid()), audit.frame);
  return audit.stream;
}

inline void flush() {
  FILE *stream = state().stream;
  fputs("}\n", stream);
  if (ferror(stream) || fflush(stream)) fail("trace write failed");
}

inline void registers(FILE *stream, const char *name, const uint64_t *gpr) {
  fprintf(stream, ",\"%s\":[", name);
  for (int i = 0; i < 32; ++i) fprintf(stream, "%s\"0x%016" PRIx64 "\"", i ? "," : "", gpr[i]);
  fputc(']', stream);
}

inline void initialize(bool enabled_diff) {
  auto &audit = state();
  if (audit.stream) fail("duplicate initialization");
  const char *path = getenv("DASICS_DEVELOPMENT_TRACE");
  audit.run_id = getenv("DASICS_DEVELOPMENT_RUN_ID");
  if (!path || path[0] != '/' || !audit.run_id || !*audit.run_id || strlen(audit.run_id) > 128)
    fail("absolute trace path and bounded run identity are required");
  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(audit.run_id); *p; ++p)
    if (!isalnum(*p) && *p != '-' && *p != '_') fail("invalid run identity");
  const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) fail("trace must be a new regular file");
  audit.stream = fdopen(fd, "w");
  if (!audit.stream) { close(fd); fail("cannot open trace stream"); }
  audit.enabled_diff = enabled_diff;
  fprintf(event("start"), ",\"mode\":\"%s\"", enabled_diff ? "difftest" : "no-diff");
  flush();
}

inline void begin_frame(const uint64_t *gpr) {
  auto &audit = state();
  ++audit.frame;
  memcpy(audit.raw_gpr, gpr, sizeof(audit.raw_gpr));
  if (audit.trap_pending && audit.frame - audit.trap_frame > 16)
    fail("terminal retirement did not arrive within 16 frames");
  if (audit.terminal_retire_frame && audit.terminal_retire_frame != audit.frame)
    fail("terminal retirement frame was not accepted");
}

inline void latch_trap(uint64_t pc, uint64_t code, uint64_t cycles, uint64_t instructions) {
  auto &audit = state();
  if (audit.trap_pending || audit.terminal_seen) fail("duplicate terminal packet");
  audit.trap_pending = true;
  audit.trap_frame = audit.frame;
  audit.trap_pc = pc;
  audit.trap_code = code;
  audit.trap_cycles = cycles;
  audit.trap_instructions = instructions;
  fprintf(event("trap_latched"), ",\"pc\":\"0x%" PRIx64 "\",\"code\":%" PRIu64
          ",\"cycle_count\":%" PRIu64 ",\"instruction_count\":%" PRIu64,
          pc, code, cycles, instructions);
  flush();
}

inline void retire(unsigned slot, uint64_t pc, uint32_t instruction, bool skip, unsigned n_fused,
                   const uint64_t *gpr) {
  auto &audit = state();
  if (audit.terminal_retire_frame == audit.frame && audit.terminal_retire_frame)
    fail("instruction retired after the terminal slot");
  if (instruction == 0x0005006b || (audit.trap_pending && pc == audit.trap_pc)) {
    if (!audit.trap_pending || pc != audit.trap_pc || instruction != 0x0005006b || skip || n_fused)
      fail("terminal retirement does not match the retained packet");
    audit.terminal_retire_frame = audit.frame;
    audit.terminal_slot = slot;
  }
  FILE *stream = event("retire");
  fprintf(stream, ",\"slot\":%u,\"pc\":\"0x%" PRIx64 "\",\"instruction\":\"0x%08x\","
          "\"skip\":%s,\"n_fused\":%u,\"gpr_scope\":\"frame_architectural\"",
          slot, pc, instruction, skip ? "true" : "false", n_fused);
  registers(stream, "gpr", gpr);
  flush();
}

inline void ref_exec(unsigned slot, uint64_t pc, uint32_t instruction, unsigned n_fused, unsigned index) {
  auto &audit = state();
  if (audit.terminal_retire_frame == audit.frame && slot == audit.terminal_slot) {
    if (pc != audit.trap_pc || instruction != 0x0005006b || n_fused || index || audit.terminal_execs++)
      fail("reference terminal execution does not match retirement");
  }
  fprintf(event("ref_exec"), ",\"slot\":%u,\"pc\":\"0x%" PRIx64 "\","
          "\"instruction\":\"0x%08x\",\"n_fused\":%u,\"index\":%u,\"skip\":false",
          slot, pc, instruction, n_fused, index);
  flush();
}

inline void comparison(uint64_t pc, uint64_t dut_pc, uint64_t ref_pc, bool pc_mismatch,
                       bool passed, const uint64_t *gpr, const uint64_t *ref_gpr, bool state_adjusted = false) {
  auto &audit = state();
  audit.compare_frame = audit.frame;
  audit.compare_pass = passed && !state_adjusted;
  FILE *stream = event("compare");
  fprintf(stream, ",\"pc\":\"0x%" PRIx64 "\",\"dut_pc\":\"0x%" PRIx64 "\","
          "\"ref_pc\":\"0x%" PRIx64 "\",\"pc_mismatch\":%s,\"pass\":%s,\"state_adjusted\":%s",
          pc, dut_pc, ref_pc, pc_mismatch ? "true" : "false", audit.compare_pass ? "true" : "false",
          state_adjusted ? "true" : "false");
  registers(stream, "gpr", gpr);
  registers(stream, "ref_gpr", ref_gpr);
  flush();
  if (state_adjusted) fail("comparison replaced raw DUT register state");
}

inline bool terminal() {
  auto &audit = state();
  if (!audit.trap_pending || audit.terminal_retire_frame != audit.frame) return false;
  if (audit.terminal_seen) fail("duplicate terminal frame");
  if (audit.enabled_diff && (audit.terminal_execs != 1 ||
      audit.compare_frame != audit.frame || !audit.compare_pass))
    fail("terminal retirement was not executed and compared in its frame");
  audit.terminal_seen = true;
  FILE *stream = event("terminal");
  fprintf(stream, ",\"pc\":\"0x%" PRIx64 "\",\"code\":%" PRIu64 ",\"mode\":\"%s\","
          "\"cycle_count\":%" PRIu64 ",\"instruction_count\":%" PRIu64 ","
          "\"compare_frame\":%" PRIu64 ",\"compare_pass\":%s,\"trap_frame\":%" PRIu64
          ",\"retire_frame\":%" PRIu64,
          audit.trap_pc, audit.trap_code, audit.enabled_diff ? "difftest" : "no-diff",
          audit.trap_cycles, audit.trap_instructions, audit.compare_frame,
          audit.compare_pass ? "true" : "false", audit.trap_frame, audit.terminal_retire_frame);
  registers(stream, "gpr", audit.raw_gpr);
  flush();
  return true;
}

inline void consume_no_diff(DiffTestState *frame) {
  if (state().enabled_diff) fail("no-diff consumption during comparison");
  // Direct-DPIC publishes only valid packets into a reused buffer. A consumer
  // acknowledges each packet by clearing valid after observation; a later
  // callback may publish a new transaction with exactly the same PC and data.
  for (auto &commit : frame->commit) commit.valid = false;
  frame->event.valid = false;
}

inline void finish() {
  auto &audit = state();
  fprintf(event("end"), ",\"terminal_seen\":%s,\"mode\":\"%s\"",
          audit.terminal_seen ? "true" : "false", audit.enabled_diff ? "difftest" : "no-diff");
  flush();
  audit.finished = true;
  if (fclose(audit.stream)) fail("trace close failed");
}
} // namespace DasicsDevelopment
#endif
#endif
