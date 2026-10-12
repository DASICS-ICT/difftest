#ifndef DASICS_SCALAR_AUDIT_H
#define DASICS_SCALAR_AUDIT_H

#ifdef DASICS_SCALAR_COMPARE
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(CONFIG_DIFFTEST_USERTIMERACCESS) || !defined(CONFIG_DIFFTEST_FDIOBSERVATION) || \
    !defined(CONFIG_DIFFTEST_HCSRSTATE) || !defined(CONFIG_DIFFTEST_STOREEVENT)
#error "Scalar comparison audit requires the UIT, FDI, HCSR and Store observation interfaces"
#endif
#if defined(DASICS_DEVELOPMENT_AUDIT) || defined(CONFIG_NO_DIFFTEST) || \
    defined(BASIC_DIFFTEST_ONLY) || defined(CONFIG_DIFFTEST_SQUASH) || \
    defined(CONFIG_DIFFTEST_REPLAY) || defined(CONFIG_DIFFTEST_BATCH) || \
    defined(CONFIG_DIFFTEST_DELTA) || defined(ENABLE_RUNAHEAD) || defined(ENABLE_RUNHEAD) || \
    defined(VM_SAVABLE) || defined(DEBUG_MODE_DIFF) || defined(LINKED_REFPROXY_LIB) || \
    defined(CONFIG_PLATFORM_FPGA)
#error "Scalar comparison audit requires direct-DPIC without restore or execution compression"
#endif
#if !defined(NUM_CORES) || NUM_CORES != 1
#error "Scalar comparison audit requires one hart"
#endif

namespace DasicsScalarAudit {
// Raw observations never execute the reference or certify a comparison. UIT
// owns reference execution, frame consumption and the final difftest outcome.
struct Audit {
  FILE *stream = nullptr;
  const char *run_id = nullptr;
  bool enabled_diff = false;
  bool reference_loaded = false;
  bool terminal_seen = false;
  bool finished = false;
  uint64_t frame = 0;
  uint64_t terminal_code = 0;
  uint64_t raw_gpr[32]{};
  // TrapEvent precedes its delayed InstrCommit by three source cycles. Retain
  // the packet with the existing 16-frame delivery bound, never guess a PC.
  bool trap_pending = false;
  uint64_t trap_frame = 0;
  uint64_t trap_pc = 0;
  uint64_t trap_cycles = 0;
  uint64_t trap_instructions = 0;
  uint64_t terminal_retire_frame = 0;
};

inline Audit &state() {
  static Audit audit;
  return audit;
}

[[noreturn]] inline void fail(const char *message) {
  fprintf(stderr, "Scalar comparison audit rejected: %s\n", message);
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
  fprintf(audit.stream, "{\"schema\":1,\"scope\":\"scalar-compare-v1\",\"event\":");
  string(audit.stream, name);
  fputs(",\"run_id\":", audit.stream);
  string(audit.stream, audit.run_id);
  fprintf(audit.stream, ",\"pid\":%ld,\"core\":0,\"frame\":%" PRIu64 ",\"mode\":\"%s\"",
          static_cast<long>(getpid()), audit.frame, audit.enabled_diff ? "difftest" : "no-diff");
  return audit.stream;
}

inline void flush() {
  auto &audit = state();
  if (!audit.stream || audit.finished) fail("trace is not active");
  fputs("}\n", audit.stream);
  if (ferror(audit.stream) || fflush(audit.stream)) fail("trace write failed");
}

inline void registers(FILE *stream, const uint64_t *gpr) {
  fputs(",\"gpr\":[", stream);
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
  struct stat file{};
  if (fstat(fd, &file) || !S_ISREG(file.st_mode)) { close(fd); fail("trace is not a regular file"); }
  audit.stream = fdopen(fd, "w");
  if (!audit.stream) { close(fd); fail("cannot open trace stream"); }
  audit.enabled_diff = enabled_diff;
  event("start");
  flush();
}

inline void mark_reference_loaded() {
  auto &audit = state();
  if (!audit.stream || audit.finished || !audit.enabled_diff || audit.reference_loaded)
    fail("reference load is outside the active difftest lifecycle");
  audit.reference_loaded = true;
}

inline void observe(const DiffTestState &frame) {
  auto &audit = state();
  if (!audit.stream || audit.finished) fail("observation outside the trace lifecycle");
  ++audit.frame;
  if (audit.trap_pending && !audit.terminal_seen && audit.frame - audit.trap_frame > 16)
    fail("terminal retirement did not arrive within 16 frames");
  if (frame.trap.hasTrap) {
    if (audit.trap_pending || audit.terminal_seen) fail("duplicate terminal packet");
    audit.trap_pending = true;
    audit.trap_frame = audit.frame;
    audit.trap_pc = frame.trap.pc;
    audit.terminal_code = frame.trap.code;
    audit.trap_cycles = frame.trap.cycleCnt;
    audit.trap_instructions = frame.trap.instrCnt;
    fprintf(event("trap_latched"), ",\"pc\":\"0x%" PRIx64 "\",\"code\":%" PRIu64
            ",\"cycle_count\":%" PRIu64 ",\"instruction_count\":%" PRIu64,
            audit.trap_pc, audit.terminal_code, audit.trap_cycles, audit.trap_instructions);
    flush();
  }
  // StoreEvent observes each accepted scalar SQ-to-Sbuffer publication before
  // cacheline merging. Its two-cycle source delay differs from InstrCommit;
  // sample_cycle names this raw frame's clock, not the publication cycle.
  for (unsigned slot = 0; slot < CONFIG_DIFF_STORE_WIDTH; ++slot) {
    const auto &store = frame.store[slot];
    if (!store.valid) continue;
    fprintf(event("store"), ",\"slot\":%u,\"sample_cycle\":%" PRIu64
            ",\"pc\":\"0x%" PRIx64 "\",\"robidx\":%u,\"address\":\"0x%" PRIx64
            "\",\"data\":\"0x%016" PRIx64 "\",\"mask\":%u",
            slot, static_cast<uint64_t>(frame.uit_clock.cycle), static_cast<uint64_t>(store.pc),
            static_cast<unsigned>(store.robidx), static_cast<uint64_t>(store.addr),
            static_cast<uint64_t>(store.data), static_cast<unsigned>(store.mask));
    flush();
    if (audit.terminal_seen && store.mask)
      fail("store publication arrived after the terminal boundary");
  }
  bool terminal_in_frame = false;
  for (unsigned slot = 0; slot < CONFIG_DIFF_COMMIT_WIDTH; ++slot) {
    const auto &commit = frame.commit[slot];
    if (!commit.valid) continue;
    if (audit.terminal_seen || terminal_in_frame) fail("instruction retired after the terminal slot");
    if (commit.instr == 0x0005006b || (audit.trap_pending && commit.pc == audit.trap_pc)) {
      if (!audit.trap_pending || commit.pc != audit.trap_pc || commit.instr != 0x0005006b ||
          commit.skip || commit.nFused)
        fail("terminal retirement does not match the retained packet");
      terminal_in_frame = true;
      audit.terminal_retire_frame = audit.frame;
      memcpy(audit.raw_gpr, frame.regs_int.value, sizeof(audit.raw_gpr));
    }
    FILE *stream = event("retire");
    fprintf(stream, ",\"slot\":%u,\"pc\":\"0x%" PRIx64 "\",\"instruction\":\"0x%08x\","
            "\"skip\":%s,\"n_fused\":%u,\"robidx\":%u,\"gpr_scope\":\"frame_architectural\"",
            slot, static_cast<uint64_t>(commit.pc), static_cast<unsigned>(commit.instr),
            commit.skip ? "true" : "false", static_cast<unsigned>(commit.nFused),
            static_cast<unsigned>(commit.robIdx));
    registers(stream, frame.regs_int.value);
    flush();
  }
  if (frame.event.valid) {
    fprintf(event("architectural_event"), ",\"pc\":\"0x%" PRIx64 "\",\"exception\":%u,\"interrupt\":%u",
            static_cast<uint64_t>(frame.event.exceptionPC), static_cast<unsigned>(frame.event.exception),
            static_cast<unsigned>(frame.event.interrupt));
    flush();
    if (audit.trap_pending || audit.terminal_seen)
      fail("architectural event while awaiting terminal retirement");
  }
  if (terminal_in_frame) {
    audit.terminal_seen = true;
    FILE *stream = event("terminal");
    fprintf(stream, ",\"pc\":\"0x%" PRIx64 "\",\"code\":%" PRIu64 ",\"cycle_count\":%" PRIu64
            ",\"instruction_count\":%" PRIu64 ",\"compare_frame\":0,\"compare_pass\":false,"
            "\"observation_only\":true,\"trap_frame\":%" PRIu64 ",\"retire_frame\":%" PRIu64,
            audit.trap_pc, audit.terminal_code, audit.trap_cycles, audit.trap_instructions,
            audit.trap_frame, audit.terminal_retire_frame);
    registers(stream, audit.raw_gpr);
    flush();
  }
}

inline void finish() {
  auto &audit = state();
  fprintf(event("end"), ",\"terminal_seen\":%s,\"reference_loaded\":%s",
          audit.terminal_seen ? "true" : "false", audit.reference_loaded ? "true" : "false");
  flush();
  audit.finished = true;
  if (fclose(audit.stream)) fail("trace close failed");
}
} // namespace DasicsScalarAudit
#endif
#endif
