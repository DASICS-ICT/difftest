#ifndef USER_TIMER_BRIDGE_H
#define USER_TIMER_BRIDGE_H

#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
#include "difftest-user-timer.h"
#include <array>
#include <cstdio>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

// Observations never flow back to the core. Frames own every ordinary DiffTest
// field until all input records belonging to that architectural boundary arrive.
struct UitBridge {
  static constexpr size_t capacity = 4096;
  struct Access {
    DifftestUserTimerAccess request{};
    DifftestUserTimerResponse response{};
    DifftestUserTimerSnapshot snapshot{};
    bool responded = false;
    bool captured = false;
  };
  std::deque<std::unique_ptr<DiffTestState>> frames;
  std::map<uint64_t, Access> accesses;
  std::map<uint64_t, DifftestUserTimerSnapshot> events;
  std::deque<DifftestUserTimerUart> uart;
  std::set<uint64_t> accepted, closed, seen_events;
  std::set<uint64_t> canceled;
  DifftestUserTimerTerminal terminal{};
  DifftestTrapEvent terminal_trap{};
  bool terminal_seen = false, raw_terminal_seen = false, terminal_compared = false;
  uint64_t terminal_frame_uid = 0;
  std::string fault_kind;
  bool fault_used = false;
  FILE *trace = nullptr;
  bool released = false, initialized = false, failed = false, finalized = false;
  uint64_t epoch = 1, retired = 0, control_seq = 0, event_seq = 0, all_instr = 0;
  uint64_t controlled_exec = 0, sample_timer = 0, sample_pending = 0, hu_events = 0, uret = 0;
  uint64_t uart_compares = 0, forbidden_skips = 0, protocol_errors = 0, initial_state_imports = 0;
  uint64_t store_checks = 0, frame_store_checks = 0, initial_retired = 0;
  std::array<uint64_t, 7> compare_attempts{}, compare_passes{};

  ~UitBridge() { if (trace) { fflush(trace); fclose(trace); } }
  int error(const char *reason, uint64_t uid = 0) {
    failed = true;
    protocol_errors++;
    fprintf(stderr, "UIT06 protocol failure: %s (uid=%lu)\n", reason, uid);
    if (trace) {
      fprintf(trace, "{\"schema\":1,\"type\":\"protocol_error\",\"hart\":0,\"epoch\":%lu,\"reason\":\"%s\",\"uid\":%lu}\n", epoch, reason, uid);
      fflush(trace);
    }
    return 1;
  }
  void prefix(const char *type) {
    fprintf(trace, "{\"schema\":1,\"type\":\"%s\",\"hart\":0,\"epoch\":%lu", type, epoch);
  }
  void inject(const char *kind, uint64_t uid, uint64_t original, uint64_t mutated) {
    fault_used = true;
    prefix("fault");
    fprintf(trace, ",\"kind\":\"%s\",\"uid\":%lu,\"original\":\"0x%lx\",\"mutated\":\"0x%lx\",\"sample_unchanged\":true}\n", kind, uid, original, mutated);
  }
  static bool controlled(uint32_t insn) {
    if (insn == 0x00200073) return true;
    if ((insn & 0x7f) != 0x73 || !(insn & 0x7000)) return false;
    switch (insn >> 20) {
      case 0x000: case 0x004: case 0x005: case 0x040: case 0x041:
      case 0x042: case 0x043: case 0x044: case 0x800: return true;
      default: return false;
    }
  }
  void summary() {
    if (!trace || finalized) return;
    finalized = true;
    prefix("summary");
    fprintf(trace, ",\"fault_kind\":\"%s\",\"fault_used\":%s,\"terminal_seen\":%s,\"terminal_compared\":%s", fault_kind.c_str(), fault_used ? "true" : "false", terminal_seen ? "true" : "false", terminal_compared ? "true" : "false");
    fprintf(trace, ",\"status\":\"%s\",\"all_instr\":%lu,\"controlled_exec\":%lu,\"sample_timer\":%lu,\"sample_pending\":%lu,\"hu_events\":%lu,\"uret\":%lu,\"uart_compares\":%lu,\"forbidden_skips\":%lu,\"state_imports_runtime\":0,\"initial_state_imports\":%lu,\"protocol_errors\":%lu,\"pending_frames\":%zu,\"pending_accesses\":%zu,\"pending_events\":%zu,\"pending_uart\":%zu,\"csr_compare_attempts\":[", failed ? "FAIL" : "PASS", all_instr, controlled_exec, sample_timer, sample_pending, hu_events, uret, uart_compares, forbidden_skips, initial_state_imports, protocol_errors, frames.size(), accesses.size(), events.size(), uart.size());
    for (size_t i = 0; i < 7; i++) fprintf(trace, "%s%lu", i ? "," : "", compare_attempts[i]);
    fprintf(trace, "],\"csr_compare_passes\":[");
    for (size_t i = 0; i < 7; i++) fprintf(trace, "%s%lu", i ? "," : "", compare_passes[i]);
    fprintf(trace, "]}\n"); fflush(trace);
  }
};
#endif
#endif
