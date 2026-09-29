#include "common.h"
#include "dut.h"
#include "refproxy.h"
#include <queue>
#include <vector>
#include "user_timer_bridge.h"

bool sim_verbose = false;
int eprintf(const char *, ...) { return 0; }

static void require(bool condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "PROTOCOL_UNIT_FIXTURE_FAILURE: %s\n", message);
    exit(91);
  }
}

static uint8_t fake_flash_bytes[]{0x13, 0, 0, 0};
struct FakeFlash {
  void *base;
  size_t img_size;
  const char *img_path;
} flash_dev{fake_flash_bytes, sizeof(fake_flash_bytes), "unit-flash"};

struct FakeSimMemory {
  uint32_t clone_calls = 0;
  bool last_clone_mode = false;
  uint8_t bytes[4]{0x11, 0x22, 0x33, 0x44};
  template <typename Callback> void clone_on_demand(Callback callback, bool mode) {
    ++clone_calls;
    last_clone_mode = mode;
    callback(0x120, bytes, sizeof(bytes));
  }
} fake_memory;
static FakeSimMemory *simMemory = &fake_memory;

// These spies provide predetermined outputs and never execute DUT or ISA logic.
struct FakeProxy {
  DifftestArchIntRegState regs_int{};
  DifftestCSRState csr{};
  DifftestHCSRState hcsr{};
  DifftestUitCaps caps{};
  DifftestUitState current{}, after{};
  DifftestUitExecRequest last_exec{};
  DifftestUitHUEvent last_event{};
  std::deque<DifftestUitTx> output;
  uint64_t pc = 0x80001000, next_pc = 0x80001004;
  int32_t exec_rc = 0, event_rc = 0, state_rc = 0;
  int reference_status = 0;
  int compare_rc = 0;
  bool end_on_exec = false;
  bool exception_on_exec = false;
  uint32_t outcome = DIFFTEST_UIT_RETIRED;
  uint32_t exec_calls = 0, event_calls = 0;
  uint32_t ordinary_exec_calls = 0, compare_calls = 0;
  uint32_t regcpy_calls = 0, init_calls = 0, flash_calls = 0, memory_calls = 0;
  uint64_t imported_pc = 0, initialized_pc = 0, initialized_epoch = 0, memory_address = 0;
  uint32_t initialized_features = 0;
  std::vector<std::string> execution_order;
  DifftestCSRState compared_csr{};
  bool corrupt_result_uid = false, corrupt_result_seq = false, corrupt_consumed = false;
  bool corrupt_result_epoch = false, corrupt_result_bytes = false;
  bool write_valid = false;
  uint64_t write_value = 0;
  FakeProxy() {
    caps.version = DIFFTEST_UIT_VERSION;
    caps.enabled_features = DIFFTEST_UIT_FEATURES;
    current.version = after.version = DIFFTEST_UIT_VERSION;
    current.bytes = after.bytes = sizeof(current);
    current.epoch = after.epoch = 1;
  }
  const DifftestUitCaps &uit_caps() const { return caps; }
  const std::string &reference_path() const { static const std::string path = "unit-fake-reference"; return path; }
  void flash_init(const uint8_t *base, size_t size, const char *path) {
    require(base == fake_flash_bytes && size == sizeof(fake_flash_bytes) && !strcmp(path, "unit-flash"), "flash initialization arguments");
    ++flash_calls; execution_order.push_back("flash_init");
  }
  void mem_init(uint64_t address, void *data, size_t size, bool direction) {
    require(data == fake_memory.bytes && size == sizeof(fake_memory.bytes) && direction == DUT_TO_REF,
            "memory clone callback arguments");
    ++memory_calls; memory_address = address; execution_order.push_back("mem_init");
  }
  void regcpy(DiffTestState *dut) {
    ++regcpy_calls; imported_pc = pc = dut->commit[0].pc;
    regs_int = dut->regs_int; csr = dut->csr; hcsr = dut->hcsr; current.pc = pc;
    execution_order.push_back("regcpy");
  }
  int32_t uit_init(uint64_t epoch, uint32_t features) {
    ++init_calls; initialized_pc = pc; initialized_epoch = epoch; initialized_features = features;
    execution_order.push_back("uit_init");
    return DIFFTEST_UIT_OK;
  }
  void sync() {}
  void ref_exec(uint64_t count) {
    require(count == 1, "production issues individual original instructions");
    ++ordinary_exec_calls;
    execution_order.push_back("instruction");
    pc = exception_on_exec ? next_pc : pc + 4;
    if (end_on_exec) reference_status = STATE_SIM_EXIT;
  }
  int get_status() { return reference_status; }
  void guided_exec(ExecutionGuide &) { require(false, "unexpected guided exception in protocol fixture"); }
  void uarchstatus_sync(void *) { require(false, "unexpected LR/SC side effect in fixture"); }
  int compare(DiffTestState *dut) { ++compare_calls; compared_csr = dut->csr; return compare_rc; }
  void display(DiffTestState *) {}
  int32_t uit_state(DifftestUitState &value) { value = current; return state_rc; }
  int32_t uit_exec(const DifftestUitExecRequest &request, DifftestUitExecResult &result) {
    ++exec_calls;
    last_exec = request;
    if (exec_rc) return exec_rc;
    result.version = DIFFTEST_UIT_VERSION;
    result.bytes = sizeof(result);
    result.hart = request.hart;
    result.epoch = request.epoch;
    if (corrupt_result_epoch) ++result.epoch;
    if (corrupt_result_bytes) --result.bytes;
    result.transaction_uid = request.transaction_uid + corrupt_result_uid;
    result.control_seq = request.control_seq + corrupt_result_seq;
    result.outcome = outcome;
    result.sample_consumed = bool(request.sample_kind) != corrupt_consumed;
    result.csr_write_valid = write_valid;
    result.csr_write_value = write_value;
    pc = next_pc;
    current = after;
    current.last_control_seq = request.control_seq;
    return 0;
  }
  int32_t uit_event(const DifftestUitHUEvent &event) {
    ++event_calls;
    last_event = event;
    if (event_rc) return event_rc;
    execution_order.push_back("event");
    pc = next_pc;
    current = after;
    current.last_control_seq = event.control_seq;
    return 0;
  }
  int32_t uit_tx(DifftestUitTx &tx) {
    if (output.empty()) return DIFFTEST_UIT_EMPTY;
    tx = output.front(); output.pop_front(); return 0;
  }
};

struct FakeState {
  uint32_t interrupts = 0, exceptions = 0;
  uint32_t group_instructions = 0;
  std::vector<uint64_t> committed_pc;
  void record_interrupt(uint64_t, uint32_t, uint32_t) { ++interrupts; }
  void record_exception(uint64_t, uint32_t, uint32_t) { ++exceptions; }
  void record_group(uint64_t, uint32_t count) { group_instructions += count; }
  template <typename... Args> void record_inst(uint64_t pc, Args...) { committed_pc.push_back(pc); }
};

class Difftest {
public:
  DiffTestState live{};
  DiffTestState *dut = &live;
  FakeProxy reference;
  FakeProxy *proxy = &reference;
  FakeState records;
  FakeState *state = &records;
  UitBridge uit;
  std::queue<DifftestStoreEvent> store_event_queue;
  std::vector<uint64_t> compared_cycles;
  int id = 0;
  int num_commit = 0;
  uint64_t nemu_this_pc = UINT64_C(0xdededededededede);
  bool progress = false, has_commit = false, pc_mismatch = false;
  bool feature_enabled = true;
  int check_all();
  int do_instr_commit(int);
  bool check_timeout() { compared_cycles.push_back(dut->uit_clock.cycle); return false; }
  void do_first_instr_commit();
  void store_event_record() {}
  int do_golden_memory_update() { return 0; }
  void cmo_inval_event_record() {}
  int do_irefill_check() { return 0; }
  int do_drefill_check() { return 0; }
  int do_ptwrefill_check() { return 0; }
  int do_l1tlb_check() { return 0; }
  void do_non_reg_interrupt_pending() {}
  void do_mhpmevent_overflow() {}
  void do_raise_critical_error() {}
  void do_sync_aia() {}
  void do_sync_custom_mflushpwr() {}
  void do_load_check(int) {}
  int do_store_check() { return 0; }
  int update_delayed_writeback() { return 0; }
  int apply_delayed_writeback() { return 0; }
  uint64_t get_commit_data(int) { return 0; }
  void update_last_commit() {}
  void raise_trap(int) { require(false, "unexpected delayed-writeback trap"); }
  void display() {}
  void do_interrupt() { ++records.interrupts; proxy->pc = proxy->next_pc; }
  void do_exception();
  int uit_ingest();
  bool uit_ready(const DiffTestState &frame);
  int uit_step();
  int uit_compare_bank(const std::array<uint64_t, 8> &, uint64_t, const char *, uint64_t = 0);
  int uit_execute(uint64_t, uint32_t, uint64_t, bool);
  int uit_event();
  int uit_check_uart();
  int uit_finalize();
  int uit_status();
};

// Compile the actual production protocol implementation in this narrow adapter.
#include "production-reference-start.inc"
#include "user_timer_bridge.inc"
#include "production-retirement.inc"

Difftest *difftest[NUM_CORES]{};
class Emulator {
public:
  int trapCode = STATE_RUNNING;
  int is_good();
};
#include "production-exit.inc"
#include "capture-census.inc"

static void clear_frame(Difftest &test, uint64_t cycle = 10) {
  test.live = {};
  test.live.uit_clock.epoch = 1;
  test.live.uit_clock.cycle = cycle;
  test.live.uit_clock.enabled = test.feature_enabled;
}

static DifftestUserTimerAccess access(uint64_t uid = 1, uint16_t csr = 0x800) {
  DifftestUserTimerAccess a{};
  a.valid = a.legal = a.needRead = 1;
  a.epoch = 1; a.uid = uid; a.cycle = 10; a.pc = 0x80001000;
  a.csr = csr; a.funct3 = 2; a.instr = (uint32_t(csr) << 20) | 0x20f3;
  a.sampleKind = csr == 0x800 ? 1 : csr == 0x44 ? 2 : 0;
  a.sampleValue = csr == 0x44 ? 1 : csr == 0x800 ? 0x345 : 0;
  return a;
}

static void observe_access(Difftest &test, DifftestUserTimerAccess a = access()) {
  clear_frame(test, a.cycle);
  test.live.uit_access = a;
  require(test.uit_ingest() == 0, "valid access intake");
  clear_frame(test, a.cycle + 1);
}

static void complete_access(Difftest &test, DifftestUserTimerAccess a = access()) {
  observe_access(test, a);
  auto &r = test.live.uit_response;
  r.valid = 1; r.epoch = 1; r.uid = a.uid; r.cycle = a.cycle + 1;
  r.rdata = a.sampleKind == 2 ? a.sampleValue << 4 : a.sampleValue;
  auto &s = test.live.uit_snapshot;
  s.valid = 1; s.epoch = 1; s.uid = a.uid; s.cycle = a.cycle + 2; s.kind = a.isUret ? 2 : 1;
  s.robIdx = a.robIdx; s.robFlag = a.robFlag;
  s.target = 0x80000002;
  require(test.uit_ingest() == 0, "valid response and snapshot intake");
  clear_frame(test, a.cycle + 3);
}

static void prepare_event(Difftest &test) {
  test.uit.retired = 8; test.uit.initial_retired = 3;
  auto &event = test.live.event;
  event.valid = 1; event.eventSeq = 1; event.irToHU = 1; event.interrupt = 4;
  event.exceptionPC = test.reference.pc;
  DifftestUserTimerSnapshot snapshot{};
  snapshot.valid = 1; snapshot.kind = 3; snapshot.epoch = 1; snapshot.uid = 9;
  snapshot.eventSeq = 1; snapshot.beforeCount = 8; snapshot.pc = event.exceptionPC;
  snapshot.target = 0x80002000;
  test.reference.next_pc = snapshot.target;
  test.uit.events.emplace(1, snapshot);
}

static void prepare_order(Difftest &test, bool before_slot_zero = false) {
  test.has_commit = true;
  test.uit.retired = test.uit.initial_retired = 3;
  auto &dut = test.live;
  dut.csr.mstatus = 0x123;
  auto &first = dut.commit[0];
  first.valid = 1; first.instr = 0x13;
  first.pc = before_slot_zero ? 0x80002000 : 0x80001000;
  first.nFused = before_slot_zero ? 0 : 2;
  auto &identity = dut.uit_retire[0];
  identity.valid = 1; identity.epoch = 1; identity.uid = 1;
  identity.beforeCount = 3; identity.afterCount = before_slot_zero ? 4 : 6;
  if (!before_slot_zero) {
    dut.commit[1] = first; dut.commit[1].pc = 0x80002000; dut.commit[1].nFused = 0;
    dut.uit_retire[1] = identity;
    dut.uit_retire[1].uid = 2; dut.uit_retire[1].beforeCount = 6; dut.uit_retire[1].afterCount = 7;
  }
  dut.event.valid = 1; dut.event.eventSeq = 1; dut.event.irToHU = 1; dut.event.interrupt = 4;
  dut.event.exceptionPC = before_slot_zero ? 0x80001000 : 0x8000100c;
  DifftestUserTimerSnapshot snapshot{};
  snapshot.valid = 1; snapshot.kind = 3; snapshot.epoch = 1; snapshot.uid = 9;
  snapshot.eventSeq = 1; snapshot.beforeCount = before_slot_zero ? 3 : 6;
  snapshot.pc = dut.event.exceptionPC; snapshot.target = 0x80002000;
  snapshot.csrState_mstatus = 0x456;
  test.uit.events.emplace(1, snapshot);
  test.reference.next_pc = snapshot.target;
}

static void early_terminal(Difftest &test, bool include_raw = true, uint64_t trap_code = 0) {
  test.has_commit = test.uit.initialized = true;
  auto &dut = test.live;
  auto &terminal = dut.uit_terminal;
  terminal.valid = 1; terminal.epoch = 1; terminal.uid = 17; terminal.cycle = 10;
  terminal.afterCount = 1; terminal.pc = test.reference.pc;
  dut.trap.hasTrap = include_raw; dut.trap.pc = terminal.pc; dut.trap.code = trap_code;
  require(test.uit_step() == 0 && test.uit.terminal_seen && !test.uit.terminal_compared,
          "early terminal record remains pending");
  clear_frame(test, 11);
}

static int terminal_commit(Difftest &test, uint64_t uid = 17) {
  clear_frame(test, 13);
  auto &dut = test.live;
  dut.commit[0].valid = 1; dut.commit[0].instr = 0x13; dut.commit[0].pc = test.uit.terminal.pc;
  dut.commit[0].robIdx = 3;
  auto &identity = dut.uit_retire[0];
  identity.valid = 1; identity.epoch = 1; identity.uid = uid; identity.robIdx = 3;
  identity.beforeCount = 0; identity.afterCount = 1;
  return test.uit_step();
}

static void mature_terminal(Difftest &test, bool include_raw = true, uint64_t trap_code = 0) {
  early_terminal(test, include_raw, trap_code);
  test.reference.end_on_exec = true;
  require(terminal_commit(test) == 0 && test.uit.terminal_compared && test.uit.retired == 1 &&
          test.uit.all_instr == 1 && test.reference.compare_calls == 1, "terminal retires through actual frame comparison");
}

static int run_case(Difftest &test, const std::string &name) {
  auto &dut = test.live;
  auto &ref = test.reference;
  if (name.rfind("indexed_cancel_", 0) == 0) {
    static_assert(sizeof(dut.uit_cancel) / sizeof(dut.uit_cancel[0]) == 160, "UIT06 indexed cancellation ROB slots");
    test.has_commit = test.uit.initialized = true;
    auto first = access(1); first.robIdx = 2; first.cycle = 11; first.sampleValue = 91;
    auto second = access(2); second.robIdx = 19; second.cycle = 12; second.sampleValue = 87;
    auto fault = access(3); fault.robIdx = 159; fault.cycle = 13;
    fault.legal = 0; fault.sampleKind = 0; fault.sampleValue = 0;
    auto unrelated = access(4); unrelated.robIdx = 73; unrelated.cycle = 14; unrelated.sampleValue = 81;
    observe_access(test, first);
    observe_access(test, second);
    complete_access(test, fault);
    test.uit.accesses.at(3).response.illegal = 1;
    observe_access(test, unrelated);
    const auto unrelated_before = test.uit.accesses.at(4).request;
    clear_frame(test, 30);
    auto cancel = [&](size_t slot, uint64_t uid, uint8_t reason) {
      auto &value = dut.uit_cancel[slot];
      value.valid = 1; value.epoch = 1; value.uid = uid; value.cycle = 30; value.reason = reason;
    };
    cancel(2, 1, 1); cancel(19, 2, 1); cancel(159, 3, 2);
    // Invalid slots may retain stale payload; only their valid bit owns a record.
    dut.uit_cancel[88].hadEffect = 1; dut.uit_cancel[88].reason = 9;
    if (name == "indexed_cancel_duplicate") dut.uit_cancel[19].uid = 1;
    if (name == "indexed_cancel_effect_first") dut.uit_cancel[2].hadEffect = 1;
    if (name == "indexed_cancel_effect_last") dut.uit_cancel[159].hadEffect = 1;
    const int result = test.uit_step();
    require(test.uit.accesses.count(4) == 1 && !memcmp(&unrelated_before, &test.uit.accesses.at(4).request, sizeof(unrelated_before)),
            "one cancellation cannot discard or rewrite an unrelated transaction");
    if (name != "indexed_cancel_mixed") {
      require(ref.exec_calls == 0 && test.uit.accesses.count(3) == 1, "invalid batch cannot execute or discard the fault transaction");
      if (name == "indexed_cancel_effect_first") require(test.uit.accesses.size() == 4, "first-slot effect rejection preserves pending transactions");
      return result;
    }
    require(result == 0 && test.uit.accesses.size() == 2 && !test.uit.accesses.count(1) && !test.uit.accesses.count(2) &&
            test.uit.accesses.count(3) && test.uit.closed.count(1) && test.uit.closed.count(2) &&
            test.uit.canceled.size() == 3, "same-cycle pure reads cancel while reason-two source remains pending");
    for (const auto &value : dut.uit_cancel) require(!value.valid, "every indexed cancellation slot is acknowledged");
    ref.outcome = DIFFTEST_UIT_ISA_EXCEPTION;
    require(test.uit_execute(3, fault.instr, fault.pc, true) == 0 && ref.exec_calls == 1 &&
            ref.ordinary_exec_calls == 0 && test.uit.closed.count(3) && test.uit.accesses.size() == 1 &&
            test.uit.accesses.count(4) && test.uit.control_seq == 1 && test.uit.all_instr == 0,
            "retained fault source closes only through its controlled exception execution");
    require(!memcmp(&unrelated_before, &test.uit.accesses.at(4).request, sizeof(unrelated_before)), "fault execution preserves unrelated pending sample");
    printf("INDEXED_CANCEL_PASS slots=160 cycle=30 canceled_reads=2 retained_fault_executed=1 unrelated_retained=1\n");
    return 0;
  }
  if (name == "ram_anchor_enabled" || name == "ram_anchor_disabled") {
    test.feature_enabled = name == "ram_anchor_enabled";
    ref.caps.enabled_features = test.feature_enabled ? DIFFTEST_UIT_FEATURES : DIFFTEST_UIT_F_UART_TX;
    const auto reference_pc_before = ref.pc;
    auto retire_frame = [&](uint64_t pc, uint64_t before, uint64_t uid) {
      clear_frame(test, 100 + before);
      dut.commit[0].valid = 1; dut.commit[0].pc = pc; dut.commit[0].instr = 0x13;
      dut.commit[0].robIdx = uid;
      auto &identity = dut.uit_retire[0];
      identity.valid = 1; identity.epoch = 1; identity.uid = uid; identity.robIdx = uid;
      identity.beforeCount = before; identity.afterCount = before + 1;
      return test.uit_step();
    };
    for (uint64_t i = 0; i < 5; ++i) {
      require(retire_frame(0x10000000 + i * 4, i, i + 1) == 0, "Flash retirement remains outside comparison");
      require(!test.has_commit && !test.uit.initialized && test.uit.initial_state_imports == 0 &&
              ref.regcpy_calls == 0 && ref.init_calls == 0 && ref.ordinary_exec_calls == 0 &&
              ref.exec_calls == 0 && ref.compare_calls == 0 && ref.flash_calls == 0 && ref.memory_calls == 0 &&
              fake_memory.clone_calls == 0 && ref.pc == reference_pc_before &&
              test.nemu_this_pc == UINT64_C(0xdededededededede), "Flash commits cause no reference initialization or execution");
    }
    require(retire_frame(0x80000000, 5, 6) == 0, "first RAM retirement initializes and executes");
    require(test.has_commit && test.uit.initialized && test.nemu_this_pc == 0x80000000 &&
            test.uit.initial_retired == 5 && test.uit.retired == 6 && test.uit.all_instr == 1 &&
            test.uit.initial_state_imports == 1 && ref.imported_pc == 0x80000000 && ref.initialized_pc == 0x80000000 &&
            ref.initialized_epoch == 1 && ref.initialized_features == ref.caps.enabled_features &&
            ref.regcpy_calls == 1 && ref.init_calls == 1 && ref.ordinary_exec_calls == 1 && ref.compare_calls == 1 &&
            ref.pc == 0x80000004 && ref.flash_calls == 1 && ref.memory_calls == 1 &&
            fake_memory.clone_calls == 1 && fake_memory.last_clone_mode && ref.memory_address == 0x80000120 &&
            ref.execution_order == std::vector<std::string>({"flash_init", "mem_init", "regcpy", "uit_init", "instruction"}),
            "RAM initializes once at its original-instruction count and PC before normal execution");
    require(retire_frame(0x80000004, 6, 7) == 0 && ref.regcpy_calls == 1 && ref.init_calls == 1 &&
            ref.flash_calls == 1 && ref.memory_calls == 1 && fake_memory.clone_calls == 1 &&
            ref.ordinary_exec_calls == 2 && ref.compare_calls == 2 && ref.pc == 0x80000008 &&
            test.uit.initial_retired == 5 && test.uit.retired == 7 && test.uit.all_instr == 2 &&
            test.uit.initial_state_imports == 1, "later RAM retirement cannot repeat initialization");
    printf("RAM_ANCHOR_PASS flash_frames=5 ram_frames=2 imports=1 uit_init=1 ram_exec=2 compares=2 initial_pc=0x%lx retired_base=%lu enabled=%d\n",
           ref.initialized_pc, test.uit.initial_retired, test.feature_enabled);
    return 0;
  }
  if (name == "capture_census" || name == "capture_reset") {
    memset(&dut, 0x5a, sizeof(dut));
    dut.uit_clock.epoch = 1; dut.uit_clock.cycle = 123; dut.uit_clock.enabled = 1;
    dut.uit_clock.coreReset = name == "capture_reset";
    dut.trap.hasWFI = 1;
    set_capture_census_flags(dut, 1);
    DiffTestState expected;
    memcpy(&expected, &dut, sizeof(expected));
    set_capture_census_flags(expected, 0);
    if (name == "capture_reset") {
      require(test.uit_step() == 0 && !test.uit.released && test.uit.frames.empty() &&
              ref.exec_calls == 0 && ref.event_calls == 0, "reset capture acknowledgement has no execution side effects");
    } else {
      uit_clear_captured_valid(dut);
    }
    require(!memcmp(&dut, &expected, sizeof(dut)), "only generated packet valid flags and hasTrap are cleared");
    printf("CAPTURE_CENSUS_PASS flags=%zu all_other_bytes_preserved=true reset=%d\n",
           capture_census_count, name == "capture_reset");
    return 0;
  }
  if (name.rfind("sticky_", 0) == 0) {
    test.has_commit = test.uit.initialized = true;
    dut.regs_int.value[5] = 0x12345678;
    dut.wb_int[3].data = 0x87654321;
    dut.regs_fp.value[2] = 0x24681357;
    dut.regs_vec.value[4] = 0x13572468;
    dut.csr.mstatus = 0x10203040;
    if (name == "sticky_controlled_frame") {
      dut.uit_access = access();
      auto &response = dut.uit_response;
      response.valid = 1; response.epoch = 1; response.uid = 1; response.cycle = 11;
      response.rdata = dut.uit_access.sampleValue;
      auto &snapshot = dut.uit_snapshot;
      snapshot.valid = 1; snapshot.kind = 1; snapshot.epoch = 1; snapshot.uid = 1; snapshot.cycle = 12;
      dut.commit[0].valid = 1; dut.commit[0].instr = dut.uit_access.instr; dut.commit[0].pc = dut.uit_access.pc;
      auto &retire = dut.uit_retire[0];
      retire.valid = 1; retire.epoch = 1; retire.uid = 1; retire.beforeCount = 0; retire.afterCount = 1;
      auto &cancel = dut.uit_cancel[0];
      cancel.valid = 1; cancel.epoch = 1; cancel.uid = 100; cancel.reason = 1;
      auto &uart = dut.uit_uart;
      uart.valid = 1; uart.epoch = 1; uart.address = DIFFTEST_UIT_UART_TX; uart.data = 'Z'; uart.length = 1;
      DifftestUitTx tx{}; tx.version = DIFFTEST_UIT_VERSION; tx.bytes = sizeof(tx);
      tx.epoch = 1; tx.address = DIFFTEST_UIT_UART_TX; tx.data = 'Z'; tx.len = 1;
      ref.output.push_back(tx);
    } else if (name == "sticky_event_frame") {
      dut.event.valid = 1; dut.event.eventSeq = 1; dut.event.irToHU = 1; dut.event.interrupt = 4;
      dut.event.exceptionPC = ref.pc;
      auto &snapshot = dut.uit_snapshot;
      snapshot.valid = 1; snapshot.kind = 3; snapshot.epoch = 1; snapshot.uid = 9; snapshot.eventSeq = 1;
      snapshot.pc = ref.pc; snapshot.target = 0x80002000;
      ref.next_pc = snapshot.target;
    } else if (name == "sticky_terminal_frame") {
      auto &terminal = dut.uit_terminal;
      terminal.valid = 1; terminal.epoch = 1; terminal.uid = 17; terminal.afterCount = 1; terminal.pc = ref.pc;
      dut.trap.hasTrap = 1; dut.trap.pc = terminal.pc;
    } else require(false, "known sticky callback case");
    require(test.uit_step() == 0, "first callback frame accepted");
    printf("STICKY_CALLBACK_CAPTURE first_access_valid=%u first_commit_valid=%u first_event_valid=%u first_terminal_valid=%u\n",
           dut.uit_access.valid, dut.commit[0].valid, dut.event.valid, dut.uit_terminal.valid);
    // No callback writes, frame clearing, or data refresh occurs between calls.
    const int result = test.uit_step();
    if (result) return result;
    require(!dut.uit_access.valid && !dut.uit_response.valid && !dut.uit_snapshot.valid && !dut.uit_retire[0].valid &&
            !dut.commit[0].valid && !dut.event.valid && !dut.uit_cancel[0].valid && !dut.uit_uart.valid && !dut.uit_terminal.valid,
            "captured pulse records are acknowledged in the live DPIC buffer");
    require(dut.regs_int.value[5] == 0x12345678 && dut.wb_int[3].data == 0x87654321 &&
            dut.regs_fp.value[2] == 0x24681357 && dut.regs_vec.value[4] == 0x13572468 && dut.csr.mstatus == 0x10203040,
            "capture acknowledgement preserves persistent register and writeback data");
    require(test.uit.frames.empty() && test.dut == &test.live, "sticky input cannot retain comparison frames");
    if (name == "sticky_controlled_frame")
      require(ref.exec_calls == 1 && test.uit.controlled_exec == 1 && test.uit.retired == 1 && test.uit.uart_compares == 1 &&
              test.uit.accesses.empty() && test.uit.uart.empty(), "callback transaction and UART consumed exactly once");
    if (name == "sticky_event_frame")
      require(ref.event_calls == 1 && test.uit.hu_events == 1 && test.uit.events.empty(), "callback event consumed exactly once");
    if (name == "sticky_terminal_frame")
      require(test.uit.terminal_seen && test.uit.raw_terminal_seen && !test.uit.terminal_compared &&
              test.uit_status() == STATE_RUNNING, "latched terminal remains pending without duplicate capture");
    return 0;
  }
  if (name.rfind("exit_", 0) == 0) {
    Emulator emulator;
    difftest[0] = &test;
    if (name == "exit_good") {
      mature_terminal(test);
      emulator.trapCode = test.uit_status();
      require(emulator.trapCode == STATE_GOODTRAP, "legal mature terminal status");
    } else if (name == "exit_limit_mature") {
      mature_terminal(test);
      emulator.trapCode = STATE_LIMIT_EXCEEDED;
    } else if (name == "exit_limit_without_terminal") {
      test.uit.initialized = true;
      emulator.trapCode = STATE_LIMIT_EXCEEDED;
    } else if (name == "exit_sim_exit_pending") {
      early_terminal(test);
      ref.reference_status = STATE_SIM_EXIT;
      emulator.trapCode = STATE_SIM_EXIT;
    } else if (name == "exit_nonzero_trap") {
      mature_terminal(test, true, 1);
      emulator.trapCode = test.uit_status();
      require(emulator.trapCode == STATE_ABORT, "nonzero terminal is not successful");
    } else require(false, "known exit case");
    const bool good = emulator.is_good();
    const int process_exit = !good;
    require(good == (name == "exit_good") && test.uit.finalized, "real emulator exit checks finalized terminal success");
    if (name == "exit_limit_mature")
      require(!test.uit.failed && emulator.trapCode == STATE_LIMIT_EXCEEDED, "LIMIT remains unsuccessful after otherwise valid finalization");
    if (name == "exit_limit_without_terminal" || name == "exit_sim_exit_pending")
      require(test.uit.failed && emulator.trapCode == STATE_ABORT, "failed finalization changes exit to ABORT");
    printf("REAL_EMULATOR_EXIT case=%s is_good=%d process_exit=%d trap_code=%d\n", name.c_str(), good, process_exit, emulator.trapCode);
    difftest[0] = nullptr;
    return process_exit;
  }
  if (name.rfind("decode_", 0) == 0) {
    const bool enabled = name == "decode_on_missing_access";
    test.feature_enabled = enabled;
    ref.caps.enabled_features = enabled ? DIFFTEST_UIT_FEATURES : DIFFTEST_UIT_F_UART_TX;
    clear_frame(test);
    if (name == "decode_off_with_access") {
      auto a = access(9); a.instr = 0x00200073; a.isUret = 1; a.legal = 0; a.needRead = 0;
      a.sampleKind = 0; a.sampleValue = 0;
      complete_access(test, a);
      test.uit.accesses.at(9).response.illegal = 1;
      ref.outcome = DIFFTEST_UIT_ISA_EXCEPTION;
    }
    prepare_event(test);
    dut.event.irToHU = 0; dut.event.interrupt = 0; dut.event.exception = 2;
    dut.event.exceptionInst = 0x00200073;
    test.uit.all_instr = 5;
    if (name == "decode_off_timer_missing_access") dut.event.exceptionInst = access().instr;
    if (name == "decode_off_wrong_cause") dut.event.exception = 3;
    if (name == "decode_off_interrupt") dut.event.interrupt = 4;
    const bool must_wait = enabled || name == "decode_off_timer_missing_access" ||
                           name == "decode_off_wrong_cause" || name == "decode_off_interrupt";
    if (must_wait) {
      require(!test.uit_ready(dut) && ref.exec_calls == 0 && ref.ordinary_exec_calls == 0,
              "only disabled decode-rejected URET may proceed without an access record");
      return 0;
    }
    require(test.uit_ready(dut), "disabled URET exception frame ready");
    ref.exception_on_exec = true;
    const uint64_t target = test.uit.events.at(1).target;
    if (name == "decode_off_target_mismatch") ref.next_pc ^= 4;
    if (name == "decode_off_bank_mismatch") ref.current.uscratch = 1;
    const int result = test.uit_event();
    if (name == "decode_off_no_access") {
      require(result == 0 && test.records.exceptions == 1 && ref.ordinary_exec_calls == 1 && ref.exec_calls == 0 &&
              test.uit.controlled_exec == 0 && test.uit.control_seq == 0 && test.uit.all_instr == 5 &&
              test.uit.retired == 8 && ref.pc == target && test.uit.event_seq == 1 && !dut.event.valid &&
              test.uit.events.empty(), "decode-only URET uses ordinary exception without advancing retirement or controlled sequence");
      for (size_t i = 0; i < 7; ++i)
        require(test.uit.compare_attempts[i] == 1 && test.uit.compare_passes[i] == 1, "decode-only URET retains every bank comparison");
    }
    if (name == "decode_off_with_access") {
      require(result == 0 && test.records.exceptions == 1 && ref.ordinary_exec_calls == 0 && ref.exec_calls == 1 &&
              test.uit.controlled_exec == 1 && test.uit.control_seq == 1 && test.uit.all_instr == 5 &&
              test.uit.retired == 8 && test.uit.accesses.empty() && test.uit.closed.count(9) &&
              ref.last_exec.kind == DIFFTEST_UIT_URET && ref.last_exec.transaction_uid == 9,
              "an observed disabled URET remains a controlled transaction and consumes its record");
    }
    return result;
  }
  if (name.rfind("status_", 0) == 0) {
    if (name == "status_compare_failure") {
      early_terminal(test);
      ref.compare_rc = 1; ref.end_on_exec = true;
      require(terminal_commit(test) == 1 && ref.compare_calls == 1 && !test.uit.terminal_compared,
              "failed terminal frame comparison cannot release terminal status");
      return test.uit_status();
    }
    if (name == "status_ref_end_without_marker") { ref.reference_status = STATE_SIM_EXIT; return test.uit_status(); }
    if (name == "status_early_marker" || name == "status_ref_end_early" || name == "status_missing_commit" ||
        name == "status_wrong_uid" || name == "status_missing_raw") {
      early_terminal(test, name != "status_missing_raw");
      if (name == "status_early_marker") {
        require(test.uit_status() == STATE_RUNNING && ref.ordinary_exec_calls == 0 && !test.uit.finalized,
                "early raw trap cannot end simulation before delayed retirement");
        return 0;
      }
      if (name == "status_ref_end_early") { ref.reference_status = STATE_SIM_EXIT; return test.uit_status(); }
      if (name == "status_missing_commit") return test.uit_finalize();
      if (name == "status_wrong_uid") return terminal_commit(test, 18);
      require(terminal_commit(test) == 0 && test.uit.terminal_compared, "terminal comparison without raw trap");
      return test.uit_status();
    }
    mature_terminal(test, true, name == "status_dut_badtrap" ? 1 : 0);
    if (name == "status_reference_running_at_terminal") ref.reference_status = 0;
    const int result = test.uit_status();
    if (name == "status_delayed_good")
      require(result == STATE_GOODTRAP && test.uit.finalized && !test.uit.failed &&
              test.uit.terminal_seen && test.uit.raw_terminal_seen && test.uit.terminal_compared,
              "delayed terminal completes only after real commit and comparison");
    return result;
  }
  if (name == "terminal_raw_pc_mismatch" || name == "terminal_duplicate_marker") {
    early_terminal(test);
    if (name == "terminal_raw_pc_mismatch") { test.uit.terminal_trap.pc ^= 4; return test.uit_ingest(); }
    dut.uit_terminal = test.uit.terminal;
    return test.uit_ingest();
  }
  if (name.rfind("fault_", 0) == 0) {
    test.uit.fault_kind = name.substr(6);
    if (test.uit.fault_kind == "hu_boundary" || test.uit.fault_kind == "hu_target") {
      prepare_event(test);
      const auto original = test.uit.events.at(1);
      const int result = test.uit_event();
      require(test.uit.fault_used && test.uit.events.at(1).pc == original.pc &&
              test.uit.events.at(1).target == original.target, "HU fault is isolated to comparison metadata");
      return result;
    }
    auto a = access();
    if (test.uit.fault_kind == "uret_target") {
      a.instr = 0x00200073; a.isUret = 1; a.needRead = 0; a.sampleKind = 0; a.sampleValue = 0;
      ref.next_pc = 0x80000002;
    } else {
      const std::vector<std::string> banks{"ustatus", "uie", "utvec", "uscratch", "uepc", "ucause", "utval"};
      const uint16_t addresses[]{0x000, 0x004, 0x005, 0x040, 0x041, 0x042, 0x043};
      bool found = false;
      for (size_t i = 0; i < banks.size(); ++i) if (test.uit.fault_kind == banks[i]) { a = access(1, addresses[i]); found = true; }
      require(found, "known bank comparison fault");
    }
    complete_access(test, a);
    const auto unchanged = test.uit.accesses.at(1).request;
    const int result = test.uit_execute(1, a.instr, a.pc, false);
    require(test.uit.fault_used && !memcmp(&unchanged, &test.uit.accesses.at(1).request, sizeof(unchanged)) &&
            ref.last_exec.sample_kind == unchanged.sampleKind && ref.last_exec.sample_payload == unchanged.sampleValue,
            "comparison fault preserves controlled read input");
    return result;
  }
  if (name.rfind("order_", 0) == 0) {
    const bool before = name == "order_before_slot0";
    prepare_order(test, before);
    if (name == "order_boundary_behind") test.uit.events.at(1).beforeCount = 2;
    if (name == "order_boundary_ahead") { test.uit.events.at(1).beforeCount = 8; dut.commit[1].valid = 0; }
    if (name == "order_boundary_inside_group") test.uit.events.at(1).beforeCount = 4;
    if (name == "order_after_last") dut.commit[1].valid = 0;
    if (name == "order_retire_count") --dut.uit_retire[0].afterCount;
    if (name == "order_missing_uid") dut.uit_retire[0].uid = 0;
    if (name == "order_wrong_pc") ++dut.commit[0].pc;
    if (name == "order_skipped_controlled" || name == "order_fused_controlled") {
      dut.event.valid = 0; dut.commit[1].valid = 0; dut.commit[0].instr = access().instr;
      if (name == "order_skipped_controlled") {
        dut.commit[0].skip = 1; dut.commit[0].nFused = 0; dut.uit_retire[0].afterCount = 4;
      }
    }
    const int rc = test.check_all();
    if (name == "order_middle") {
      require(rc == 0 && ref.execution_order == std::vector<std::string>({"instruction", "instruction", "instruction", "event", "instruction"}),
              "original instructions precede HU and handler follows HU");
      require(ref.ordinary_exec_calls == 4 && test.num_commit == 4 && test.uit.all_instr == 4 && test.uit.retired == 7 &&
              ref.last_event.prior_instruction_count == 3 && ref.last_event.boundary_pc == 0x8000100c &&
              test.records.group_instructions == 4 && ref.compare_calls == 1 && ref.compared_csr.mstatus == 0x123,
              "fused retirement count, event boundary, and frame CSR restoration");
    }
    if (name == "order_before_slot0") {
      require(rc == 0 && ref.execution_order == std::vector<std::string>({"event", "instruction"}) &&
              test.records.committed_pc == std::vector<uint64_t>({0x80002000}) && test.uit.retired == 4 &&
              ref.last_event.prior_instruction_count == 0 && ref.ordinary_exec_calls == 1,
              "event at frame start preserves and executes slot zero");
    }
    if (name == "order_after_last") {
      require(rc == 0 && ref.execution_order == std::vector<std::string>({"instruction", "instruction", "instruction", "event"}) &&
              test.uit.retired == 6 && ref.compare_calls == 1 && ref.compared_csr.mstatus == 0x456,
              "event after last group retains event CSR snapshot");
    }
    if (name == "order_middle" || before || name == "order_after_last")
      require(!dut.commit[0].valid && !dut.commit[1].valid && !dut.event.valid && test.uit.events.empty(), "all frame records consumed once");
    else {
      require(ref.event_calls == 0, "invalid boundary cannot inject an event");
      if (name != "order_boundary_ahead")
        require(ref.ordinary_exec_calls == 0, "invalid retirement metadata rejected before reference execution");
    }
    return rc;
  }
  if (name == "initial_reset") { dut.uit_clock.coreReset = 1; return test.uit_ingest(); }
  if (name == "warm_reset") { test.uit.released = true; dut.uit_clock.coreReset = 1; return test.uit_ingest(); }
  if (name == "clock_epoch") { dut.uit_clock.epoch = 2; return test.uit_ingest(); }
  if (name == "feature_mismatch") { dut.uit_clock.enabled = 0; return test.uit_ingest(); }
  if (name == "feature_off") { dut.uit_clock.enabled = 0; ref.caps.enabled_features = DIFFTEST_UIT_F_UART_TX; return test.uit_ingest(); }
  if (name == "same_pc_distinct_uid") {
    observe_access(test); auto a = access(2); a.sampleValue = 123; observe_access(test, a);
    require(test.uit.accesses.size() == 2 && test.uit.accesses.at(1).request.sampleValue == 0x345 &&
            test.uit.accesses.at(2).request.sampleValue == 123, "same-PC samples retain distinct values");
    return 0;
  }
  if (name == "same_pc_distinct_uid_execute") {
    auto first = access(); complete_access(test, first);
    require(test.uit_execute(first.uid, first.instr, first.pc, false) == 0, "first sampled execution");
    // The caller models intervening ordinary loop instructions outside this API.
    ref.pc = first.pc;
    auto second = access(2); second.sampleValue = 123; complete_access(test, second);
    require(test.uit_execute(second.uid, second.instr, second.pc, false) == 0, "second sampled execution");
    require(ref.exec_calls == 2 && ref.last_exec.transaction_uid == 2 && ref.last_exec.sample_payload == 123 &&
            test.uit.control_seq == 2 && test.uit.sample_timer == 2 && test.uit.closed.size() == 2 &&
            test.uit.accesses.empty(), "same-PC samples consumed by their own identities");
    return 0;
  }
  if (name == "out_of_order_samples_execute" || name == "out_of_order_closed_duplicate") {
    auto younger = access(20897); younger.cycle = 10115; younger.sampleValue = 87;
    auto older = access(20895); older.cycle = 10117; older.sampleValue = 91;
    complete_access(test, younger);
    complete_access(test, older);
    require(test.uit_execute(older.uid, older.instr, older.pc, false) == 0 &&
            ref.last_exec.transaction_uid == older.uid && ref.last_exec.sample_payload == 91,
            "older retirement consumes its own later execution sample");
    ref.pc = younger.pc;
    require(test.uit_execute(younger.uid, younger.instr, younger.pc, false) == 0 &&
            ref.last_exec.transaction_uid == younger.uid && ref.last_exec.sample_payload == 87 &&
            ref.exec_calls == 2 && test.uit.control_seq == 2 && test.uit.accesses.empty(),
            "younger retirement consumes its retained earlier execution sample");
    if (name == "out_of_order_closed_duplicate") {
      dut.uit_access = older;
      return test.uit_ingest();
    }
    return 0;
  }
  if (name == "duplicate_access") { observe_access(test); dut.uit_access = access(); return test.uit_ingest(); }
  if (name.rfind("access_", 0) == 0) {
    dut.uit_access = access(); auto &a = dut.uit_access;
    if (name == "access_missing_sample") a.sampleKind = 0;
    else if (name == "access_wrong_csr") a.csr = 0x44;
    else if (name == "access_wrong_funct3") a.funct3 = 3;
    else if (name == "access_epoch") a.epoch = 2;
    else if (name == "access_zero_uid") a.uid = 0;
    else if (name == "access_pending_payload") { a = access(1, 0x44); a.sampleValue = 2; }
    else if (name == "access_unexpected_sample") a.legal = 0;
    else if (name == "access_wrong_sample_kind") a.sampleKind = 2;
    else if (name == "access_overflow") for (uint64_t i = 2; i < UitBridge::capacity + 2; ++i) test.uit.accesses[i] = {};
    else require(false, "known access case");
    return test.uit_ingest();
  }
  if (name == "missing_response_access") {
    dut.uit_response.valid = 1; dut.uit_response.epoch = 1; dut.uit_response.uid = 33;
    return test.uit_ingest();
  }
  if (name == "duplicate_response" || name == "response_wrong_uid" || name == "response_epoch") {
    complete_access(test);
    dut.uit_response.valid = 1; dut.uit_response.epoch = name == "response_epoch" ? 2 : 1;
    dut.uit_response.uid = name == "response_wrong_uid" ? 2 : 1;
    return test.uit_ingest();
  }
  if (name == "snapshot_wrong_uid" || name == "duplicate_snapshot" || name == "snapshot_epoch") {
    complete_access(test);
    dut.uit_snapshot.valid = 1; dut.uit_snapshot.kind = 1;
    dut.uit_snapshot.epoch = name == "snapshot_epoch" ? 2 : 1;
    dut.uit_snapshot.uid = name == "snapshot_wrong_uid" ? 2 : 1;
    return test.uit_ingest();
  }
  if (name == "duplicate_event_snapshot") {
    prepare_event(test); dut.uit_snapshot = test.uit.events.at(1);
    test.uit.events.clear(); require(test.uit_ingest() == 0, "event snapshot intake");
    return test.uit_ingest();
  }
  if (name.rfind("cancel_", 0) == 0) {
    observe_access(test); observe_access(test, access(2));
    dut.uit_cancel[0].valid = 1; dut.uit_cancel[0].epoch = 1; dut.uit_cancel[0].uid = 1;
    dut.uit_cancel[0].reason = name == "cancel_hu_keeps_source" ? 2 : 1;
    dut.uit_cancel[0].hadEffect = name == "cancel_after_effect";
    const int rc = test.uit_ingest();
    if (name == "cancel_after_effect") return rc;
    require(rc == 0 && test.uit.accesses.count(2) == 1, "cancellation preserves unrelated access");
    require(test.uit.accesses.count(1) == (name == "cancel_hu_keeps_source"), "cancellation source lifetime");
    return 0;
  }
  if (name == "readiness" || name == "frame_fifo") {
    observe_access(test);
    dut.commit[0].valid = 1; dut.commit[0].instr = access().instr; dut.uit_retire[0].uid = 1;
    require(!test.uit_ready(dut), "controlled frame waits for response and snapshot");
    if (name == "frame_fifo") {
      require(test.uit_step() == 0 && test.compared_cycles.empty() && test.uit.frames.size() == 1, "blocked first frame");
      clear_frame(test, 12);
      require(test.uit_step() == 0 && test.compared_cycles.empty() && test.uit.frames.size() == 2, "later frame cannot bypass");
    }
    auto &record = test.uit.accesses.at(1); record.responded = true;
    require(!test.uit_ready(* (name == "frame_fifo" ? test.uit.frames.front().get() : &dut)), "snapshot still required");
    record.captured = true;
    if (name == "frame_fifo") {
      clear_frame(test, 13); require(test.uit_step() == 0, "released frame FIFO");
      require(test.compared_cycles == std::vector<uint64_t>({11, 12, 13}) && test.dut == &test.live && test.uit.frames.empty(),
              "FIFO order and live frame pointer restored");
    } else require(test.uit_ready(dut), "complete access releases frame");
    return 0;
  }
  if (name == "frame_overflow") {
    for (size_t i = 0; i < UitBridge::capacity; ++i) test.uit.frames.emplace_back(new DiffTestState{});
    return test.uit_step();
  }
  if (name.rfind("exec_", 0) == 0) {
    auto a = access();
    const bool fault = name == "exec_legal_exception";
    if (fault) { a.legal = 0; a.sampleKind = 0; a.sampleValue = 0; }
    if (name == "exec_uret" || name == "exec_uret_target") {
      a.instr = 0x00200073; a.isUret = 1; a.needRead = 0; a.sampleKind = 0; a.sampleValue = 0;
      ref.next_pc = name == "exec_uret_target" ? 0x80000006 : 0x80000002;
    }
    if (name != "exec_missing") complete_access(test, a);
    if (name == "exec_pc") ++ref.pc;
    if (name == "exec_mode") ref.csr.privilegeMode = 1;
    if (name == "exec_pre_bank") ref.current.uscratch = 1;
    if (name == "exec_post_bank") ref.after.uepc = 2;
    if (name == "exec_result_uid") ref.corrupt_result_uid = true;
    if (name == "exec_result_seq") ref.corrupt_result_seq = true;
    if (name == "exec_result_epoch") ref.corrupt_result_epoch = true;
    if (name == "exec_result_bytes") ref.corrupt_result_bytes = true;
    if (name == "exec_state_epoch") ++ref.current.epoch;
    if (name == "exec_state_bytes") --ref.current.bytes;
    if (name == "exec_state_sequence") ++ref.current.last_control_seq;
    if (name == "exec_sample_consumed") ref.corrupt_consumed = true;
    if (name == "exec_rejected") ref.exec_rc = DIFFTEST_UIT_E_ORDER;
    if (name == "exec_response_rdata") test.uit.accesses.at(1).response.rdata ^= 1;
    if (name == "exec_write_value") test.uit.accesses.at(1).snapshot.writeSeen = true;
    if (fault) { ref.outcome = DIFFTEST_UIT_ISA_EXCEPTION; test.uit.accesses.at(1).response.illegal = 1; }
    const int rc = test.uit_execute(1, a.instr, name == "exec_wrong_transaction" ? a.pc + 4 : a.pc, fault);
    if (name == "exec_valid" || fault || name == "exec_uret") {
      require(rc == 0 && ref.exec_calls == 1 && test.uit.accesses.empty() && test.uit.closed.count(1), "controlled execution consumed once");
      require(ref.last_exec.transaction_uid == 1 && ref.last_exec.diagnostic_pc == a.pc &&
              ref.last_exec.sample_payload == a.sampleValue, "controlled input identity and retained sample");
    }
    return rc;
  }
  if (name.rfind("event_", 0) == 0) {
    if (name != "event_missing") prepare_event(test);
    if (name == "event_pc") ++ref.pc;
    if (name == "event_order") test.uit.event_seq = 1;
    if (name == "event_retirement") ++test.uit.retired;
    if (name == "event_type") dut.event.irToHS = 1;
    if (name == "event_target") ++ref.next_pc;
    if (name == "event_post_bank") ref.after.ucause = 1;
    if (name == "event_rejected") ref.event_rc = DIFFTEST_UIT_E_CONTEXT;
    const int rc = test.uit_event();
    if (name == "event_valid") {
      require(rc == 0 && test.uit.hu_events == 1 && ref.event_calls == 1 && test.uit.events.empty() &&
              test.uit.event_seq == 1 && !dut.event.valid && test.progress, "HU event applied once");
      require(ref.last_event.prior_instruction_count == 5 && ref.last_event.boundary_pc == 0x80001000 &&
              ref.last_event.diagnostic_target == 0x80002000 && ref.last_event.event_uid == 9,
              "HU event preserves reference boundary metadata");
    }
    return rc;
  }
  if (name.rfind("uart_observe_", 0) == 0) {
    test.uit.initialized = true;
    auto &u = dut.uit_uart;
    u.valid = 1; u.epoch = 1; u.cycle = 16000;
    u.address = DIFFTEST_UIT_UART_TX; u.length = 1;
    u.data = name == "uart_observe_upper_lanes" ? 0xa5f09e55 : 0x55555555;
    if (name == "uart_observe_length") u.length = 2;
    if (name == "uart_observe_address") ++u.address;
    if (name == "uart_observe_epoch") ++u.epoch;
    const int intake = test.uit_ingest();
    if (intake) return intake;
    require(test.uit.uart.size() == 1 && test.uit.uart.front().data == 0x55,
            "the fixed single-byte UART write preserves its addressed byte");
    DifftestUitTx tx{}; tx.version = DIFFTEST_UIT_VERSION; tx.bytes = sizeof(tx);
    tx.epoch = 1; tx.address = DIFFTEST_UIT_UART_TX; tx.len = 1;
    tx.data = name == "uart_observe_mismatch" ? 0x54 : 0x55;
    ref.output.push_back(tx);
    const int rc = test.uit_check_uart();
    if (name != "uart_observe_mismatch")
      require(rc == 0 && test.uit.uart_compares == 1 && test.uit.uart.empty(),
              "the observed UART byte reaches the production comparison");
    return rc;
  }
  if (name.rfind("uart_", 0) == 0) {
    test.uit.initialized = true;
    DifftestUserTimerUart u{}; u.epoch = 1; u.address = DIFFTEST_UIT_UART_TX; u.data = 'A'; u.length = 1;
    test.uit.uart.push_back(u);
    if (name != "uart_wait") {
      DifftestUitTx tx{}; tx.version = DIFFTEST_UIT_VERSION; tx.bytes = sizeof(tx);
      tx.epoch = 1; tx.address = DIFFTEST_UIT_UART_TX; tx.len = 1;
      if (name == "uart_header_bytes") --tx.bytes;
      tx.data = name == "uart_mismatch" ? 'B' : 'A'; ref.output.push_back(tx);
    }
    const int rc = test.uit_check_uart();
    if (name == "uart_valid") require(rc == 0 && test.uit.uart_compares == 1 && test.uit.uart.empty(), "UART compare consumed");
    if (name == "uart_wait") require(rc == 0 && test.uit.uart.size() == 1 && test.uit.uart_compares == 0, "UART waits for export");
    return rc;
  }
  if (name.rfind("terminal_", 0) == 0) {
    mature_terminal(test);
    test.uit.initialized = name != "terminal_uninitialized";
    if (name == "terminal_access") test.uit.accesses[1] = {};
    if (name == "terminal_retirement") ++test.uit.retired;
    if (name == "terminal_reference_uart") ref.output.push_back({});
    if (name == "terminal_pending_store") test.store_event_queue.push({});
    return test.uit_finalize();
  }
  require(false, "known test name");
  return 91;
}

int main(int argc, char **argv) {
  require(argc == 3, "expected case and fresh trace path");
  Difftest test;
  test.uit.trace = fopen(argv[2], "wx");
  require(test.uit.trace != nullptr, "fresh trace file");
  clear_frame(test);
  const int result = run_case(test, argv[1]);
  printf("PROTOCOL_UNIT_RESULT case=%s exit=%d fake_reference=true dut_execution=false\n", argv[1], result);
  return result;
}
