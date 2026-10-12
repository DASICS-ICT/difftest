#include "fdi_bridge.h"
#include <cstdlib>
#include <functional>

static void require(bool condition, const char *message) {
  if (!condition) { fprintf(stderr, "FDI_HOST_UNIT_FAILURE: %s\n", message); exit(91); }
}

static DifftestFdiCaps caps{DIFFTEST_FDI_VERSION, sizeof(DifftestFdiCaps), sizeof(DifftestFdiState), 52,
  DIFFTEST_FDI_FEATURES, DIFFTEST_FDI_FEATURES, 64, 1, sizeof(DifftestFdiInit), 1, 2, 0, 0};
static DifftestFdiState state{DIFFTEST_FDI_VERSION, sizeof(DifftestFdiState), 0, DIFFTEST_FDI_PHASE_RESET,
                             0, UINT64_C(0x10000000), {}};
static bool captured, initialized, cross_buffer;
static uint32_t capture_calls, init_calls, state_calls;
static std::string fault;

static int32_t query(void *out, uint32_t bytes) {
  require(bytes == sizeof(caps), "caps transfer size");
#define CAP_FAULT(name) if (fault == "cap_" #name) ++caps.name;
  CAP_FAULT(version) CAP_FAULT(bytes) CAP_FAULT(state_bytes) CAP_FAULT(projection_words)
  CAP_FAULT(supported_features) CAP_FAULT(enabled_features) CAP_FAULT(xlen) CAP_FAULT(max_harts)
  CAP_FAULT(init_bytes) CAP_FAULT(projection_version) CAP_FAULT(machine_abi_major)
  CAP_FAULT(reserved32) CAP_FAULT(reserved64)
#undef CAP_FAULT
  if (fault == "disabled") caps.enabled_features = 0;
  memcpy(out, &caps, bytes);
  if (fault == "caps_canary") static_cast<uint8_t *>(out)[bytes] ^= 0xff;
  return fault == "query_rc" ? DIFFTEST_FDI_E_ABI : DIFFTEST_FDI_OK;
}

static int32_t capture(uint32_t hart, void *out, uint32_t bytes) {
  require(hart == 0 && bytes == sizeof(state), "reset transfer shape");
  ++capture_calls;
  require(!captured && !initialized, "one natural reset observation");
  if (fault == "reference_reset_dirty") state.words[39] = 1;
  if (fault == "reset_header") state.epoch = 1;
  memcpy(out, &state, bytes);
  if (fault == "reset_canary") static_cast<uint8_t *>(out)[bytes] ^= 0xff;
  captured = true;
  return fault == "capture_rc" ? DIFFTEST_FDI_E_STATE : DIFFTEST_FDI_OK;
}

static int32_t initialize(const void *input, uint32_t bytes) {
  const auto &request = *static_cast<const DifftestFdiInit *>(input);
  require(bytes == 32 && request.version == DIFFTEST_FDI_VERSION && request.bytes == 32 && !request.hart &&
          !request.reserved && request.epoch == 7 && request.required_features == 3, "init request contract");
  require(captured && !initialized, "init follows capture once");
  ++init_calls;
  state.phase = DIFFTEST_FDI_PHASE_CURRENT;
  state.epoch = request.epoch;
  initialized = true;
  if (fault == "startup_changes_fdi") state.words[39] = 2;
  return fault == "init_rc" ? DIFFTEST_FDI_E_STATE : DIFFTEST_FDI_OK;
}

static int32_t get_state(uint32_t hart, void *out, uint32_t bytes) {
  require(hart == 0 && bytes == sizeof(state) && initialized, "state export contract");
  ++state_calls;
  memcpy(out, &state, bytes);
  if (cross_buffer) static_cast<uint8_t *>(out)[bytes] ^= 0xff;
  return fault == "state_rc" ? DIFFTEST_FDI_E_STATE : DIFFTEST_FDI_OK;
}

static FdiReferenceApi api() { return {query, capture, initialize, get_state}; }
static FdiObservation reset() {
  FdiObservation p;
  p.kind = FDI_RESET; p.epoch = 7; p.cycle = 10;
  return p;
}
static FdiObservation pre(uint64_t uid = 1, uint64_t cycle = 12) {
  FdiObservation p;
  p.kind = FDI_CSR_PRE; p.epoch = 7; p.uid = uid; p.cycle = cycle;
  p.pc = UINT64_C(0xffffffc080000000) + uid * 4;
  p.instruction = UINT32_C(0x8b009173); // csrrw x2, MainCallEntry, x1
  p.robIdx = uid % 160; p.robFlag = (uid / 160) % 2; p.csrAddress = 0x8b0;
  p.readNeeded = 1; p.writeNeeded = 1; p.permitted = 1;
  return p;
}
static FdiObservation post(const FdiObservation &p) {
  auto result = p;
  result.kind = FDI_CSR_POST; result.cycle += 2; result.actualWrite = p.permitted && p.writeNeeded;
  result.responseIllegal = !p.permitted;
  if (result.actualWrite) result.words[39] = UINT64_C(0xff00880000000001) + p.uid;
  return result;
}
static FdiBoundary boundary(const FdiObservation &p) {
  return {p.epoch, p.uid, p.pc, p.uid - 1, p.uid, 0, p.instruction, p.robIdx, p.robFlag};
}
static DifftestFdiState reference(const FdiObservation &p) {
  DifftestFdiState value{DIFFTEST_FDI_VERSION, sizeof(DifftestFdiState), 0, DIFFTEST_FDI_PHASE_CURRENT,
                         p.epoch, p.pc, {}};
  std::copy(p.words.begin(), p.words.end(), std::begin(value.words));
  return value;
}
static void accepted(FdiLedger &ledger, const FdiObservation &p) {
  require(!ledger.observe(reset()) && !ledger.observe(p), "valid reset and pre");
}
static void finish(FdiLedger &ledger, const FdiObservation &p, const FdiObservation &q) {
  require(!ledger.before(boundary(p), reference(p), false), "compare pre at retirement");
  auto after = reference(q); after.model_pc += 4;
  require(!ledger.after(after), "compare saved post after reference execution");
}

static FdiObservation call_pre(uint64_t uid = 1, uint64_t cycle = 12) {
  auto p = pre(uid, cycle);
  p.kind = FDI_CALL_PRE; p.csrAddress = 0x8b1; p.readNeeded = 0;
  p.instruction = UINT32_C(0x0040000b); // fdicall.j uses its dedicated immediate encoding
  return p;
}

static FdiObservation call_post(const FdiObservation &p) {
  auto q = p;
  q.kind = FDI_CALL_POST; q.cycle++; q.actualWrite = p.permitted;
  q.responseIllegal = !p.permitted;
  if (q.actualWrite) q.words[40] = p.pc + 4;
  return q;
}

static int call_test(const std::string &test) {
  FdiLedger ledger;
  auto p = call_pre();
  if (test == "jr") p.instruction = UINT32_C(0x0040910b);
  if (test == "jr_rd_zero") p.instruction = UINT32_C(0x0000900b);
  const bool illegal = test == "illegal" || test == "illegal_retired" || test == "illegal_changed" ||
      test == "illegal_missing_cancel" || test == "wrong_cancel_reason" || test == "discard";
  if (illegal) p.permitted = 0;
  auto q = call_post(p);
  if (test == "missing_pre") {
    require(!ledger.observe(reset()) && !ledger.ready(p.uid, p.instruction), "call needs acceptance");
    require(ledger.before(boundary(p), reference(p), false), "unobserved call cannot retire");
    return 0;
  }
  if (test == "orphan_post") {
    require(!ledger.observe(reset()) && ledger.observe(q), "call effect needs acceptance");
    return 0;
  }
  if (test == "bad_encoding" || test == "csr_as_call" || test == "call_as_csr" ||
      test == "bad_read" || test == "bad_write" || test == "bad_address") {
    if (test == "bad_encoding") p.instruction ^= UINT32_C(0x2000);
    if (test == "csr_as_call") p.instruction = pre().instruction;
    if (test == "call_as_csr") p.kind = FDI_CSR_PRE;
    if (test == "bad_read") p.readNeeded = 1;
    if (test == "bad_write") p.writeNeeded = 0;
    if (test == "bad_address") p.csrAddress = 0x8b0;
    require(!ledger.observe(reset()) && ledger.observe(p), "call obligations match its encoding");
    return 0;
  }
  accepted(ledger, p);
  if (test == "duplicate_pre") {
    auto duplicate = p; duplicate.cycle++;
    require(ledger.observe(duplicate), "call acceptance cannot repeat across cycles"); return 0;
  }
  if (test == "missing_post") {
    require(!ledger.ready(p.uid, p.instruction) && ledger.before(boundary(p), reference(p), false),
            "call cannot retire without its actual effect snapshot"); return 0;
  }
  if (test == "discard") {
    auto cancel = p; cancel.kind = FDI_CANCEL; cancel.cycle++; cancel.cancelReason = 1;
    require(!ledger.observe(cancel) && ledger.canceled_accesses() == 1 && !ledger.finalize(),
            "discarded no-effect call closes with real cancellation"); return 0;
  }
  if (test == "wrong_uid") q.uid++;
  if (test == "wrong_rob") q.robIdx++;
  if (test == "wrong_pc") q.pc += 4;
  if (test == "wrong_kind") q.kind = FDI_CSR_POST;
  if (test == "late_post") q.cycle++;
  if (test == "missing_effect") q.actualWrite = 0;
  if (test == "wrong_link") q.words[40] += 4;
  if (test == "truncated_link") q.words[40] &= UINT64_C(0xffffffff);
  if (test == "unrelated_word") q.words[41] = 8;
  if (test == "illegal_changed") q.words[40] = p.pc + 4;
  if (test == "wrong_response") q.responseIllegal = 1;
  const int observed = ledger.observe(q);
  if (test == "wrong_uid" || test == "wrong_rob" || test == "wrong_pc" || test == "wrong_kind" ||
      test == "late_post" || test == "missing_effect" || test == "wrong_link" || test == "truncated_link" ||
      test == "unrelated_word" || test == "illegal_changed" || test == "wrong_response") {
    require(observed, "bad call completion must fail"); return 0;
  }
  require(!observed && ledger.ready(p.uid, p.instruction), "call post retained until boundary");
  if (test == "duplicate_post") {
    q.cycle++;
    require(ledger.observe(q), "second call effect is rejected"); return 0;
  }
  if (test == "cancel_after_write") {
    auto cancel = p; cancel.kind = FDI_CANCEL; cancel.cycle += 2; cancel.cancelReason = 1;
    cancel.words = q.words;
    require(ledger.observe(cancel), "committed implicit write cannot be discarded"); return 0;
  }
  if (test == "illegal_retired") {
    require(ledger.before(boundary(p), reference(p), false), "illegal call cannot retire"); return 0;
  }
  if (illegal) {
    auto event = p; event.kind = FDI_TRAP_POST; event.cycle += 3; event.eventSeq = 1;
    require(!ledger.observe(event), "illegal call trap snapshot");
    auto b = boundary(p); b.eventSeq = 1;
    require(!ledger.event_ready(1, p.uid, p.instruction), "illegal call waits for synchronous cancel");
    if (test == "illegal_missing_cancel") {
      require(ledger.before(b, reference(p), true), "missing synchronous cancellation cannot pass"); return 0;
    }
    auto cancel = p; cancel.kind = FDI_CANCEL; cancel.cycle += 4;
    cancel.cancelReason = test == "wrong_cancel_reason" ? 1 : 2;
    require(!ledger.observe(cancel), "observed call cancellation");
    if (test == "wrong_cancel_reason") {
      require(!ledger.event_ready(1, p.uid, p.instruction) && ledger.before(b, reference(p), true),
              "ordinary discard cannot replace synchronous fault cancellation"); return 0;
    }
    require(ledger.event_ready(1, p.uid, p.instruction) && !ledger.before(b, reference(p), true) &&
            !ledger.after(reference(event)) && !ledger.finalize(), "illegal call compared at its real trap");
    return 0;
  }
  if (test == "saved_snapshots" || test == "unchanged_link") {
    auto next = call_pre(2, 16); next.words = q.words;
    if (test == "unchanged_link") next.pc = p.pc;
    auto next_post = call_post(next);
    require(!ledger.observe(next) && !ledger.observe(next_post), "independent younger call snapshots");
    finish(ledger, p, q); finish(ledger, next, next_post);
    require(ledger.compared_retirements() == 2 && !ledger.finalize(), "each call owns one retirement comparison");
    return 0;
  }
  if (test == "reference_mismatch") {
    require(!ledger.before(boundary(p), reference(p), false), "call pre matches reference");
    auto wrong = reference(q); wrong.words[40] ^= 8;
    require(ledger.after(wrong), "real reference call effect must match"); return 0;
  }
  require(test == "j" || test == "jr" || test == "jr_rd_zero", "known call test");
  finish(ledger, p, q);
  require(ledger.compared_retirements() == 1 && !ledger.finalize(), "call comparison closes once");
  return 0;
}

int main(int argc, char **argv) {
  require(argc == 2, "one test name");
  const std::string test = argv[1];
  if (test.compare(0, 5, "call_") == 0) return call_test(test.substr(5));
  if (test.compare(0, 4, "api_") == 0) {
    fault = test.substr(4);
    FdiReference ref;
    auto functions = api();
    if (fault == "missing") functions.state = nullptr;
    const int connection = ref.connect(functions, fault == "hart" ? 1 : 0, fault == "cores" ? 2 : 1);
    if (fault.compare(0, 4, "cap_") == 0 || fault == "disabled" || fault == "missing" || fault == "hart" ||
        fault == "cores" || fault == "caps_canary" || fault == "query_rc") {
      require(connection && capture_calls == 0, "reject before reference reset capture"); return 0;
    }
    require(!connection, "connect good API");
    if (fault == "import_before_reset") { require(ref.startup_import(), "import rejected before reset"); return 0; }
    const int reset_rc = ref.capture_reset();
    if (fault == "reference_reset_dirty" || fault == "reset_header" || fault == "reset_canary" || fault == "capture_rc") {
      require(reset_rc && init_calls == 0, "reject invalid natural reference reset"); return 0;
    }
    require(!reset_rc && ref.natural_reset_pc() == 0x10000000, "retain natural reference PC");
    if (fault == "duplicate_reset") { require(ref.capture_reset() && capture_calls == 1, "one capture only"); return 0; }
    FdiBank dut{};
    if (fault == "dut_reset_dirty") dut[39] = 1;
    const int verify = ref.verify_dut_reset(dut, fault == "epoch_zero" ? 0 : 7);
    if (fault == "dut_reset_dirty" || fault == "epoch_zero") { require(verify, "reject invalid DUT reset"); return 0; }
    require(!verify, "independent DUT reset verified");
    if (fault == "init_before_import") { require(ref.initialize() && !init_calls, "startup order enforced"); return 0; }
    require(!ref.startup_import(), "one initial ordinary import");
    if (fault == "double_import") { require(ref.startup_import(), "duplicate startup import rejected"); return 0; }
    const int init = ref.initialize();
    if (fault == "startup_changes_fdi" || fault == "init_rc" || fault == "state_rc") {
      require(init, "reject altered state or failed initialization"); return 0;
    }
    require(!init && ref.active(), "session initialized");
    if (fault == "runtime_import") { require(ref.startup_import(), "runtime import rejected"); return 0; }
    if (fault == "double_init") { require(ref.initialize() && init_calls == 1, "duplicate init rejected"); return 0; }
    if (fault == "state_header") state.epoch++;
    if (fault == "state_alias") state.words[0] = 2;
    if (fault == "state_reserved") state.words[43] = 2;
    if (fault == "state_canary") cross_buffer = true;
    DifftestFdiState value{};
    const int read = ref.read(value);
    if (fault.compare(0, 6, "state_") == 0) { require(read, "reject malformed state output"); return 0; }
    require(!read && !ref.read(value) && capture_calls == 1 && init_calls == 1 && state_calls == 3,
            "repeated read-only exports do not reinitialize");
    return 0;
  }

  FdiLedger ledger;
  auto p = pre(), q = post(p);
  if (test == "canceled_pre_pollution") {
    require(!ledger.observe(reset()), "natural reset anchor");
    p.words[39] = 3;
    require(ledger.observe(p), "canonical contamination before a canceled access is detected");
    return 0;
  }
  if (test == "same_cycle_pre_post" || test == "same_cycle_lane_disagreement") {
    accepted(ledger, p);
    auto younger = pre(2, q.cycle); younger.words = q.words;
    if (test == "same_cycle_lane_disagreement") younger.words[39] ^= 1;
    const int rc = ledger.observe_frame({younger, q});
    if (test == "same_cycle_lane_disagreement") { require(rc, "same-cycle physical bank must agree"); return 0; }
    require(!rc, "older effect and younger pre are ingested as one bank sample");
    auto later = post(younger);
    require(!ledger.observe(later), "later UID effect");
    finish(ledger, p, q); finish(ledger, younger, later);
    require(!ledger.finalize(), "same-cycle lanes preserve separate transaction snapshots");
    return 0;
  }
  if (test == "interrupt_wrong_cancel_reason") {
    accepted(ledger, p);
    auto cancel = p; cancel.kind = FDI_CANCEL; cancel.cancelReason = 1; cancel.cycle++;
    require(!ledger.observe(cancel), "ordinary discard recorded");
    auto e = p; e.kind = FDI_TRAP_POST; e.eventSeq = 1; e.cycle += 8;
    require(!ledger.observe(e), "trap observation");
    auto b = boundary(p); b.eventSeq = 1; b.asynchronous = true;
    require(ledger.before(b, reference(p), true), "interrupt cannot relabel an ordinary flush");
    return 0;
  }
  if (test == "interrupt_before_acceptance" || test == "interrupt_canceled_read" || test == "interrupt_before_cancel") {
    require(!ledger.observe(reset()), "natural DUT reset");
    p.instruction = UINT32_C(0x8b002173); p.writeNeeded = 0;
    auto e = p; e.kind = FDI_TRAP_POST; e.cycle += 8; e.eventSeq = 1; e.beforeCount = 0;
    if (test != "interrupt_before_acceptance") {
      require(!ledger.observe(p) && !ledger.observe(post(p)), "read accepted before interrupt");
    }
    if (test != "interrupt_canceled_read") require(!ledger.observe(e), "interrupt snapshot naming unexecuted CSR encoding");
    if (test != "interrupt_before_acceptance") {
      require(!ledger.event_ready(1, p.uid, p.instruction, true), "interrupt waits for discard evidence");
      auto cancel = p; cancel.kind = FDI_CANCEL; cancel.cycle += 9; cancel.cancelReason = 3;
      require(!ledger.observe(cancel), "actual interrupt cancellation");
    }
    if (test == "interrupt_canceled_read") { e.cycle += 2; require(!ledger.observe(e), "interrupt snapshot follows cancellation"); }
    require(ledger.event_ready(1, p.uid, p.instruction, true), "interrupt needs no executed CSR transaction");
    auto b = boundary(p); b.eventSeq = 1; b.asynchronous = true;
    require(!ledger.before(b, reference(p), true) && !ledger.after(reference(e)) && !ledger.finalize(),
            "interrupt-only boundary compared without executing CSR");
    return 0;
  }
  if (test == "duplicate_event_uid") {
    require(!ledger.observe(reset()), "reset before event");
    auto e = p; e.kind = FDI_TRAP_POST; e.eventSeq = 1;
    require(!ledger.observe(e), "first trap UID");
    e.eventSeq++; e.cycle++;
    require(ledger.observe(e), "different event sequence cannot reuse trap UID");
    return 0;
  }
  if (test == "all_words_mismatch") {
    for (size_t word = 0; word < 52; ++word) {
      FdiLedger candidate;
      accepted(candidate, p);
      require(!candidate.observe(q) && !candidate.before(boundary(p), reference(p), false), "accept mismatch fixture");
      auto value = reference(q);
      value.words[word] ^= (word >= 2 && word <= 5) || (word >= 7 && word <= 38) || word >= 44 ? 8 : 1;
      require(candidate.after(value), "every projected word is compared");
    }
    return 0;
  }
  if (test == "both_reset_dirty") {
    auto r = reset(); r.words[39] = 1;
    require(ledger.observe(r), "same polluted DUT/REF reset cannot compare equal"); return 0;
  }
  if (test == "no_reset") { require(ledger.observe(p), "pre needs natural reset"); return 0; }
  if (test == "duplicate_reset") {
    require(!ledger.observe(reset()) && ledger.observe(reset()), "warm reset rejected"); return 0;
  }
  if (test == "orphan_post") {
    require(!ledger.observe(reset()) && ledger.observe(q), "post needs acceptance"); return 0;
  }
  if (test == "wrong_epoch") {
    p.epoch++; require(!ledger.observe(reset()) && ledger.observe(p), "wrong epoch rejected"); return 0;
  }
  if (test == "bad_read_obligation" || test == "bad_write_obligation") {
    if (test == "bad_read_obligation") p.readNeeded = 0; else p.writeNeeded = 0;
    require(!ledger.observe(reset()) && ledger.observe(p), "independently decoded access obligation"); return 0;
  }
  if (test == "alias_pollution" || test == "reserved_pollution") {
    if (test == "alias_pollution") p.words[0] = 2; else p.words[7] = 1;
    require(!ledger.observe(reset()) && ledger.observe(p), "raw projection invariant checked"); return 0;
  }
  if (test == "readonly" || test == "readonly_changed") {
    p.instruction = UINT32_C(0x8b002173); p.writeNeeded = 0; q = post(p);
    if (test == "readonly_changed") q.words[39] = 1;
  }
  if (test == "illegal" || test == "illegal_retired" || test == "sync_cancel" || test == "wrong_event" || test == "event_before_cancel" || test == "trap_before_acceptance") {
    p.permitted = 0; q = post(p);
  }
  if (test == "reason_seven") {
    p.instruction = UINT32_C(0x8b309173); p.csrAddress = 0x8b3;
    q = post(p); q.words[39] = 0; q.words[42] = 7;
  }
  accepted(ledger, p);
  if (test == "duplicate_pre") { require(ledger.observe(p), "repeated pre rejected"); return 0; }
  if (test == "missing_post") {
    require(!ledger.ready(p.uid, p.instruction) && ledger.before(boundary(p), reference(p), false), "missing post cannot skip comparison"); return 0;
  }
  if (test == "unfinished") { require(ledger.finalize(), "unconsumed transaction rejected"); return 0; }
  if (test == "same_cycle_post") q.cycle = p.cycle;
  if (test == "wrong_rob") q.robFlag ^= 1;
  if (test == "wrong_pc") q.pc ^= 2;
  if (test == "wrong_uid") q.uid++;
  if (test == "missing_effect") q.actualWrite = 0;
  if (test == "virtual_fault") q.responseVirtual = 1;
  if (test == "cancel" || test == "sync_cancel") {
    q = p; q.kind = FDI_CANCEL; q.cycle++; q.cancelReason = test == "sync_cancel" ? 2 : 1;
  }
  const int observed = ledger.observe(q);
  if (test == "same_cycle_post" || test == "wrong_rob" || test == "wrong_pc" || test == "wrong_uid" ||
      test == "missing_effect" || test == "virtual_fault" || test == "readonly_changed") {
    require(observed, "invalid completion rejected"); return 0;
  }
  require(!observed, "valid post/cancellation");
  if (test == "cancel") { require(ledger.canceled_accesses() == 1 && !ledger.finalize(), "canceled access closed with real evidence"); return 0; }
  if (test == "duplicate_post") { require(ledger.observe(q), "repeated post rejected"); return 0; }
  if (test == "cancel_after_write") {
    q.kind = FDI_CANCEL; q.cycle++; q.cancelReason = 1;
    require(ledger.observe(q), "applied write cannot disappear under cancellation"); return 0;
  }
  if (test == "illegal" || test == "sync_cancel" || test == "wrong_event" || test == "event_before_cancel" || test == "trap_before_acceptance") {
    auto e = p; e.kind = FDI_TRAP_POST; e.cycle += 8; e.eventSeq = 1; e.beforeCount = 0;
    if (test == "trap_before_acceptance") e.cycle = p.cycle - 1;
    if (test == "trap_before_acceptance") {
      require(ledger.observe(e), "trap sampling cannot move before acceptance"); return 0;
    }
    require(!ledger.observe(e), "actual trap snapshot");
    if (test == "event_before_cancel") require(!ledger.event_ready(1, p.uid, p.instruction), "wait for redirect after trap snapshot");
    if (test != "sync_cancel") {
      auto cancel = p; cancel.kind = FDI_CANCEL; cancel.cycle += 9; cancel.cancelReason = 2;
      require(!ledger.observe(cancel), "matching synchronous redirect");
    }
    auto b = boundary(p); b.eventSeq = test == "wrong_event" ? 2 : 1;
    const int before = ledger.before(b, reference(p), true);
    if (test == "wrong_event" || test == "trap_before_acceptance") { require(before, "wrong event identity/order rejected"); return 0; }
    require(!before && !ledger.after(reference(e)) && ledger.compared_events() == 1 && !ledger.finalize(), "exception compared independently"); return 0;
  }
  if (test == "illegal_retired") {
    require(ledger.before(boundary(p), reference(p), false), "illegal access cannot retire"); return 0;
  }
  if (test == "saved_snapshots") {
    auto younger = pre(2, 20); younger.words = q.words;
    auto later = post(younger);
    require(!ledger.observe(younger) && !ledger.observe(later), "both effects precede delayed retirement");
    finish(ledger, p, q); finish(ledger, younger, later);
    require(ledger.compared_retirements() == 2 && !ledger.finalize(), "UID snapshots prevent live-bank miscomparison"); return 0;
  }
  if (test == "bad_retired_identity") {
    auto b = boundary(p); b.robIdx++;
    require(ledger.before(b, reference(p), false), "retirement ROB checked"); return 0;
  }
  require(!ledger.before(boundary(p), reference(p), false), "begin existing execution once");
  if (test == "execute_twice") {
    require(ledger.before(boundary(p), reference(p), false), "second execution bracket rejected"); return 0;
  }
  auto exported = reference(q);
  if (test == "single_word_mismatch") exported.words[39] ^= 1;
  if (test == "full_pointer_mismatch") exported.words[39] ^= UINT64_C(1) << 63;
  if (test == "reference_alias_pollution") exported.words[0] = 2;
  const int compared = ledger.after(exported);
  if (test == "single_word_mismatch" || test == "full_pointer_mismatch" || test == "reference_alias_pollution") {
    require(compared, "raw reference mismatch detected"); return 0;
  }
  require(!compared, "matching independent output");
  if (test == "duplicate_retirement") {
    require(ledger.before(boundary(p), reference(p), false), "completed UID cannot execute again"); return 0;
  }
  require(ledger.compared_retirements() == 1 && !ledger.finalize(), "normal comparison finalized");
  puts("FDI_HOST_UNIT_PASS: synthetic observations and fake API, no DUT or ISA execution");
  return 0;
}
