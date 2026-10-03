#ifndef FDI_BRIDGE_H
#define FDI_BRIDGE_H

#include "difftest-fdi.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

using FdiBank = std::array<uint64_t, DIFFTEST_FDI_PROJECTION_WORDS>;

inline uint64_t fdi_word_mask(size_t word) {
  if (word == 0) return UINT64_C(0x7ff);
  if (word == 1) return UINT64_C(0x7c2);
  if (word == 6) return UINT64_C(0xbbbbbbbbbbbbbbbb);
  if (word == 42) return UINT64_C(7);
  if (word == 43) return UINT64_C(0x0001000100010001);
  if (word >= 39 && word <= 41) return UINT64_MAX;
  return UINT64_MAX - 7;
}

// Check the raw projection before comparing it. Masking either operand here
// would conceal reserved-bit corruption and a broken shared MainCfg alias.
inline bool fdi_canonical(const FdiBank &bank, size_t &bad_word) {
  for (size_t i = 0; i < bank.size(); ++i) {
    if (bank[i] & ~fdi_word_mask(i)) { bad_word = i; return false; }
  }
  if (bank[1] != (bank[0] & UINT64_C(0x7c2))) { bad_word = 1; return false; }
  return true;
}

inline bool fdi_is_csr(uint32_t instruction) {
  if ((instruction & 0x7f) != 0x73 || !(instruction & 0x3000)) return false;
  const uint32_t address = instruction >> 20;
  return (address >= 0xbc4 && address <= 0xbc6) || (address >= 0x9e1 && address <= 0x9e3) ||
         address == 0x880 || (address >= 0x890 && address <= 0x8af) ||
         (address >= 0x8b0 && address <= 0x8b3) || (address >= 0x8c0 && address <= 0x8c8);
}

class FdiFailure {
public:
  bool failed() const { return !diagnostic.empty(); }
  const std::string &error() const { return diagnostic; }
  int fail(const char *reason, uint64_t uid = 0, size_t word = 52) {
    if (!failed()) {
      diagnostic = reason;
      fprintf(stderr, "FDI protocol failure: %s (uid=%llu, word=%zu)\n", reason,
              static_cast<unsigned long long>(uid), word);
    }
    return 1;
  }

private:
  std::string diagnostic;
};

// The function table is only a transport adapter. There is deliberately no
// import, instruction execution, reset, or DUT-value injection operation.
struct FdiReferenceApi {
  decltype(&difftest_fdi_query_caps) query = nullptr;
  decltype(&difftest_fdi_capture_reset) capture = nullptr;
  decltype(&difftest_fdi_init) initialize = nullptr;
  decltype(&difftest_fdi_get_state) state = nullptr;
};

class FdiReference : public FdiFailure {
public:
  int connect(FdiReferenceApi functions, uint32_t hart, uint32_t harts) {
    if (failed()) return 1;
    if (connected || hart || harts != 1) return fail("unsupported reference hart or duplicate connection");
    if (!functions.query || !functions.capture || !functions.initialize || !functions.state)
      return fail("missing FDI reference symbol");
    api = functions;
    Guarded<DifftestFdiCaps> output;
    if (api.query(&output.value, sizeof(output.value)) != DIFFTEST_FDI_OK)
      return fail("FDI capability query failed");
    if (!output.intact()) return fail("FDI capability output crossed its buffer");
    caps = output.value;
    if (caps.version != DIFFTEST_FDI_VERSION || caps.bytes != sizeof(caps) ||
        caps.state_bytes != sizeof(DifftestFdiState) || caps.projection_words != 52 ||
        caps.supported_features != DIFFTEST_FDI_FEATURES || caps.enabled_features != DIFFTEST_FDI_FEATURES ||
        caps.xlen != 64 || caps.max_harts != 1 || caps.init_bytes != sizeof(DifftestFdiInit) ||
        caps.projection_version != DIFFTEST_FDI_PROJECTION_VERSION ||
        caps.machine_abi_major != DIFFTEST_FDI_MACHINE_ABI_MAJOR || caps.reserved32 || caps.reserved64)
      return fail("FDI capabilities do not match the enabled DUT contract");
    connected = true;
    return 0;
  }

  // Called immediately after the model's natural initialization, before any
  // ordinary register import. Capturing a later zero bank is not equivalent.
  int capture_reset() {
    if (failed()) return 1;
    if (!connected || captured) return fail("invalid reference reset capture lifecycle");
    Guarded<DifftestFdiState> output;
    if (api.capture(0, &output.value, sizeof(output.value)) != DIFFTEST_FDI_OK)
      return fail("reference rejected reset capture before import");
    if (!output.intact()) return fail("FDI reset output crossed its buffer");
    if (check_state(output.value, DIFFTEST_FDI_PHASE_RESET, 0)) return 1;
    reference_reset = bank_of(output.value);
    if (reference_reset != FdiBank{}) return fail("reference natural reset is not zero");
    reset_pc = output.value.model_pc;
    captured = true;
    return 0;
  }

  int verify_dut_reset(const FdiBank &bank, uint64_t epoch) {
    if (failed()) return 1;
    if (!captured || reset_verified || !epoch) return fail("invalid DUT reset verification lifecycle");
    size_t bad_word = 52;
    if (!fdi_canonical(bank, bad_word)) return fail("DUT reset projection is not canonical", 0, bad_word);
    if (bank != FdiBank{}) return fail("DUT natural reset is not zero");
    if (bank != reference_reset) return fail("DUT and reference reset projections differ");
    session_epoch = epoch;
    reset_verified = true;
    return 0;
  }

  int startup_import() {
    if (failed()) return 1;
    if (!reset_verified || imported || initialized)
      return fail("ordinary state import outside the single verified startup boundary");
    imported = true;
    return 0;
  }

  int initialize() {
    if (failed()) return 1;
    if (!imported || initialized) return fail("invalid FDI initialization lifecycle");
    const DifftestFdiInit input{DIFFTEST_FDI_VERSION, sizeof(DifftestFdiInit), 0, 0,
                              session_epoch, DIFFTEST_FDI_FEATURES};
    if (api.initialize(&input, sizeof(input)) != DIFFTEST_FDI_OK)
      return fail("reference rejected FDI initialization");
    initialized = true;
    DifftestFdiState current{};
    if (read(current)) return 1;
    if (bank_of(current) != reference_reset) return fail("startup synchronization changed FDI state");
    return 0;
  }

  int read(DifftestFdiState &state) {
    if (failed()) return 1;
    if (!initialized) return fail("FDI state export before initialization");
    Guarded<DifftestFdiState> output;
    if (api.state(0, &output.value, sizeof(output.value)) != DIFFTEST_FDI_OK)
      return fail("FDI reference state export failed");
    if (!output.intact()) return fail("FDI state output crossed its buffer");
    if (check_state(output.value, DIFFTEST_FDI_PHASE_CURRENT, session_epoch)) return 1;
    state = output.value;
    return 0;
  }

  uint64_t epoch() const { return session_epoch; }
  uint64_t natural_reset_pc() const { return reset_pc; }
  bool active() const { return initialized && !failed(); }
  static FdiBank bank_of(const DifftestFdiState &state) {
    FdiBank bank;
    std::copy(std::begin(state.words), std::end(state.words), bank.begin());
    return bank;
  }

private:
  template <typename T> struct Guarded {
    uint64_t before = UINT64_C(0xeac713b8609df245);
    T value{};
    uint64_t after = UINT64_C(0xa519ce207b3648df);
    bool intact() const {
      return before == UINT64_C(0xeac713b8609df245) && after == UINT64_C(0xa519ce207b3648df);
    }
  };
  int check_state(const DifftestFdiState &state, uint32_t phase, uint64_t epoch) {
    if (state.version != DIFFTEST_FDI_VERSION || state.bytes != sizeof(state) || state.hart ||
        state.phase != phase || state.epoch != epoch) return fail("FDI state header mismatch");
    size_t bad_word = 52;
    if (!fdi_canonical(bank_of(state), bad_word))
      return fail("reference state projection is not canonical", 0, bad_word);
    return 0;
  }
  FdiReferenceApi api;
  DifftestFdiCaps caps{};
  FdiBank reference_reset{};
  bool connected = false, captured = false, reset_verified = false, imported = false, initialized = false;
  uint64_t session_epoch = 0, reset_pc = 0;
};

enum FdiObservationKind : uint8_t {
  FDI_RESET = 1, FDI_CSR_PRE = 2, FDI_CSR_POST = 3, FDI_TRAP_POST = 4, FDI_CANCEL = 5
};

// Logical host input, independent of the generated DPI layout and the public
// reference ABI. The adapter copies every field from the real observation.
struct FdiObservation {
  uint64_t epoch = 0, uid = 0, cycle = 0, pc = 0, eventSeq = 0, beforeCount = 0;
  uint32_t instruction = 0;
  uint16_t robIdx = 0, csrAddress = 0;
  uint8_t kind = 0, robFlag = 0, readNeeded = 0, writeNeeded = 0, permitted = 0;
  uint8_t actualWrite = 0, responseIllegal = 0, responseVirtual = 0, cancelReason = 0;
  FdiBank words{};
};

struct FdiBoundary {
  uint64_t epoch = 0, uid = 0, pc = 0, beforeCount = 0, afterCount = 0, eventSeq = 0;
  uint32_t instruction = 0;
  uint16_t robIdx = 0;
  uint8_t robFlag = 0;
  bool asynchronous = false;
};

class FdiLedger : public FdiFailure {
public:
  static constexpr size_t capacity = 4096;

  int observe(const FdiObservation &packet) {
    return observe_frame({packet});
  }

  int observe_frame(const std::vector<FdiObservation> &packets) {
    if (failed()) return 1;
    if (packets.empty()) return 0;
    const auto &sample = packets.front();
    if (sample_seen && sample.cycle <= sample_cycle)
      return fail("FDI sample cycle repeated or moved backwards", sample.uid);
    bool effect = false;
    for (const auto &packet : packets) {
      if (packet.cycle != sample.cycle || packet.words != sample.words)
        return fail("FDI lanes disagree about their shared bank sampling cycle", packet.uid);
      effect |= (packet.kind == FDI_CSR_POST && packet.actualWrite) || packet.kind == FDI_TRAP_POST;
    }
    // All lanes sample the same physical bank in this cycle. Apply this check
    // once per frame so a simultaneous older post and younger pre are ordered
    // by their real effects, not by lane number or delayed reference progress.
    if (sample_seen && sample.words != observed_bank && !effect)
      return fail("DUT FDI state changed without an observed effect", sample.uid);
    observed_bank = sample.words;
    sample_cycle = sample.cycle;
    sample_seen = true;
    for (const auto &packet : packets) if (observe_packet(packet)) return 1;
    return 0;
  }

private:
  int observe_packet(const FdiObservation &packet) {
    if (failed()) return 1;
    if (finalized) return fail("observation after finalization", packet.uid);
    size_t bad_word = 52;
    if (!fdi_canonical(packet.words, bad_word)) return fail("DUT projection is not canonical", packet.uid, bad_word);
    if (packet.kind == FDI_RESET) {
      if (reset_seen || !packet.epoch || packet.uid || packet.actualWrite || packet.words != FdiBank{})
        return fail("invalid, polluted, or repeated DUT natural reset", packet.uid);
      reset_seen = true;
      session_epoch = packet.epoch;
      reset_cycle = packet.cycle;
      reset_bank = packet.words;
      return 0;
    }
    if (!reset_seen || packet.epoch != session_epoch || !packet.uid || packet.cycle <= reset_cycle)
      return fail("observation outside the reset epoch", packet.uid);
    if (packet.robFlag > 1 || packet.readNeeded > 1 || packet.writeNeeded > 1 || packet.permitted > 1 ||
        packet.actualWrite > 1 || packet.responseIllegal > 1 || packet.responseVirtual > 1)
      return fail("non-boolean observation field", packet.uid);
    if (packet.kind == FDI_TRAP_POST) {
      if (!packet.eventSeq || events.count(packet.eventSeq) || closed_events.count(packet.eventSeq) ||
          event_uids.count(packet.uid) || consumed.count(packet.uid) ||
          events.size() >= capacity) return fail("duplicate or invalid trap observation", packet.uid);
      events.emplace(packet.eventSeq, packet);
      event_uids.insert(packet.uid);
      return 0;
    }
    if (closed.count(packet.uid)) return fail("observation for a closed UID", packet.uid);
    if (packet.kind == FDI_CSR_PRE) {
      if (!fdi_is_csr(packet.instruction) || packet.csrAddress != packet.instruction >> 20 ||
          packet.actualWrite || packet.cancelReason || transactions.count(packet.uid) ||
          transactions.size() >= capacity) return fail("invalid or duplicate FDI acceptance", packet.uid);
      const uint32_t operation = (packet.instruction >> 12) & 3;
      const bool read = operation != 1 || ((packet.instruction >> 7) & 31);
      const bool write = operation == 1 || ((packet.instruction >> 15) & 31);
      if (bool(packet.readNeeded) != read || bool(packet.writeNeeded) != write)
        return fail("FDI access obligations differ from the instruction", packet.uid);
      Transaction value;
      value.pre = packet;
      transactions.emplace(packet.uid, value);
      return 0;
    }
    auto found = transactions.find(packet.uid);
    if (found == transactions.end()) return fail("FDI completion has no acceptance", packet.uid);
    auto &transaction = found->second;
    const auto &pre = transaction.pre;
    if (!same_access(pre, packet) || packet.cycle <= pre.cycle)
      return fail("FDI completion identity or cycle mismatch", packet.uid);
    if (packet.kind == FDI_CSR_POST) {
      if (transaction.post_seen || transaction.cancel_seen || packet.cancelReason)
        return fail("duplicate or canceled FDI post state", packet.uid);
      if (packet.responseVirtual || bool(packet.responseIllegal) == bool(pre.permitted))
        return fail("FDI response does not match acceptance permission", packet.uid);
      if (bool(packet.actualWrite) != bool(pre.permitted && pre.writeNeeded))
        return fail("FDI write effect is missing or unexpected", packet.uid);
      if (!packet.actualWrite && packet.words != pre.words)
        return fail("non-writing FDI transaction changed state", packet.uid);
      transaction.post = packet;
      transaction.post_seen = true;
      return 0;
    }
    if (packet.kind != FDI_CANCEL || transaction.cancel_seen || packet.cancelReason < 1 || packet.cancelReason > 3)
      return fail("invalid or repeated FDI cancellation", packet.uid);
    if (packet.actualWrite || (transaction.post_seen && transaction.post.actualWrite))
      return fail("discarded FDI transaction already changed state", packet.uid);
    if (packet.words != pre.words || (transaction.post_seen && packet.words != transaction.post.words))
      return fail("canceled FDI transaction changed state", packet.uid);
    transaction.cancel_seen = true;
    transaction.cancel_reason = packet.cancelReason;
    if (!transaction.post_seen) {
      // A cancellation before the normal post stage owns a real sampled bank;
      // it must not synthesize a successful post record from the pre value.
      transaction.post = packet;
      transaction.post_seen = true;
    }
    if (packet.cancelReason != 2) {
      closed.insert(packet.uid);
      discarded.emplace(packet.uid, packet.cancelReason);
      transactions.erase(found);
      ++cancellations;
    }
    return 0;
  }

public:
  bool ready(uint64_t uid, uint32_t instruction) const {
    if (!fdi_is_csr(instruction)) return true;
    const auto found = transactions.find(uid);
    return found != transactions.end() && found->second.post_seen;
  }

  bool event_ready(uint64_t sequence, uint64_t uid, uint32_t instruction, bool asynchronous = false) const {
    // exceptionInst may name the interrupted instruction even though the
    // reference must only raise an interrupt, not execute that instruction.
    if (asynchronous) return events.count(sequence) && !transactions.count(uid);
    if (!events.count(sequence) || !ready(uid, instruction)) return false;
    if (!fdi_is_csr(instruction)) return true;
    const auto &transaction = transactions.at(uid);
    // Trap state can reach the transport before the redirect cancellation.
    // Keep the accepted fault UID alive until both pieces of evidence arrive.
    return transaction.cancel_seen && transaction.cancel_reason == 2;
  }

  // These calls bracket the existing reference execution; they never execute
  // an instruction themselves, including for FDI CSR accesses.
  int before(const FdiBoundary &boundary, const DifftestFdiState &reference, bool event) {
    if (failed()) return 1;
    if (finalized || executing || !reset_seen || boundary.epoch != session_epoch || !boundary.uid ||
        boundary.robFlag > 1 || (!event && boundary.asynchronous) || consumed.count(boundary.uid) ||
        (event ? !boundary.eventSeq : boundary.eventSeq != 0))
      return fail("invalid architectural FDI comparison boundary", boundary.uid);
    if (check_reference(reference)) return 1;
    if (reference.model_pc != boundary.pc) return fail("reference PC differs from FDI source boundary", boundary.uid);
    if (FdiReference::bank_of(reference) != model_bank)
      return fail("reference FDI state changed outside a compared boundary", boundary.uid);
    auto found = transactions.find(boundary.uid);
    const bool csr_instruction = fdi_is_csr(boundary.instruction) && !boundary.asynchronous;
    if (csr_instruction) {
      if (found == transactions.end() || !found->second.post_seen || closed.count(boundary.uid))
        return fail("missing FDI transaction at architectural boundary", boundary.uid);
      const auto &transaction = found->second;
      if (!same_boundary(transaction.pre, boundary) ||
          transaction.pre.words != FdiReference::bank_of(reference))
        return fail("FDI pre state or retirement identity mismatch", boundary.uid);
      if (event) {
        if (!transaction.cancel_seen || transaction.cancel_reason != 2 ||
            (transaction.pre.permitted && !transaction.post.responseIllegal))
          return fail("FDI fault lacks its matching synchronous cancellation", boundary.uid);
      } else if (transaction.cancel_seen || transaction.post.responseIllegal || transaction.post.responseVirtual) {
        return fail("canceled or faulting FDI transaction retired", boundary.uid);
      }
    } else if (found != transactions.end()) {
      return fail("FDI acceptance paired with a different instruction", boundary.uid);
    }
    if (boundary.asynchronous && discarded.count(boundary.uid) && discarded.at(boundary.uid) != 3)
      return fail("interrupt boundary has a different cancellation cause", boundary.uid);
    if (event) {
      const auto snapshot = events.find(boundary.eventSeq);
      if (snapshot == events.end() || closed_events.count(boundary.eventSeq) ||
          !same_boundary(snapshot->second, boundary) || snapshot->second.beforeCount != boundary.beforeCount)
        return fail("trap snapshot does not match its architectural boundary", boundary.uid);
      if (csr_instruction && (snapshot->second.cycle <= found->second.pre.cycle ||
          (found->second.post.kind == FDI_CSR_POST && snapshot->second.cycle < found->second.post.cycle)))
        return fail("FDI trap snapshot precedes its accepted transaction", boundary.uid);
      expected = snapshot->second.words;
    } else {
      if (closed.count(boundary.uid)) return fail("architectural UID executed more than once", boundary.uid);
      if (boundary.afterCount <= boundary.beforeCount)
        return fail("invalid retirement count", boundary.uid);
      if (csr_instruction && boundary.afterCount - boundary.beforeCount != 1)
        return fail("FDI CSR retirement was fused", boundary.uid);
      expected = found == transactions.end() ? model_bank : found->second.post.words;
    }
    active_boundary = boundary;
    active_event = event;
    executing = true;
    return 0;
  }

  int after(const DifftestFdiState &reference) {
    if (failed()) return 1;
    if (!executing) return fail("FDI comparison without a pending architectural boundary");
    if (check_reference(reference)) return 1;
    const auto actual = FdiReference::bank_of(reference);
    for (size_t word = 0; word < expected.size(); ++word)
      if (expected[word] != actual[word]) return fail("FDI architectural state mismatch", active_boundary.uid, word);
    model_bank = actual;
    auto transaction = transactions.find(active_boundary.uid);
    if (transaction != transactions.end()) transactions.erase(transaction);
    if (active_event) {
      events.erase(active_boundary.eventSeq);
      closed_events.insert(active_boundary.eventSeq);
      ++event_comparisons;
    } else {
      ++retire_comparisons;
    }
    closed.insert(active_boundary.uid);
    consumed.insert(active_boundary.uid);
    executing = false;
    return 0;
  }

  int finalize() {
    if (failed()) return 1;
    if (finalized || !reset_seen || executing || !transactions.empty() || !events.empty() || observed_bank != model_bank)
      return fail("FDI comparison ended with missing or unconsumed observations");
    finalized = true;
    return 0;
  }

  bool has_reset() const { return reset_seen; }
  const FdiBank &natural_reset() const { return reset_bank; }
  uint64_t epoch() const { return session_epoch; }
  uint64_t compared_retirements() const { return retire_comparisons; }
  uint64_t compared_events() const { return event_comparisons; }
  uint64_t canceled_accesses() const { return cancellations; }
  uint64_t current_uid() const { return active_boundary.uid; }
  uint64_t current_event_sequence() const { return active_boundary.eventSeq; }
  size_t pending() const { return transactions.size() + events.size(); }

private:
  struct Transaction {
    FdiObservation pre, post;
    bool post_seen = false, cancel_seen = false;
    uint8_t cancel_reason = 0;
  };
  static bool same_access(const FdiObservation &a, const FdiObservation &b) {
    return a.epoch == b.epoch && a.uid == b.uid && a.robIdx == b.robIdx && a.robFlag == b.robFlag &&
           a.pc == b.pc && a.instruction == b.instruction && a.csrAddress == b.csrAddress &&
           a.readNeeded == b.readNeeded && a.writeNeeded == b.writeNeeded && a.permitted == b.permitted;
  }
  static bool same_boundary(const FdiObservation &a, const FdiBoundary &b) {
    return a.epoch == b.epoch && a.uid == b.uid && a.robIdx == b.robIdx && a.robFlag == b.robFlag &&
           a.pc == b.pc && a.instruction == b.instruction;
  }
  int check_reference(const DifftestFdiState &state) {
    if (state.version != DIFFTEST_FDI_VERSION || state.bytes != sizeof(state) || state.hart ||
        state.phase != DIFFTEST_FDI_PHASE_CURRENT || state.epoch != session_epoch)
      return fail("reference comparison state header mismatch");
    size_t bad_word = 52;
    if (!fdi_canonical(FdiReference::bank_of(state), bad_word))
      return fail("reference comparison projection is not canonical", 0, bad_word);
    return 0;
  }
  std::map<uint64_t, Transaction> transactions;
  std::map<uint64_t, FdiObservation> events;
  std::map<uint64_t, uint8_t> discarded;
  std::set<uint64_t> closed, closed_events, event_uids, consumed;
  bool reset_seen = false, finalized = false, executing = false, active_event = false, sample_seen = false;
  uint64_t session_epoch = 0, reset_cycle = 0;
  uint64_t retire_comparisons = 0, event_comparisons = 0, cancellations = 0;
  uint64_t sample_cycle = 0;
  FdiBank reset_bank{}, model_bank{}, expected{}, observed_bank{};
  FdiBoundary active_boundary;
};

#endif
