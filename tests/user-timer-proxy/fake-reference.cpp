#include "difftest-user-timer.h"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// This library exercises the host ABI only; it does not execute an ISA model.
static std::array<uint64_t, 175> registers;
static uint32_t imports, exports;
static bool initialized;

static int32_t api_rc() {
  const char *value = getenv("FAKE_UIT_API_RC");
  return value ? static_cast<int32_t>(strtol(value, nullptr, 0)) : DIFFTEST_UIT_OK;
}

extern "C" {
void difftest_init() { puts("FAKE_REFERENCE_INITIALIZED"); }
void difftest_regcpy(void *buffer, bool to_reference) {
  if (to_reference) {
    ++imports;
    if (initialized) {
      fputs("FAKE_REFERENCE_RUNTIME_IMPORT_REACHED\n", stderr);
      exit(92);
    }
    memcpy(registers.data(), buffer, sizeof(registers));
    for (size_t i = 0; i < registers.size(); ++i) {
      if (registers[i] != UINT64_C(0xa700000000000000) + i) {
        fprintf(stderr, "FAKE_REFERENCE_IMPORT_WORD_MISMATCH index=%zu\n", i);
        exit(93);
      }
    }
  } else {
    ++exports;
    for (size_t i = 0; i < registers.size(); ++i) registers[i] = UINT64_C(0xb800000000000000) + i;
    memcpy(buffer, registers.data(), sizeof(registers));
  }
}
void difftest_csrcpy(void *, bool) { abort(); }
void difftest_memcpy(uint64_t, void *, size_t, bool) { abort(); }
void difftest_exec(uint64_t) { abort(); }
void difftest_display() {}
void update_dynamic_config(void *) {}
void difftest_uarchstatus_sync(void *) { abort(); }
int difftest_store_commit(uint64_t *, uint64_t *, uint8_t *) { return 0; }
void difftest_raise_intr(uint64_t) { abort(); }
uint32_t fake_reference_imports() { return imports; }
uint32_t fake_reference_exports() { return exports; }

#ifndef OMIT_UIT_QUERY_CAPS
int32_t difftest_uit_query_caps(void *out, uint32_t bytes) {
  if (bytes != sizeof(DifftestUitCaps)) return DIFFTEST_UIT_E_ABI;
  DifftestUitCaps caps{DIFFTEST_UIT_VERSION, sizeof(DifftestUitCaps), DIFFTEST_UIT_FEATURES,
                      DIFFTEST_UIT_FEATURES, 64, 128, 1400, 32768, 2, 1, 64, 64, 112, 64};
  const char *fault = getenv("FAKE_UIT_BAD_CAP");
  if (getenv("FAKE_UIT_DISABLED")) caps.enabled_features = DIFFTEST_UIT_F_UART_TX;
  if (fault && !strcmp(fault, "query_rc")) return DIFFTEST_UIT_E_ABI;
#define CorruptCap(field) if (fault && !strcmp(fault, #field)) ++caps.field;
  CorruptCap(version)
  CorruptCap(bytes)
  CorruptCap(enabled_features)
  CorruptCap(supported_features)
  CorruptCap(xlen)
  CorruptCap(vlen)
  CorruptCap(legacy_regcpy_bytes)
  CorruptCap(legacy_csrcpy_bytes)
  CorruptCap(legacy_regcpy_arity)
  CorruptCap(max_harts)
  CorruptCap(exec_request_bytes)
  CorruptCap(event_request_bytes)
  CorruptCap(state_bytes)
  CorruptCap(exec_result_bytes)
#undef CorruptCap
  memcpy(out, &caps, sizeof(caps));
  return DIFFTEST_UIT_OK;
}
#endif

#ifndef OMIT_UIT_INIT
int32_t difftest_uit_init(const void *input, uint32_t bytes) {
  if (bytes != sizeof(DifftestUitInit)) return DIFFTEST_UIT_E_ABI;
  const auto &request = *static_cast<const DifftestUitInit *>(input);
  const uint32_t required = getenv("FAKE_UIT_DISABLED") ? DIFFTEST_UIT_F_UART_TX : DIFFTEST_UIT_FEATURES;
  if (request.version != DIFFTEST_UIT_VERSION || request.bytes != bytes || request.hart != 0 ||
      request.required_features != required || request.epoch != 7 || request.reserved != 0)
    return DIFFTEST_UIT_E_PAYLOAD;
  if (api_rc()) return api_rc();
  if (initialized || imports != 1) return DIFFTEST_UIT_E_STATE;
  initialized = true;
  return DIFFTEST_UIT_OK;
}
#endif

#ifndef OMIT_UIT_EXEC
int32_t difftest_uit_exec(const void *input, uint32_t bytes, void *output, uint32_t out_bytes) {
  if (bytes != sizeof(DifftestUitExecRequest) || out_bytes != sizeof(DifftestUitExecResult))
    return DIFFTEST_UIT_E_ABI;
  if (api_rc()) return api_rc();
  const auto &request = *static_cast<const DifftestUitExecRequest *>(input);
  if (!initialized || request.epoch != 7 || request.transaction_uid != 41 || request.sample_payload != 19)
    return DIFFTEST_UIT_E_PAYLOAD;
  DifftestUitExecResult result{};
  result.version = DIFFTEST_UIT_VERSION;
  result.bytes = out_bytes;
  result.epoch = request.epoch;
  result.transaction_uid = request.transaction_uid;
  result.control_seq = request.control_seq;
  result.sample_consumed = 1;
  memcpy(output, &result, sizeof(result));
  return DIFFTEST_UIT_OK;
}
#endif

#ifndef OMIT_UIT_RAISE_EVENT
int32_t difftest_uit_raise_event(const void *input, uint32_t bytes) {
  if (bytes != sizeof(DifftestUitHUEvent)) return DIFFTEST_UIT_E_ABI;
  if (api_rc()) return api_rc();
  const auto &event = *static_cast<const DifftestUitHUEvent *>(input);
  return initialized && event.epoch == 7 && event.event_uid == 42 && event.boundary_pc == 0x80000002
             ? DIFFTEST_UIT_OK : DIFFTEST_UIT_E_PAYLOAD;
}
#endif

#ifndef OMIT_UIT_GET_STATE
int32_t difftest_uit_get_state(void *out, uint32_t bytes) {
  if (bytes != sizeof(DifftestUitState)) return DIFFTEST_UIT_E_ABI;
  if (api_rc()) return api_rc();
  DifftestUitState state{};
  state.version = DIFFTEST_UIT_VERSION;
  state.bytes = bytes;
  state.epoch = 7;
  state.ustatus = 0x11;
  state.uie = 0x12;
  state.utvec = 0x13;
  state.uscratch = 0x14;
  state.uepc = 0x15;
  state.ucause = 0x16;
  state.utval = 0x17;
  state.pc = 0x80000002;
  state.in_handler = 1;
  memcpy(out, &state, sizeof(state));
  return DIFFTEST_UIT_OK;
}
#endif

#ifndef OMIT_UIT_READ_TX
int32_t difftest_uit_read_tx(void *out, uint32_t bytes) {
  if (bytes != sizeof(DifftestUitTx)) return DIFFTEST_UIT_E_ABI;
  if (api_rc()) return api_rc();
  DifftestUitTx tx{};
  tx.version = DIFFTEST_UIT_VERSION;
  tx.bytes = bytes;
  tx.epoch = 7;
  tx.tx_seq = 1;
  tx.address = DIFFTEST_UIT_UART_TX;
  tx.data = 'Z';
  tx.len = 1;
  memcpy(out, &tx, sizeof(tx));
  return DIFFTEST_UIT_OK;
}
#endif
}
