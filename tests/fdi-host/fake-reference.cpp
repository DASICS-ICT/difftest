// Reuse the unchanged legacy/UIT fake ABI so this fixture checks both protocol
// lifecycles against the production RefProxy without executing a model.
#define difftest_init legacy_fake_init
#define difftest_regcpy legacy_fake_regcpy
#include "../user-timer-proxy/fake-reference.cpp"
#undef difftest_init
#undef difftest_regcpy
#include "difftest-fdi.h"

static bool fdi_reset_seen, fdi_initialized;
static DifftestFdiState fdi_state{DIFFTEST_FDI_VERSION, sizeof(DifftestFdiState), 0, DIFFTEST_FDI_PHASE_RESET,
                                 0, UINT64_C(0x10000000), {}};

extern "C" {
void difftest_init() { legacy_fake_init(); puts("FDI_FAKE_NATURAL_RESET"); }
void difftest_regcpy(void *buffer, bool to_reference) {
  if (to_reference && (!fdi_reset_seen || fdi_initialized)) {
    fputs("FDI_FAKE_FORBIDDEN_IMPORT_REACHED\n", stderr); exit(94);
  }
  legacy_fake_regcpy(buffer, to_reference);
}
#ifndef OMIT_FDI_QUERY
int32_t difftest_fdi_query_caps(void *out, uint32_t bytes) {
  if (bytes != sizeof(DifftestFdiCaps)) return DIFFTEST_FDI_E_ABI;
  DifftestFdiCaps value{DIFFTEST_FDI_VERSION, sizeof(DifftestFdiCaps), sizeof(DifftestFdiState), 52,
    DIFFTEST_FDI_FEATURES, DIFFTEST_FDI_FEATURES, 64, 1, sizeof(DifftestFdiInit), 1, 2, 0, 0};
  if (getenv("FAKE_FDI_DISABLED")) value.enabled_features = 0;
  memcpy(out, &value, bytes);
  return DIFFTEST_FDI_OK;
}
#endif
#ifndef OMIT_FDI_CAPTURE
int32_t difftest_fdi_capture_reset(uint32_t hart, void *out, uint32_t bytes) {
  if (hart || bytes != sizeof(fdi_state)) return DIFFTEST_FDI_E_ABI;
  if (fdi_reset_seen || imports || fdi_initialized) return DIFFTEST_FDI_E_STATE;
  if (getenv("FAKE_FDI_DIRTY_RESET")) fdi_state.words[39] = 1;
  memcpy(out, &fdi_state, bytes); fdi_reset_seen = true;
  puts("FDI_FAKE_CAPTURED_BEFORE_IMPORT");
  return DIFFTEST_FDI_OK;
}
#endif
#ifndef OMIT_FDI_INITIALIZE
int32_t difftest_fdi_init(const void *input, uint32_t bytes) {
  const auto &request = *static_cast<const DifftestFdiInit *>(input);
  if (bytes != sizeof(request) || request.version != DIFFTEST_FDI_VERSION || request.hart ||
      request.reserved || request.epoch != 7 || request.required_features != DIFFTEST_FDI_FEATURES)
    return DIFFTEST_FDI_E_ABI;
  if (!fdi_reset_seen || fdi_initialized || imports != 1) return DIFFTEST_FDI_E_STATE;
  fdi_state.phase = DIFFTEST_FDI_PHASE_CURRENT; fdi_state.epoch = request.epoch;
  fdi_initialized = true;
  puts("FDI_FAKE_INITIALIZED_AFTER_SINGLE_IMPORT");
  return DIFFTEST_FDI_OK;
}
#endif
#ifndef OMIT_FDI_STATE
int32_t difftest_fdi_get_state(uint32_t hart, void *out, uint32_t bytes) {
  if (hart || bytes != sizeof(fdi_state)) return DIFFTEST_FDI_E_ABI;
  if (!fdi_initialized) return DIFFTEST_FDI_E_STATE;
  memcpy(out, &fdi_state, bytes);
  return DIFFTEST_FDI_OK;
}
#endif
}
