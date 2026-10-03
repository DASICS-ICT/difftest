#ifndef DIFFTEST_FDI_H
#define DIFFTEST_FDI_H

#include <stddef.h>
#include <stdint.h>

#define DIFFTEST_FDI_VERSION UINT32_C(0x00010000)
#define DIFFTEST_FDI_PROJECTION_VERSION UINT32_C(1)
#define DIFFTEST_FDI_MACHINE_ABI_MAJOR UINT32_C(2)
#define DIFFTEST_FDI_PROJECTION_WORDS UINT32_C(52)
#define DIFFTEST_FDI_XLEN UINT32_C(64)
#define DIFFTEST_FDI_MAX_HARTS UINT32_C(1)

#define DIFFTEST_FDI_F_CSR_STATE_EXPORT (UINT64_C(1) << 0)
#define DIFFTEST_FDI_F_RESET_BEFORE_IMPORT (UINT64_C(1) << 1)
#define DIFFTEST_FDI_FEATURES UINT64_C(0x3)

enum {
  DIFFTEST_FDI_OK = 0,
  DIFFTEST_FDI_E_ABI = -1,
  DIFFTEST_FDI_E_FEATURE = -2,
  DIFFTEST_FDI_E_HART = -3,
  DIFFTEST_FDI_E_STATE = -4,
  DIFFTEST_FDI_E_INVARIANT = -5
};

enum {
  DIFFTEST_FDI_PHASE_RESET = 0,
  DIFFTEST_FDI_PHASE_CURRENT = 1
};

typedef struct {
  uint32_t version, bytes, state_bytes, projection_words;
  uint64_t supported_features, enabled_features;
  uint32_t xlen, max_harts, init_bytes, projection_version;
  uint32_t machine_abi_major, reserved32;
  uint64_t reserved64;
} DifftestFdiCaps;

/* Binding a comparison session never resets or imports architectural state.
 * Reset capture must precede imports; initialization must precede execution. */
typedef struct {
  uint32_t version, bytes, hart, reserved;
  uint64_t epoch, required_features;
} DifftestFdiInit;

/* Output only. The words follow the fixed machine ABI projection. model_pc is
 * the reference's own PC, not a DUT input or a replacement for frame identity.
 * RESET uses epoch zero; CURRENT uses the initialized session epoch. */
typedef struct {
  uint32_t version, bytes, hart, phase;
  uint64_t epoch, model_pc;
  uint64_t words[DIFFTEST_FDI_PROJECTION_WORDS];
} DifftestFdiState;

#ifdef __cplusplus
#define FDI_STATIC_ASSERT static_assert
extern "C" {
#else
#define FDI_STATIC_ASSERT _Static_assert
#endif

FDI_STATIC_ASSERT(sizeof(DifftestFdiCaps) == 64, "FDI capabilities size");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, version) == 0, "FDI capabilities version offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, bytes) == 4, "FDI capabilities bytes offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, state_bytes) == 8, "FDI capabilities state size offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, projection_words) == 12, "FDI capabilities projection offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, supported_features) == 16, "FDI supported features offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, enabled_features) == 24, "FDI enabled features offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, xlen) == 32, "FDI capabilities XLEN offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, max_harts) == 36, "FDI capabilities hart count offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, init_bytes) == 40, "FDI capabilities init size offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, projection_version) == 44, "FDI projection version offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, machine_abi_major) == 48, "FDI machine ABI offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, reserved32) == 52, "FDI capabilities reserved32 offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiCaps, reserved64) == 56, "FDI capabilities reserved64 offset");
FDI_STATIC_ASSERT(sizeof(DifftestFdiInit) == 32, "FDI initialization size");
FDI_STATIC_ASSERT(offsetof(DifftestFdiInit, version) == 0, "FDI initialization version offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiInit, bytes) == 4, "FDI initialization bytes offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiInit, hart) == 8, "FDI initialization hart offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiInit, reserved) == 12, "FDI initialization reserved offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiInit, epoch) == 16, "FDI initialization epoch offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiInit, required_features) == 24, "FDI required features offset");
FDI_STATIC_ASSERT(sizeof(DifftestFdiState) == 448, "FDI state size");
FDI_STATIC_ASSERT(offsetof(DifftestFdiState, version) == 0, "FDI state version offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiState, bytes) == 4, "FDI state bytes offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiState, hart) == 8, "FDI state hart offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiState, phase) == 12, "FDI state phase offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiState, epoch) == 16, "FDI state epoch offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiState, model_pc) == 24, "FDI state PC offset");
FDI_STATIC_ASSERT(offsetof(DifftestFdiState, words) == 32, "FDI state projection offset");

/* Query is available with the feature disabled. Other operations return
 * E_FEATURE then. All failures preserve the caller's output buffer. */
int32_t difftest_fdi_query_caps(void *out, uint32_t out_bytes);
int32_t difftest_fdi_capture_reset(uint32_t hart, void *out, uint32_t out_bytes);
int32_t difftest_fdi_init(const void *input, uint32_t input_bytes);
int32_t difftest_fdi_get_state(uint32_t hart, void *out, uint32_t out_bytes);

#ifdef __cplusplus
}
#endif
#undef FDI_STATIC_ASSERT

#endif
