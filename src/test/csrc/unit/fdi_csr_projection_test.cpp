/***************************************************************************************
* Copyright (c) 2020-2024 Institute of Computing Technology, Chinese Academy of Sciences
*
* DiffTest is licensed under Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*          http://license.coscl.org.cn/MulanPSL2
*
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
* EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
* MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
*
* See the Mulan PSL v2 for more details.
***************************************************************************************/

#include "fdi_csr_projection.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fdi = difftest::fdi;

static_assert(sizeof(DifftestFDICSRState) == 52 * sizeof(uint64_t), "FDI CSR state must contain 52 64-bit words");

namespace {

int failures = 0;

void expect_equal(uint64_t actual, uint64_t expected, const char *label, size_t index = 0) {
  if (actual != expected) {
    std::fprintf(stderr, "FAIL: %s[%zu]: actual=0x%016lx expected=0x%016lx\n", label, index, actual, expected);
    failures++;
  }
}

void expect_true(bool condition, const char *label) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s\n", label);
    failures++;
  }
}

uint64_t csr_sentinel(size_t csr) {
  return UINT64_C(0x9100000000000000) | static_cast<uint64_t>(csr);
}

uint64_t field_sentinel(size_t field) {
  return UINT64_C(0xa200000000000000) | (static_cast<uint64_t>(field) << 16);
}

struct GuardedCSRArray {
  uint64_t lower_canary;
  std::array<uint64_t, fdi::kCsrArraySize> values;
  uint64_t upper_canary;
};

std::array<uint64_t, 52> flatten(const DifftestFDICSRState &state) {
  std::array<uint64_t, 52> words;
  size_t index = 0;
  words[index++] = state.fdiSMainCfg;
  words[index++] = state.fdiUMainCfg;
  words[index++] = state.fdiSMainBoundLo;
  words[index++] = state.fdiSMainBoundHi;
  words[index++] = state.fdiUMainBoundLo;
  words[index++] = state.fdiUMainBoundHi;
  words[index++] = state.fdiLibCfg;
  for (size_t i = 0; i < fdi::kLibBoundCount; i++) {
    words[index++] = state.fdiLibBound[i];
  }
  words[index++] = state.fdiMainCallEntry;
  words[index++] = state.fdiReturnPC;
  words[index++] = state.fdiActiveZoneReturnPC;
  words[index++] = state.fdiFReason;
  words[index++] = state.fdiJumpCfg;
  for (size_t i = 0; i < fdi::kJumpBoundCount; i++) {
    words[index++] = state.fdiJumpBound[i];
  }
  expect_equal(index, words.size(), "flattened field count");
  return words;
}

void expect_unique_fields(const DifftestFDICSRState &state) {
  const std::array<uint64_t, 52> words = flatten(state);
  for (size_t i = 0; i < words.size(); i++) {
    for (size_t j = i + 1; j < words.size(); j++) {
      if (words[i] == words[j]) {
        std::fprintf(stderr, "FAIL: fields %zu and %zu share sentinel 0x%016lx\n", i, j, words[i]);
        failures++;
      }
    }
  }
}

void initialize_csr_array(GuardedCSRArray *guarded) {
  guarded->lower_canary = UINT64_C(0x13579bdf2468ace0);
  guarded->upper_canary = UINT64_C(0xfedcba9876543210);
  for (size_t i = 0; i < guarded->values.size(); i++) {
    guarded->values[i] = csr_sentinel(i);
  }
  guarded->values[fdi::kSMainCfg] = UINT64_C(0xf1000000000002d5);
  guarded->values[fdi::kFReason] = UINT64_C(0xf200000000000005);
}

void check_canaries(const GuardedCSRArray &guarded) {
  expect_equal(guarded.lower_canary, UINT64_C(0x13579bdf2468ace0), "lower canary");
  expect_equal(guarded.upper_canary, UINT64_C(0xfedcba9876543210), "upper canary");
}

DifftestFDICSRState make_reverse_state() {
  DifftestFDICSRState state = {};
  size_t field = 0;
  state.fdiSMainCfg = field_sentinel(field++) | UINT64_C(0x2d5);
  state.fdiUMainCfg = field_sentinel(field++) | UINT64_C(0x14);
  state.fdiSMainBoundLo = field_sentinel(field++);
  state.fdiSMainBoundHi = field_sentinel(field++);
  state.fdiUMainBoundLo = field_sentinel(field++);
  state.fdiUMainBoundHi = field_sentinel(field++);
  state.fdiLibCfg = field_sentinel(field++);
  for (size_t i = 0; i < fdi::kLibBoundCount; i++) {
    state.fdiLibBound[i] = field_sentinel(field++);
  }
  state.fdiMainCallEntry = field_sentinel(field++);
  state.fdiReturnPC = field_sentinel(field++);
  state.fdiActiveZoneReturnPC = field_sentinel(field++);
  state.fdiFReason = field_sentinel(field++) | UINT64_C(0x5);
  state.fdiJumpCfg = field_sentinel(field++);
  for (size_t i = 0; i < fdi::kJumpBoundCount; i++) {
    state.fdiJumpBound[i] = field_sentinel(field++);
  }
  expect_equal(field, 52, "initialized field count");
  return state;
}

void test_from_csr_array() {
  GuardedCSRArray guarded;
  initialize_csr_array(&guarded);
  DifftestFDICSRState state;
  for (size_t i = 0; i < sizeof(state); i++) {
    reinterpret_cast<unsigned char *>(&state)[i] = 0xa5;
  }

  fdi::from_csr_array(&state, guarded.values.data());

  expect_equal(state.fdiSMainCfg, UINT64_C(0x2d5), "fdiSMainCfg");
  expect_equal(state.fdiUMainCfg, UINT64_C(0x14), "fdiUMainCfg");
  expect_equal(state.fdiSMainBoundLo, csr_sentinel(fdi::kSMainBoundLo), "fdiSMainBoundLo");
  expect_equal(state.fdiSMainBoundHi, csr_sentinel(fdi::kSMainBoundHi), "fdiSMainBoundHi");
  expect_equal(state.fdiUMainBoundLo, csr_sentinel(fdi::kUMainBoundLo), "fdiUMainBoundLo");
  expect_equal(state.fdiUMainBoundHi, csr_sentinel(fdi::kUMainBoundHi), "fdiUMainBoundHi");
  expect_equal(state.fdiLibCfg, csr_sentinel(fdi::kLibCfg), "fdiLibCfg");
  for (size_t i = 0; i < fdi::kLibBoundCount; i++) {
    expect_equal(state.fdiLibBound[i], csr_sentinel(fdi::kLibBoundBase + i), "fdiLibBound", i);
  }
  expect_equal(state.fdiMainCallEntry, csr_sentinel(fdi::kMainCallEntry), "fdiMainCallEntry");
  expect_equal(state.fdiReturnPC, csr_sentinel(fdi::kReturnPC), "fdiReturnPC");
  expect_equal(state.fdiActiveZoneReturnPC, csr_sentinel(fdi::kActiveZoneReturnPC), "fdiActiveZoneReturnPC");
  expect_equal(state.fdiFReason, UINT64_C(0x5), "fdiFReason");
  expect_equal(state.fdiJumpCfg, csr_sentinel(fdi::kJumpCfg), "fdiJumpCfg");
  for (size_t i = 0; i < fdi::kJumpBoundCount; i++) {
    expect_equal(state.fdiJumpBound[i], csr_sentinel(fdi::kJumpBoundBase + i), "fdiJumpBound", i);
  }
  expect_unique_fields(state);
  check_canaries(guarded);
}

void mark_projected_csrs(std::array<bool, fdi::kCsrArraySize> *projected) {
  (*projected)[fdi::kSMainCfg] = true;
  (*projected)[fdi::kSMainBoundLo] = true;
  (*projected)[fdi::kSMainBoundHi] = true;
  (*projected)[fdi::kUMainBoundLo] = true;
  (*projected)[fdi::kUMainBoundHi] = true;
  (*projected)[fdi::kLibCfg] = true;
  for (size_t i = 0; i < fdi::kLibBoundCount; i++) {
    (*projected)[fdi::kLibBoundBase + i] = true;
  }
  (*projected)[fdi::kMainCallEntry] = true;
  (*projected)[fdi::kReturnPC] = true;
  (*projected)[fdi::kActiveZoneReturnPC] = true;
  (*projected)[fdi::kFReason] = true;
  (*projected)[fdi::kJumpCfg] = true;
  for (size_t i = 0; i < fdi::kJumpBoundCount; i++) {
    (*projected)[fdi::kJumpBoundBase + i] = true;
  }
}

void test_to_csr_array() {
  GuardedCSRArray guarded;
  initialize_csr_array(&guarded);
  const std::array<uint64_t, fdi::kCsrArraySize> before = guarded.values;
  const DifftestFDICSRState state = make_reverse_state();
  expect_unique_fields(state);

  fdi::to_csr_array(guarded.values.data(), state);

  const uint64_t expected_main_cfg =
      (before[fdi::kSMainCfg] & ~fdi::kSMainCfgMask) | (state.fdiSMainCfg & fdi::kSMainCfgMask);
  expect_equal(guarded.values[fdi::kSMainCfg], expected_main_cfg, "SMainCfg backing CSR");
  expect_equal(guarded.values[fdi::kSMainBoundLo], state.fdiSMainBoundLo, "SMainBoundLo CSR");
  expect_equal(guarded.values[fdi::kSMainBoundHi], state.fdiSMainBoundHi, "SMainBoundHi CSR");
  expect_equal(guarded.values[fdi::kUMainBoundLo], state.fdiUMainBoundLo, "UMainBoundLo CSR");
  expect_equal(guarded.values[fdi::kUMainBoundHi], state.fdiUMainBoundHi, "UMainBoundHi CSR");
  expect_equal(guarded.values[fdi::kLibCfg], state.fdiLibCfg, "LibCfg CSR");
  for (size_t i = 0; i < fdi::kLibBoundCount; i++) {
    expect_equal(guarded.values[fdi::kLibBoundBase + i], state.fdiLibBound[i], "LibBound CSR", i);
  }
  expect_equal(guarded.values[fdi::kMainCallEntry], state.fdiMainCallEntry, "MainCallEntry CSR");
  expect_equal(guarded.values[fdi::kReturnPC], state.fdiReturnPC, "ReturnPC CSR");
  expect_equal(guarded.values[fdi::kActiveZoneReturnPC], state.fdiActiveZoneReturnPC, "ActiveZoneReturnPC CSR");
  expect_equal(guarded.values[fdi::kFReason], state.fdiFReason & fdi::kFReasonMask, "FReason CSR");
  expect_equal(guarded.values[fdi::kJumpCfg], state.fdiJumpCfg, "JumpCfg CSR");
  for (size_t i = 0; i < fdi::kJumpBoundCount; i++) {
    expect_equal(guarded.values[fdi::kJumpBoundBase + i], state.fdiJumpBound[i], "JumpBound CSR", i);
  }

  std::array<bool, fdi::kCsrArraySize> projected = {};
  mark_projected_csrs(&projected);
  size_t projected_count = 0;
  for (size_t i = 0; i < guarded.values.size(); i++) {
    if (projected[i]) {
      projected_count++;
    } else {
      expect_equal(guarded.values[i], before[i], "unrelated CSR", i);
    }
  }
  expect_equal(projected_count, 51, "canonical projected CSR count");
  check_canaries(guarded);

  DifftestFDICSRState round_trip = {};
  fdi::from_csr_array(&round_trip, guarded.values.data());
  DifftestFDICSRState expected = state;
  expected.fdiSMainCfg &= fdi::kSMainCfgMask;
  expected.fdiUMainCfg &= fdi::kUMainCfgMask;
  expected.fdiFReason &= fdi::kFReasonMask;
  const std::array<uint64_t, 52> actual_words = flatten(round_trip);
  const std::array<uint64_t, 52> expected_words = flatten(expected);
  for (size_t i = 0; i < actual_words.size(); i++) {
    expect_equal(actual_words[i], expected_words[i], "round-trip FDI field", i);
  }
}

void test_inconsistent_main_cfg_fails_fast() {
  GuardedCSRArray guarded;
  initialize_csr_array(&guarded);
  DifftestFDICSRState state = make_reverse_state();
  state.fdiUMainCfg ^= UINT64_C(0x2);

  std::fflush(NULL);
  const pid_t pid = fork();
  if (pid == -1) {
    std::perror("fork");
    failures++;
    return;
  }
  if (pid == 0) {
    (void)close(STDERR_FILENO);
    fdi::to_csr_array(guarded.values.data(), state);
    _exit(0);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) != pid) {
    std::perror("waitpid");
    failures++;
    return;
  }
  expect_true(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT, "inconsistent S/U MainCfg views must abort");
  check_canaries(guarded);
}

} // namespace

int main() {
  test_from_csr_array();
  test_to_csr_array();
  test_inconsistent_main_cfg_fails_fast();

  if (failures != 0) {
    std::fprintf(stderr, "FDI CSR projection test failed: %d checks\n", failures);
    return EXIT_FAILURE;
  }
  std::printf("FDI CSR projection test passed\n");
  return EXIT_SUCCESS;
}
