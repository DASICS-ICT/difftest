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

#ifdef CONFIG_DIFFTEST_FDICSRSTATE
#include <cassert>
#include <cstdio>
#include <cstdlib>

namespace difftest {
namespace fdi {

void from_csr_array(DifftestFDICSRState *fdi_csr, const uint64_t *csr_array) {
  assert(fdi_csr != nullptr);
  assert(csr_array != nullptr);
  const uint64_t main_cfg = csr_array[kSMainCfg];

  fdi_csr->fdiSMainCfg = main_cfg & kSMainCfgMask;
  fdi_csr->fdiUMainCfg = main_cfg & kUMainCfgMask;
  fdi_csr->fdiSMainBoundLo = csr_array[kSMainBoundLo];
  fdi_csr->fdiSMainBoundHi = csr_array[kSMainBoundHi];
  fdi_csr->fdiUMainBoundLo = csr_array[kUMainBoundLo];
  fdi_csr->fdiUMainBoundHi = csr_array[kUMainBoundHi];
  fdi_csr->fdiLibCfg = csr_array[kLibCfg];
  for (size_t i = 0; i < kLibBoundCount; i++) {
    fdi_csr->fdiLibBound[i] = csr_array[kLibBoundBase + i];
  }
  fdi_csr->fdiMainCallEntry = csr_array[kMainCallEntry];
  fdi_csr->fdiReturnPC = csr_array[kReturnPC];
  fdi_csr->fdiActiveZoneReturnPC = csr_array[kActiveZoneReturnPC];
  fdi_csr->fdiFReason = csr_array[kFReason] & kFReasonMask;
  fdi_csr->fdiJumpCfg = csr_array[kJumpCfg];
  for (size_t i = 0; i < kJumpBoundCount; i++) {
    fdi_csr->fdiJumpBound[i] = csr_array[kJumpBoundBase + i];
  }
}

void to_csr_array(uint64_t *csr_array, const DifftestFDICSRState &fdi_csr) {
  assert(csr_array != nullptr);
  const uint64_t smain_cfg = fdi_csr.fdiSMainCfg & kSMainCfgMask;
  const uint64_t umain_cfg = fdi_csr.fdiUMainCfg & kUMainCfgMask;

  // SMainCfg and UMainCfg are masked views of the same architectural backing CSR.
  if ((smain_cfg & kUMainCfgMask) != umain_cfg) {
    std::fprintf(stderr, "Inconsistent FDI MainCfg views: SMainCfg=0x%016llx UMainCfg=0x%016llx\n",
                 static_cast<unsigned long long>(smain_cfg), static_cast<unsigned long long>(umain_cfg));
    std::fflush(stderr);
    std::abort();
  }
  const uint64_t main_cfg = (smain_cfg & ~kUMainCfgMask) | umain_cfg;

  csr_array[kSMainCfg] = (csr_array[kSMainCfg] & ~kSMainCfgMask) | main_cfg;
  csr_array[kSMainBoundLo] = fdi_csr.fdiSMainBoundLo;
  csr_array[kSMainBoundHi] = fdi_csr.fdiSMainBoundHi;
  csr_array[kUMainBoundLo] = fdi_csr.fdiUMainBoundLo;
  csr_array[kUMainBoundHi] = fdi_csr.fdiUMainBoundHi;
  csr_array[kLibCfg] = fdi_csr.fdiLibCfg;
  for (size_t i = 0; i < kLibBoundCount; i++) {
    csr_array[kLibBoundBase + i] = fdi_csr.fdiLibBound[i];
  }
  csr_array[kMainCallEntry] = fdi_csr.fdiMainCallEntry;
  csr_array[kReturnPC] = fdi_csr.fdiReturnPC;
  csr_array[kActiveZoneReturnPC] = fdi_csr.fdiActiveZoneReturnPC;
  csr_array[kFReason] = fdi_csr.fdiFReason & kFReasonMask;
  csr_array[kJumpCfg] = fdi_csr.fdiJumpCfg;
  for (size_t i = 0; i < kJumpBoundCount; i++) {
    csr_array[kJumpBoundBase + i] = fdi_csr.fdiJumpBound[i];
  }
}

} // namespace fdi
} // namespace difftest
#endif // CONFIG_DIFFTEST_FDICSRSTATE
