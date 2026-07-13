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

#ifndef __FDI_CSR_PROJECTION_H
#define __FDI_CSR_PROJECTION_H

#include "diffstate.h"
#include <cstddef>
#include <cstdint>

#ifdef CONFIG_DIFFTEST_FDICSRSTATE
namespace difftest {
namespace fdi {

constexpr size_t kCsrArraySize = 4096;
constexpr size_t kLibCfg = 0x880;
constexpr size_t kLibBoundBase = 0x890;
constexpr size_t kMainCallEntry = 0x8b0;
constexpr size_t kReturnPC = 0x8b1;
constexpr size_t kActiveZoneReturnPC = 0x8b2;
constexpr size_t kFReason = 0x8b3;
constexpr size_t kJumpBoundBase = 0x8c0;
constexpr size_t kJumpCfg = 0x8c8;
constexpr size_t kUMainBoundLo = 0x9e2;
constexpr size_t kUMainBoundHi = 0x9e3;
constexpr size_t kSMainCfg = 0xbc0;
constexpr size_t kSMainBoundLo = 0xbc2;
constexpr size_t kSMainBoundHi = 0xbc3;

constexpr uint64_t kSMainCfgMask = 0x3ff;
constexpr uint64_t kUMainCfgMask = 0x3e;
constexpr uint64_t kFReasonMask = 0x7;
constexpr size_t kLibBoundCount = 32;
constexpr size_t kJumpBoundCount = 8;

void from_csr_array(DifftestFDICSRState *fdi_csr, const uint64_t *csr_array);
void to_csr_array(uint64_t *csr_array, const DifftestFDICSRState &fdi_csr);

} // namespace fdi
} // namespace difftest
#endif // CONFIG_DIFFTEST_FDICSRSTATE

#endif // __FDI_CSR_PROJECTION_H
