/***************************************************************************************
* Copyright (c) 2020-2023 Institute of Computing Technology, Chinese Academy of Sciences
* Copyright (c) 2020-2021 Peng Cheng Laboratory
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

#include "refproxy.h"
#include "dasics_development_audit.h"
#include <dlfcn.h>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <vector>

#if defined(CONFIG_DIFFTEST_USERTIMERACCESS) || defined(DASICS_DEVELOPMENT_AUDIT)
#include <link.h>
#include <sys/stat.h>
#include <type_traits>

#if !defined(CONFIG_DIFFTEST_ARCHFPREGSTATE) || !defined(CONFIG_DIFFTEST_HCSRSTATE) || \
    !defined(CONFIG_DIFFTEST_ARCHVECREGSTATE) || !defined(CONFIG_DIFFTEST_VECCSRSTATE) || \
    !defined(CONFIG_DIFFTEST_FPCSRSTATE) || !defined(CONFIG_DIFFTEST_TRIGGERCSRSTATE)
#error "UIT requires the complete RV64/VLEN128 legacy reference register layout"
#endif

// Marshal a fixed legacy buffer instead of relying on inherited class layout.
struct UitLegacyRegisters {
  DifftestArchIntRegState regs_int;
  DifftestArchFpRegState regs_fp;
  DifftestCSRState csr;
  uint64_t pc;
  DifftestHCSRState hcsr;
  DifftestArchVecRegState regs_vec;
  DifftestVecCSRState vcsr;
  DifftestFpCSRState fcsr;
  DifftestTriggerCSRState triggercsr;
};

static_assert(std::is_standard_layout<UitLegacyRegisters>::value, "UIT legacy standard layout");
static_assert(sizeof(UitLegacyRegisters) == 1400, "UIT legacy transfer size");
static_assert(offsetof(UitLegacyRegisters, regs_int) == 0, "UIT integer register offset");
static_assert(offsetof(UitLegacyRegisters, regs_fp) == 256, "UIT floating register offset");
static_assert(offsetof(UitLegacyRegisters, csr) == 512, "UIT CSR offset");
static_assert(offsetof(UitLegacyRegisters, pc) == 656, "UIT PC offset");
static_assert(offsetof(UitLegacyRegisters, hcsr) == 664, "UIT hypervisor CSR offset");
static_assert(offsetof(UitLegacyRegisters, regs_vec) == 800, "UIT vector register offset");
static_assert(offsetof(UitLegacyRegisters, vcsr) == 1312, "UIT vector CSR offset");
static_assert(offsetof(UitLegacyRegisters, fcsr) == 1368, "UIT floating CSR offset");
static_assert(offsetof(UitLegacyRegisters, triggercsr) == 1376, "UIT trigger CSR offset");
static_assert(DIFFTEST_VLEN == 128, "UIT requires VLEN128");

#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
static void uit_require_equal(const char *field, uint64_t actual, uint64_t expected) {
  if (actual != expected) {
    fprintf(stderr, "UIT ABI mismatch: %s actual=%" PRIu64 " expected=%" PRIu64 "\n", field, actual, expected);
    exit(EXIT_FAILURE);
  }
}
#endif

#endif

uint8_t *ref_golden_mem = NULL;
const char *difftest_ref_so = NULL;

#define check_and_assert(func)                             \
  do {                                                     \
    if (!func) {                                           \
      printf("Failed loading %s: %s\n", #func, dlerror()); \
      fflush(stdout);                                      \
      assert(func);                                        \
    }                                                      \
  } while (0);

#ifdef LINKED_REFPROXY_LIB
#define DeclExtRefFunc(dummy, ref_func, ret, ...) \
  extern "C" {                                    \
  extern RefFunc(ref_func, ret, __VA_ARGS__);     \
  }
REF_ALL(DeclExtRefFunc)

// Special notes on these weak symbols:
// For static libraries, the functions are linked at compile-time, as well as for the symbols.
// For dynamic libraries, despite being loaded at run-time, the symbols are looked up at compile-time.
// Be careful if you change the symbols in dynamic libraries after compiling and want to load it at run-time.
#define DeclWeakExtRefFunc(dummy, ref_func, ret, ...)               \
  extern "C" {                                                      \
  extern RefFunc(ref_func, ret __attribute__((weak)), __VA_ARGS__); \
  }
REF_OPTIONAL(DeclWeakExtRefFunc)
#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
// Give the linked symbol the same two-argument type as the negotiated ABI.
extern "C" void uit_linked_regcpy(void *, bool) asm("difftest_regcpy");
#endif
#endif

AbstractRefProxy::AbstractRefProxy(int coreid, size_t ram_size, const char *env, const char *file_path)
    : handler(load_handler(env, file_path)) {
#ifdef LINKED_REFPROXY_LIB
#define GetRefFunc(dummy, ref_func, ret, ...) ref_func
#else
#define GetRefFunc(dummy, ref_func, ret, ...) load_function<RefFunc((*), ret, __VA_ARGS__)>(#ref_func)
#endif
#define LoadRefFunc(this_func, ref_func, ret, ...)  this_func = GetRefFunc(, ref_func, ret, __VA_ARGS__);
#define CheckRefFunc(this_func, ref_func, ret, ...) check_and_assert(this_func);

  REF_ALL(LoadRefFunc)
  REF_ALL(CheckRefFunc)
  REF_OPTIONAL(LoadRefFunc)

#ifdef CONFIG_DIFFTEST_FDIOBSERVATION
#if defined(CONFIG_DIFFTEST_SQUASH) || defined(CONFIG_DIFFTEST_REPLAY) || defined(CONFIG_DIFFTEST_BATCH) || \
    defined(CONFIG_DIFFTEST_DELTA) || defined(ENABLE_RUNHEAD) || defined(BASIC_DIFFTEST_ONLY) || \
    defined(VM_SAVABLE) || defined(DEBUG_MODE_DIFF) || defined(CONFIG_NO_DIFFTEST)
  fprintf(stderr, "FDI requires a single-hart cold-start comparison without restore or execution compression\n");
  exit(EXIT_FAILURE);
#endif
  FdiReferenceApi fdi_api;
  fdi_api.query = GetRefFunc(, difftest_fdi_query_caps, int32_t, void *, uint32_t);
  fdi_api.capture = GetRefFunc(, difftest_fdi_capture_reset, int32_t, uint32_t, void *, uint32_t);
  fdi_api.initialize = GetRefFunc(, difftest_fdi_init, int32_t, const void *, uint32_t);
  fdi_api.state = GetRefFunc(, difftest_fdi_get_state, int32_t, uint32_t, void *, uint32_t);
  if (fdi.connect(fdi_api, coreid, NUM_CORES)) exit(EXIT_FAILURE);
#endif

#ifdef DASICS_DEVELOPMENT_AUDIT
  if (!DasicsDevelopment::state().enabled_diff || coreid != 0)
    DasicsDevelopment::fail("reference loaded outside single-hart difftest mode");
  development_ref_regcpy = load_function<decltype(development_ref_regcpy)>("difftest_regcpy");
  auto query = load_function<decltype(&difftest_uit_query_caps)>("difftest_uit_query_caps");
  if (!development_ref_regcpy || !query) DasicsDevelopment::fail("missing legacy reference capability API");
  DifftestUitCaps caps{};
  if (query(&caps, sizeof(caps)) != DIFFTEST_UIT_OK || caps.version != DIFFTEST_UIT_VERSION ||
      caps.bytes != sizeof(caps) || caps.enabled_features != 0 || caps.xlen != 64 || caps.vlen != 128 ||
      caps.legacy_regcpy_bytes != sizeof(UitLegacyRegisters) || caps.legacy_csrcpy_bytes != 32768 ||
      caps.legacy_regcpy_arity != 2 || caps.max_harts != 1 || caps.exec_request_bytes != 64 ||
      caps.event_request_bytes != 64 || caps.state_bytes != 112 || caps.exec_result_bytes != 64)
    DasicsDevelopment::fail("legacy reference capability or layout mismatch");
  struct link_map *loaded = nullptr;
  if (dlinfo(handler, RTLD_DI_LINKMAP, &loaded) || !loaded || !loaded->l_name)
    DasicsDevelopment::fail("cannot identify loaded reference");
  char *loaded_path = realpath(loaded->l_name, nullptr);
  struct stat loaded_stat{};
  if (!loaded_path || stat(loaded_path, &loaded_stat) || !S_ISREG(loaded_stat.st_mode))
    DasicsDevelopment::fail("loaded reference is not a regular file");
  auto verify_owner = [&](void *function) {
    Dl_info info{};
    struct stat symbol_stat{};
    if (!dladdr(function, &info) || !info.dli_fname || stat(info.dli_fname, &symbol_stat) ||
        symbol_stat.st_dev != loaded_stat.st_dev || symbol_stat.st_ino != loaded_stat.st_ino)
      DasicsDevelopment::fail("reference symbol belongs to another loaded object");
  };
#define VerifyDevelopmentOwner(this_func, dummy, ret, ...) verify_owner(reinterpret_cast<void *>(this_func));
  REF_ALL(VerifyDevelopmentOwner)
#undef VerifyDevelopmentOwner
  verify_owner(reinterpret_cast<void *>(query));
  FILE *audit = DasicsDevelopment::event("loaded");
  fputs(",\"path\":", audit);
  DasicsDevelopment::string(audit, loaded_path);
  fputs(",\"symbol_path\":", audit);
  DasicsDevelopment::string(audit, loaded_path);
  fprintf(audit, ",\"device\":%" PRIu64 ",\"inode\":%" PRIu64
          ",\"enabled_features\":%" PRIu64 ",\"supported_features\":%" PRIu64
          ",\"regcpy_bytes\":1400,\"csrcpy_bytes\":32768,\"regcpy_arity\":2,"
          "\"xlen\":64,\"vlen\":128,\"max_harts\":1,\"all_required_symbol_owners_verified\":true",
          static_cast<uint64_t>(loaded_stat.st_dev), static_cast<uint64_t>(loaded_stat.st_ino),
          caps.enabled_features, caps.supported_features);
  DasicsDevelopment::flush();
  free(loaded_path);
#endif

#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
#define LoadUitFunc(this_func, ref_func, ...)                                    \
  this_func = GetRefFunc(, ref_func, int32_t, __VA_ARGS__);                      \
  if (!this_func) {                                                             \
    fprintf(stderr, "UIT required reference symbol missing: %s\n", #ref_func); \
    exit(EXIT_FAILURE);                                                         \
  }
  LoadUitFunc(uit_query_caps, difftest_uit_query_caps, void *, uint32_t);
  LoadUitFunc(uit_initialize, difftest_uit_init, const void *, uint32_t);
  LoadUitFunc(uit_execute, difftest_uit_exec, const void *, uint32_t, void *, uint32_t);
  LoadUitFunc(uit_raise_event, difftest_uit_raise_event, const void *, uint32_t);
  LoadUitFunc(uit_get_state, difftest_uit_get_state, void *, uint32_t);
  LoadUitFunc(uit_read_tx, difftest_uit_read_tx, void *, uint32_t);
#undef LoadUitFunc

#ifdef LINKED_REFPROXY_LIB
  uit_ref_regcpy = uit_linked_regcpy;
#else
  uit_ref_regcpy = load_function<decltype(uit_ref_regcpy)>("difftest_regcpy");
#endif
  if (!uit_ref_regcpy) {
    fprintf(stderr, "UIT required reference symbol missing: difftest_regcpy\n");
    exit(EXIT_FAILURE);
  }
  const int32_t caps_rc = uit_query_caps(&uit_capabilities, sizeof(uit_capabilities));
  if (caps_rc != DIFFTEST_UIT_OK) {
    fprintf(stderr, "UIT capability query failed: rc=%" PRId32 "\n", caps_rc);
    exit(EXIT_FAILURE);
  }
  uit_require_equal("version", uit_capabilities.version, DIFFTEST_UIT_VERSION);
  uit_require_equal("caps bytes", uit_capabilities.bytes, sizeof(DifftestUitCaps));
  // The host matches this mode to the observed DUT feature before UIT init.
  if (uit_capabilities.enabled_features != DIFFTEST_UIT_F_UART_TX) {
    uit_require_equal("enabled features", uit_capabilities.enabled_features, DIFFTEST_UIT_FEATURES);
  }
  uit_require_equal("supported features", uit_capabilities.supported_features, DIFFTEST_UIT_FEATURES);
  uit_require_equal("XLEN", uit_capabilities.xlen, 64);
  uit_require_equal("VLEN", uit_capabilities.vlen, 128);
  uit_require_equal("legacy regcpy bytes", uit_capabilities.legacy_regcpy_bytes, sizeof(UitLegacyRegisters));
  uit_require_equal("legacy csrcpy bytes", uit_capabilities.legacy_csrcpy_bytes, 4096 * sizeof(uint64_t));
  uit_require_equal("legacy regcpy arity", uit_capabilities.legacy_regcpy_arity, 2);
  uit_require_equal("max harts", uit_capabilities.max_harts, 1);
  uit_require_equal("DUT harts", NUM_CORES, 1);
  uit_require_equal("hart ID", coreid, 0);
  uit_require_equal("exec request bytes", uit_capabilities.exec_request_bytes, sizeof(DifftestUitExecRequest));
  uit_require_equal("event request bytes", uit_capabilities.event_request_bytes, sizeof(DifftestUitHUEvent));
  uit_require_equal("state bytes", uit_capabilities.state_bytes, sizeof(DifftestUitState));
  uit_require_equal("exec result bytes", uit_capabilities.exec_result_bytes, sizeof(DifftestUitExecResult));
#endif

  if (NUM_CORES > 1) {
    check_and_assert(ref_set_mhartid);
    ref_set_mhartid(coreid);

    check_and_assert(ref_put_gmaddr);
    check_and_assert(ref_golden_mem);
    ref_put_gmaddr(ref_golden_mem);
  }

  // set ram_size before ref_init()
  if (ram_size > 0) {
    check_and_assert(ref_set_ramsize);
    ref_set_ramsize(ram_size);
  }

#ifdef ENABLE_STORE_LOG
  check_and_assert(ref_store_log_reset);
  check_and_assert(ref_store_log_restore);
#endif // ENABLE_STORE_LOG

  ref_init();
#ifdef CONFIG_DIFFTEST_FDIOBSERVATION
  if (fdi.capture_reset()) exit(EXIT_FAILURE);
#endif
}

AbstractRefProxy::~AbstractRefProxy() {
  if (handler) {
    dlclose(handler);
  }
};

void *AbstractRefProxy::load_handler(const char *env, const char *file_path) {
#ifdef LINKED_REFPROXY_LIB
  Info("The reference model (dynamically or statically linked at compile-time) is %s\n", LINKED_REFPROXY_LIB);
#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
  Dl_info linked_info{};
  if (!dladdr(reinterpret_cast<void *>(difftest_init), &linked_info) || !linked_info.dli_fname) {
    fprintf(stderr, "UIT could not identify the linked reference path\n");
    exit(EXIT_FAILURE);
  }
  char *resolved_linked_path = realpath(linked_info.dli_fname, nullptr);
  loaded_reference_path = resolved_linked_path ? resolved_linked_path : linked_info.dli_fname;
  free(resolved_linked_path);
#endif
  return nullptr;
#endif

#ifdef DASICS_DEVELOPMENT_AUDIT
  if (!difftest_ref_so) DasicsDevelopment::fail("explicit dynamic reference is required");
#endif

  bool use_given_diff = true;

  if (difftest_ref_so == NULL) {
    const char *ref_home = getenv(env);
    if (ref_home == NULL) {
#ifdef REF_HOME
      ref_home = REF_HOME;
#else
      printf("FATAL: $(%s) is not defined!\n", env);
      exit(1);
#endif // REF_HOME
    }
    char *buf = (char *)malloc(256);
    sprintf(buf, "%s/%s", ref_home, file_path);
    difftest_ref_so = buf;
    use_given_diff = false;
  }

  Info("The reference model is %s\n", difftest_ref_so);

  int mode = RTLD_LAZY | RTLD_DEEPBIND;
  void *so_handler = (NUM_CORES > 1) ? dlmopen(LM_ID_NEWLM, difftest_ref_so, mode) : dlopen(difftest_ref_so, mode);
  check_and_assert(so_handler);

#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
  struct link_map *loaded_map = nullptr;
  if (dlinfo(so_handler, RTLD_DI_LINKMAP, &loaded_map) != 0 || !loaded_map || !loaded_map->l_name) {
    fprintf(stderr, "UIT could not identify the loaded reference path\n");
    exit(EXIT_FAILURE);
  }
  char *resolved_path = realpath(loaded_map->l_name, nullptr);
  loaded_reference_path = resolved_path ? resolved_path : loaded_map->l_name;
  free(resolved_path);
#endif

  if (!use_given_diff) {
    free((void *)difftest_ref_so);
    difftest_ref_so = nullptr;
  }

  return so_handler;
}

template <typename T> T AbstractRefProxy::load_function(const char *func_name) {
  check_and_assert(handler);
  return reinterpret_cast<T>(dlsym(handler, func_name));
}

RefProxy::~RefProxy() {
  if (ref_close) {
    ref_close();
  }
}

#if defined(CONFIG_DIFFTEST_USERTIMERACCESS) || defined(DASICS_DEVELOPMENT_AUDIT)
#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
void RefProxy::uit_sync_regs(bool is_from_dut) {
#else
void RefProxy::development_sync_regs(bool is_from_dut) {
#endif
#ifdef CONFIG_DIFFTEST_FDIOBSERVATION
  if (is_from_dut && fdi.startup_import()) exit(EXIT_FAILURE);
#endif
#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
  if (is_from_dut && uit_initialized) {
    fprintf(stderr, "UIT runtime register import is forbidden\n");
    exit(EXIT_FAILURE);
  }
#endif
  UitLegacyRegisters legacy{};
  if (is_from_dut) {
    legacy = {regs_int, regs_fp, csr, pc, hcsr, regs_vec, vcsr, fcsr, triggercsr};
  }
#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
  uit_ref_regcpy(&legacy, is_from_dut);
#else
  if (is_from_dut) {
    if (development_imported) DasicsDevelopment::fail("runtime reference register import is forbidden");
    development_imported = true;
    fprintf(DasicsDevelopment::event("state_import"), ",\"pc\":\"0x%" PRIx64 "\"", pc);
    DasicsDevelopment::flush();
  }
  development_ref_regcpy(&legacy, is_from_dut);
#endif
  if (!is_from_dut) {
    regs_int = legacy.regs_int;
    regs_fp = legacy.regs_fp;
    csr = legacy.csr;
    pc = legacy.pc;
    hcsr = legacy.hcsr;
    regs_vec = legacy.regs_vec;
    vcsr = legacy.vcsr;
    fcsr = legacy.fcsr;
    triggercsr = legacy.triggercsr;
  }
}

#endif

#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
int32_t RefProxy::uit_init(uint64_t epoch, uint32_t required_features) {
  const DifftestUitInit init{DIFFTEST_UIT_VERSION, sizeof(DifftestUitInit), 0, required_features, epoch, 0};
  const int32_t rc = uit_initialize(&init, sizeof(init));
  if (rc == DIFFTEST_UIT_OK) {
    uit_initialized = true;
  }
  return rc;
}

int32_t RefProxy::uit_exec(const DifftestUitExecRequest &request, DifftestUitExecResult &result) {
  return uit_execute(&request, sizeof(request), &result, sizeof(result));
}

int32_t RefProxy::uit_event(const DifftestUitHUEvent &event) {
  return uit_raise_event(&event, sizeof(event));
}

int32_t RefProxy::uit_state(DifftestUitState &out) {
  return uit_get_state(&out, sizeof(out));
}

int32_t RefProxy::uit_tx(DifftestUitTx &out) {
  return uit_read_tx(&out, sizeof(out));
}
#endif

void RefProxy::regcpy(DiffTestState *dut) {
  memcpy(&regs_int, dut->regs_int.value, 32 * sizeof(uint64_t));
#ifdef CONFIG_DIFFTEST_ARCHFPREGSTATE
  memcpy(&regs_fp, dut->regs_fp.value, 32 * sizeof(uint64_t));
#endif // CONFIG_DIFFTEST_ARCHFPREGSTATE
  memcpy(&csr, &dut->csr, sizeof(csr));
  pc = dut->commit[0].pc;
#ifdef CONFIG_DIFFTEST_HCSRSTATE
  memcpy(&hcsr, &dut->hcsr, sizeof(hcsr));
#endif // CONFIG_DIFFTEST_HCSRSTATE
#ifdef CONFIG_DIFFTEST_ARCHVECREGSTATE
  memcpy(&regs_vec, &dut->regs_vec.value, sizeof(regs_vec));
#endif // CONFIG_DIFFTEST_ARCHVECREGSTATE
#ifdef CONFIG_DIFFTEST_VECCSRSTATE
  memcpy(&vcsr, &dut->vcsr, sizeof(vcsr));
#endif // CONFIG_DIFFTEST_VECCSRSTATE
#ifdef CONFIG_DIFFTEST_FPCSRSTATE
  memcpy(&fcsr, &dut->fcsr, sizeof(fcsr));
#endif // CONFIG_DIFFTEST_FPCSRSTATE
#ifdef CONFIG_DIFFTEST_TRIGGERCSRSTATE
  memcpy(&triggercsr, &dut->triggercsr, sizeof(triggercsr));
#endif //CONFIG_DIFFTEST_TRIGGERCSRSTATE
#ifdef CONFIG_DIFFTEST_USERTIMERACCESS
  uit_sync_regs(DUT_TO_REF);
#elif defined(DASICS_DEVELOPMENT_AUDIT)
  development_sync_regs(DUT_TO_REF);
#else
  ref_regcpy(&regs_int, DUT_TO_REF, false);
#endif
};

int RefProxy::compare(DiffTestState *dut) {
#define PROXY_COMPARE(field) memcmp(&(dut->field), &(field), sizeof(field))

  const int results[] = {PROXY_COMPARE(regs_int),
#ifdef CONFIG_DIFFTEST_ARCHFPREGSTATE
                         PROXY_COMPARE(regs_fp),
#endif // CONFIG_DIFFTEST_ARCHFPREGSTATE
#ifdef CONFIG_DIFFTEST_ARCHVECREGSTATE
                         PROXY_COMPARE(regs_vec),
#endif // CONFIG_DIFFTEST_ARCHVECREGSTATE
#ifdef CONFIG_DIFFTEST_VECCSRSTATE
                         PROXY_COMPARE(vcsr),
#endif // CONFIG_DIFFTEST_VECCSRSTATE
#ifdef CONFIG_DIFFTEST_FPCSRSTATE
                         PROXY_COMPARE(fcsr),
#endif // CONFIG_DIFFTEST_FPCSRSTATE
#ifdef CONFIG_DIFFTEST_HCSRSTATE
                         PROXY_COMPARE(hcsr),
#endif // CONFIG_DIFFTEST_HCSRSTATE
#ifdef CONFIG_DIFFTEST_TRIGGERCSRSTATE
                         PROXY_COMPARE(triggercsr),
#endif // CONFIG_DIFFTEST_TRIGGERCSRSTATE
                         PROXY_COMPARE(csr)

  };
  for (int i = 0; i < sizeof(results) / sizeof(int); i++) {
    if (results[i]) {
      // There may be some waive rules for CSRs
      if (i == sizeof(results) / sizeof(int) - 1) {
        // If mismatches are cleared, we sync the states back to REF.
        if (do_csr_waive(dut) && !PROXY_COMPARE(csr)) {
          sync(true);
          return 0;
        }
      }
      return 1;
    }
  }
  return 0;
};

void RefProxy::display(DiffTestState *dut) {
  if (dut) {
#define PROXY_COMPARE_AND_DISPLAY(field, field_names)                     \
  do {                                                                    \
    uint64_t *_ptr_dut = (uint64_t *)(&((dut)->field));                   \
    uint64_t *_ptr_ref = (uint64_t *)(&(field));                          \
    for (int i = 0; i < sizeof(field) / sizeof(uint64_t); i++) {          \
      if (_ptr_dut[i] != _ptr_ref[i]) {                                   \
        Info(                                                             \
            "%7s different at pc = 0x%010lx, right= 0x%016lx, "           \
            "wrong = 0x%016lx\n",                                         \
            field_names[i], dut->commit[0].pc, _ptr_ref[i], _ptr_dut[i]); \
      }                                                                   \
    }                                                                     \
  } while (0);

    PROXY_COMPARE_AND_DISPLAY(regs_int, regs_name_int)
#ifdef CONFIG_DIFFTEST_ARCHFPREGSTATE
    PROXY_COMPARE_AND_DISPLAY(regs_fp, regs_name_fp)
#endif // CONFIG_DIFFTEST_ARCHFPREGSTATE
    PROXY_COMPARE_AND_DISPLAY(csr, regs_name_csr)
#ifdef CONFIG_DIFFTEST_HCSRSTATE
    PROXY_COMPARE_AND_DISPLAY(hcsr, regs_name_hcsr)
#endif // CONFIG_DIFFTEST_HCSRSTATE
#ifdef CONFIG_DIFFTEST_ARCHVECREGSTATE
    PROXY_COMPARE_AND_DISPLAY(regs_vec, regs_name_vec)
#endif // CONFIG_DIFFTEST_ARCHVECREGSTATE
#ifdef CONFIG_DIFFTEST_VECCSRSTATE
    PROXY_COMPARE_AND_DISPLAY(vcsr, regs_name_vec_csr)
#endif // CONFIG_DIFFTEST_VECCSRSTATE
#ifdef CONFIG_DIFFTEST_FPCSRSTATE
    PROXY_COMPARE_AND_DISPLAY(fcsr, regs_name_fp_csr)
#endif // CONFIG_DIFFTEST_FPCSRSTATE
#ifdef CONFIG_DIFFTEST_TRIGGERCSRSTATE
    PROXY_COMPARE_AND_DISPLAY(triggercsr, regs_name_triggercsr)
#endif // CONFIG_DIFFTEST_TRIGGERCSRSTATE
  } else {
    ref_reg_display();
  }
};

void RefProxy::flash_init(const uint8_t *flash_base, size_t size, const char *flash_bin) {
  if (load_flash_bin_v2) {
    load_flash_bin_v2(flash_base, size);
  } else if (load_flash_bin) {
    // This API is deprecated because flash_bin may be an empty pointer
    load_flash_bin(flash_bin, size);
  } else {
    std::cout << "Require load_flash_bin or load_flash_bin_v2 to initialize the flash" << std::endl;
    assert(0);
  }
}

#ifdef CPU_ROCKET_CHIP
// similar function as encodeVirtualAddress@RocketCore.scala: 1151
static uint64_t encode_vaddr(uint64_t vaddr) {
  int64_t hi = (int64_t)vaddr >> 39;
  if (hi == 0 || hi == -1) {
    return vaddr;
  }
  hi = ((vaddr >> 38) & 0x1) ? 0 : -1;
  uint64_t mask = (1UL << 39) - 1;
  return (vaddr & mask) | (hi & (~mask));
}

static uint64_t sext_vaddr_40bit(uint64_t vaddr) {
  uint64_t hi = ((vaddr >> 39) & 0x1) ? -1UL : 0;
  uint64_t mask = (1UL << 40) - 1;
  return (vaddr & mask) | (hi & (~mask));
}

static uint64_t read_stvec(uint64_t vaddr) {
  vaddr = vaddr & ((1UL << 39) - 1);
  vaddr = vaddr & (~((vaddr & 0x1) ? 0xfeUL : 0x2UL));
  return ((int64_t)vaddr << 25) >> 25;
}

static uint64_t read_mtvec(uint64_t paddr) {
  paddr = paddr & ((1UL << 32) - 1);
  return paddr & (~((paddr & 0x1) ? 0xfeUL : 0x2UL));
}
#endif // CPU_ROCKET_CHIP

bool RefProxy::do_csr_waive(DiffTestState *dut) {
#define CSR_WAIVE(field, mapping)                             \
  do {                                                        \
    uint64_t v = mapping(csr.field);                          \
    if (csr.field != dut->csr.field && dut->csr.field == v) { \
      csr.field = v;                                          \
      has_waive = true;                                       \
    }                                                         \
  } while (0);

  bool has_waive = false;
#ifdef CPU_ROCKET_CHIP
  CSR_WAIVE(mtval, encode_vaddr);
  CSR_WAIVE(mtval, sext_vaddr_40bit);
  CSR_WAIVE(stval, encode_vaddr);
  CSR_WAIVE(stval, sext_vaddr_40bit);
  CSR_WAIVE(mtvec, read_mtvec);
  CSR_WAIVE(stvec, read_stvec);
#endif // CPU_ROCKET_CHIP
  return has_waive;
}

#define NEMU_ENV_VARIABLE "NEMU_HOME"
#define NEMU_SO_FILENAME  "build/riscv64-nemu-interpreter-so"
NemuProxy::NemuProxy(int coreid, size_t ram_size) : RefProxy(coreid, ram_size, NEMU_ENV_VARIABLE, NEMU_SO_FILENAME) {}

#define SPIKE_ENV_VARIABLE "SPIKE_HOME"
#define SPIKE_SO_FILENAME  "difftest/build/riscv64-spike-so"
SpikeProxy::SpikeProxy(int coreid, size_t ram_size)
    : RefProxy(coreid, ram_size, SPIKE_ENV_VARIABLE, SPIKE_SO_FILENAME) {}

LinkedProxy::LinkedProxy(int coreid, size_t ram_size) : RefProxy(coreid, ram_size) {
  if (NUM_CORES > 1) {
    printf("LinkedProxy does not support NUM_CORES(%d) > 1. Please use other REFs.\n", NUM_CORES);
    fflush(stdout);
    assert(0);
  }
}
