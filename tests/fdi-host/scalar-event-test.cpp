#include "dasics_scalar_event.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

struct Event {
  uint64_t csrState_privilegeMode = 1, hcsrState_virtMode = 0;
  uint64_t csrState_mcause = 7, csrState_mepc = 0x81000100, csrState_mtval = 0x88000000;
  uint64_t csrState_scause = 25, csrState_sepc = 0x82000100, csrState_stval = 0x89000000;
  uint64_t target = 0x80000100;
};
struct Csr {
  uint64_t privilegeMode = 1;
  uint64_t mcause = 7, mepc = 0x81000100, mtval = 0x88000000;
  uint64_t scause = 25, sepc = 0x82000100, stval = 0x89000000;
};
struct Hcsr { uint64_t virtMode = 0; };

static void require(bool condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "SCALAR_EVENT_UNIT_FAILURE: %s\n", message);
    exit(91);
  }
}

int main() {
  const Event event;
  const Csr csr;
  const Hcsr hcsr;
  require(!dasics_scalar_event_mismatch(event, csr, hcsr, event.target), "matching snapshot");
#define CHECK_CSR(field) do { \
    auto wrong = csr; \
    wrong.field ^= 1; \
    const auto mismatch = dasics_scalar_event_mismatch(event, wrong, hcsr, event.target); \
    require(mismatch && !strcmp(mismatch, "csrState_" #field), #field); \
  } while (0)
  CHECK_CSR(privilegeMode);
  CHECK_CSR(mcause); CHECK_CSR(mepc); CHECK_CSR(mtval);
  CHECK_CSR(scause); CHECK_CSR(sepc); CHECK_CSR(stval);
#undef CHECK_CSR
  auto wrong_hcsr = hcsr;
  wrong_hcsr.virtMode = 1;
  require(!strcmp(dasics_scalar_event_mismatch(event, csr, wrong_hcsr, event.target),
                  "hcsrState_virtMode"), "virtual target mismatch");
  require(!strcmp(dasics_scalar_event_mismatch(event, csr, hcsr, event.target ^ 2),
                  "target"), "target PC mismatch");
  // The source is the saved event even when a younger retirement has changed
  // the live frame to values matching the reference.
  auto saved = event;
  saved.csrState_stval ^= 8;
  require(!strcmp(dasics_scalar_event_mismatch(saved, csr, hcsr, event.target),
                  "csrState_stval"), "event mismatch cannot be hidden by a later frame");
  require(!dasics_scalar_event_mismatch(event, csr, hcsr, event.target), "inputs remain unchanged");
  puts("SCALAR_EVENT_UNIT_PASS: 12 checks");
}
