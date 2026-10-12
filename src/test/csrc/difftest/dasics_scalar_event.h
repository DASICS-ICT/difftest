#ifndef DASICS_SCALAR_EVENT_H
#define DASICS_SCALAR_EVENT_H

#include <cstdint>

// Use the saved trap snapshot at its execution boundary. A later retirement
// may replace the frame CSR values before the ordinary register comparison.
template <typename Event, typename Csr, typename Hcsr>
const char *dasics_scalar_event_mismatch(const Event &event, const Csr &csr,
                                        const Hcsr &hcsr, uint64_t pc) {
#define SCALAR_EVENT_FIELD(saved, actual) if (event.saved != (actual)) return #saved
  SCALAR_EVENT_FIELD(csrState_privilegeMode, csr.privilegeMode);
  SCALAR_EVENT_FIELD(hcsrState_virtMode, hcsr.virtMode);
  SCALAR_EVENT_FIELD(csrState_mcause, csr.mcause);
  SCALAR_EVENT_FIELD(csrState_mepc, csr.mepc);
  SCALAR_EVENT_FIELD(csrState_mtval, csr.mtval);
  SCALAR_EVENT_FIELD(csrState_scause, csr.scause);
  SCALAR_EVENT_FIELD(csrState_sepc, csr.sepc);
  SCALAR_EVENT_FIELD(csrState_stval, csr.stval);
  SCALAR_EVENT_FIELD(target, pc);
#undef SCALAR_EVENT_FIELD
  return nullptr;
}

#endif
