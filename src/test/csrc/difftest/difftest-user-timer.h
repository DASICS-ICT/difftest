#ifndef DIFFTEST_USER_TIMER_H
#define DIFFTEST_USER_TIMER_H

#include <stddef.h>
#include <stdint.h>

#define DIFFTEST_UIT_VERSION UINT32_C(0x00010000)
#define DIFFTEST_UIT_UART_TX UINT64_C(0x40600004)

enum {
  DIFFTEST_UIT_F_USER_CSR = 1u << 0,
  DIFFTEST_UIT_F_TIMER_SAMPLE = 1u << 1,
  DIFFTEST_UIT_F_PENDING_SAMPLE = 1u << 2,
  DIFFTEST_UIT_F_HU_EVENT = 1u << 3,
  DIFFTEST_UIT_F_URET = 1u << 4,
  DIFFTEST_UIT_F_UART_TX = 1u << 5,
  DIFFTEST_UIT_FEATURES = 0x3f
};

enum {
  DIFFTEST_UIT_OK = 0,
  DIFFTEST_UIT_EMPTY = 1,
  DIFFTEST_UIT_E_ABI = -1,
  DIFFTEST_UIT_E_FEATURE = -2,
  DIFFTEST_UIT_E_STATE = -3,
  DIFFTEST_UIT_E_EPOCH = -4,
  DIFFTEST_UIT_E_ORDER = -5,
  DIFFTEST_UIT_E_ID = -6,
  DIFFTEST_UIT_E_PC = -7,
  DIFFTEST_UIT_E_INSTRUCTION = -8,
  DIFFTEST_UIT_E_CSR = -9,
  DIFFTEST_UIT_E_SAMPLE_MISSING = -10,
  DIFFTEST_UIT_E_SAMPLE_UNEXPECTED = -11,
  DIFFTEST_UIT_E_SAMPLE_DUPLICATE = -12,
  DIFFTEST_UIT_E_PAYLOAD = -13,
  DIFFTEST_UIT_E_CONTEXT = -14,
  DIFFTEST_UIT_E_OVERFLOW = -15,
  DIFFTEST_UIT_E_UNSUPPORTED = -16,
  DIFFTEST_UIT_E_EXECUTION = -17
};

enum { DIFFTEST_UIT_CSR = 1, DIFFTEST_UIT_URET = 2 };
enum { DIFFTEST_UIT_NO_SAMPLE, DIFFTEST_UIT_TIMER_SAMPLE, DIFFTEST_UIT_PENDING_SAMPLE };
enum { DIFFTEST_UIT_HU_TIMER = 1 };
enum { DIFFTEST_UIT_RETIRED, DIFFTEST_UIT_ISA_EXCEPTION };

typedef struct {
  uint32_t version, bytes;
  uint64_t enabled_features, supported_features;
  uint32_t xlen, vlen, legacy_regcpy_bytes, legacy_csrcpy_bytes;
  uint32_t legacy_regcpy_arity, max_harts;
  uint32_t exec_request_bytes, event_request_bytes, state_bytes, exec_result_bytes;
} DifftestUitCaps;

/* Init is accepted once after difftest_init, before any reference execution.
 * No runtime API imports ordinary user CSR, PC, or register values. */
typedef struct {
  uint32_t version, bytes, hart, required_features;
  uint64_t epoch, reserved;
} DifftestUitInit;

/* The continuous control sequence covers user CSR instructions, URET and HU
 * events. Other instructions retain the ordinary reference execution path.
 * PC and instruction bits are validation metadata, never execution inputs. */
typedef struct {
  uint32_t version, bytes, hart, kind;
  uint64_t epoch, transaction_uid, control_seq, diagnostic_pc;
  uint32_t instruction;
  uint16_t csr;
  uint8_t funct3, sample_kind;
  uint64_t sample_payload;
} DifftestUitExecRequest;

/* A normal ISA exception is an execution outcome, not a protocol error.
 * csr_write_value describes an independently computed software write request;
 * it does not assert that a hardware timer was loaded or pending was cleared. */
typedef struct {
  uint32_t version, bytes, hart, reserved;
  uint64_t epoch, transaction_uid, control_seq;
  uint32_t outcome, exception_cause, sample_consumed, csr_write_valid;
  uint64_t csr_write_value;
} DifftestUitExecResult;

typedef struct {
  uint32_t version, bytes, hart, event_kind;
  uint64_t epoch, event_uid, control_seq;
  uint64_t boundary_pc, diagnostic_target, prior_instruction_count;
} DifftestUitHUEvent;

/* This is an output-only architectural snapshot. There is deliberately no
 * timer or pending field: a read sample is valid only for its instruction. */
typedef struct {
  uint32_t version, bytes, hart, flags;
  uint64_t epoch, last_control_seq;
  uint64_t ustatus, uie, utvec, uscratch, uepc, ucause, utval;
  uint64_t pc, mode;
  uint32_t v, in_handler;
} DifftestUitState;

typedef struct {
  uint32_t version, bytes, hart, reserved;
  uint64_t epoch, tx_seq, pc, address, data;
  uint32_t len, reserved2;
} DifftestUitTx;

#ifdef __cplusplus
#define UIT_STATIC_ASSERT static_assert
extern "C" {
#else
#define UIT_STATIC_ASSERT _Static_assert
#endif

UIT_STATIC_ASSERT(sizeof(DifftestUitCaps) == 64, "UIT caps layout");
UIT_STATIC_ASSERT(sizeof(DifftestUitInit) == 32, "UIT init layout");
UIT_STATIC_ASSERT(sizeof(DifftestUitExecRequest) == 64, "UIT request layout");
UIT_STATIC_ASSERT(sizeof(DifftestUitExecResult) == 64, "UIT result layout");
UIT_STATIC_ASSERT(sizeof(DifftestUitHUEvent) == 64, "UIT event layout");
UIT_STATIC_ASSERT(sizeof(DifftestUitState) == 112, "UIT state layout");
UIT_STATIC_ASSERT(sizeof(DifftestUitTx) == 64, "UIT TX layout");
UIT_STATIC_ASSERT(offsetof(DifftestUitCaps, enabled_features) == 8, "UIT caps offset");
UIT_STATIC_ASSERT(offsetof(DifftestUitExecRequest, epoch) == 16, "UIT request identity offset");
UIT_STATIC_ASSERT(offsetof(DifftestUitExecRequest, instruction) == 48, "UIT instruction offset");
UIT_STATIC_ASSERT(offsetof(DifftestUitExecRequest, sample_payload) == 56, "UIT sample offset");
UIT_STATIC_ASSERT(offsetof(DifftestUitExecResult, outcome) == 40, "UIT outcome offset");
UIT_STATIC_ASSERT(offsetof(DifftestUitHUEvent, boundary_pc) == 40, "UIT boundary offset");
UIT_STATIC_ASSERT(offsetof(DifftestUitState, ustatus) == 32, "UIT bank offset");
UIT_STATIC_ASSERT(offsetof(DifftestUitState, pc) == 88, "UIT PC offset");
UIT_STATIC_ASSERT(offsetof(DifftestUitState, in_handler) == 108, "UIT handler offset");
UIT_STATIC_ASSERT(offsetof(DifftestUitTx, data) == 48, "UIT TX data offset");

int32_t difftest_uit_query_caps(void *out, uint32_t out_bytes);
int32_t difftest_uit_init(const void *init, uint32_t init_bytes);
int32_t difftest_uit_exec(const void *request, uint32_t request_bytes,
                          void *result, uint32_t result_bytes);
int32_t difftest_uit_raise_event(const void *event, uint32_t event_bytes);
int32_t difftest_uit_get_state(void *out, uint32_t out_bytes);
int32_t difftest_uit_read_tx(void *out, uint32_t out_bytes);

#ifdef __cplusplus
}
#endif
#undef UIT_STATIC_ASSERT

#endif
