#ifdef CONFIG_DIFFTEST_USERTIMERACCESS

#define UIT_BANK(x, p) std::array<uint64_t, 8>{x.p##ustatus, x.p##uie, x.p##utvec, x.p##uscratch, x.p##uepc, x.p##ucause, x.p##utval, x.p##inHandler}
static const char *uit_bank_names[] = {"ustatus", "uie", "utvec", "uscratch", "uepc", "ucause", "utval", "in_handler"};
static void uit_log_bank(FILE *file, const std::array<uint64_t, 8> &bank) {
  fprintf(file, "{");
  for (size_t i = 0; i < bank.size(); i++) fprintf(file, "%s\"%s\":\"0x%016lx\"", i ? "," : "", uit_bank_names[i], bank[i]);
  fprintf(file, "}");
}

// DPI callbacks set valid only when publishing a packet. The live buffer is
// reused, so ownership transfer to a frame must acknowledge just its events.
// Architectural registers and sparse physical writeback data remain resident.
static void uit_clear_captured_valid(DiffTestState &state) {
#define UIT_CLEAR_ONE(name) state.name.valid = false
#define UIT_CLEAR_ARRAY(name) for (auto &entry : state.name) entry.valid = false
  UIT_CLEAR_ONE(uit_access); UIT_CLEAR_ONE(uit_response); UIT_CLEAR_ONE(uit_snapshot);
  UIT_CLEAR_ARRAY(uit_cancel); UIT_CLEAR_ONE(uit_uart); UIT_CLEAR_ONE(uit_terminal);
  UIT_CLEAR_ARRAY(uit_retire);
#ifdef CONFIG_DIFFTEST_FDIOBSERVATION
  UIT_CLEAR_ARRAY(fdi_observation);
#endif
  UIT_CLEAR_ONE(event); UIT_CLEAR_ARRAY(commit);
  state.trap.hasTrap = false;
#ifdef CONFIG_DIFFTEST_ATOMICEVENT
  UIT_CLEAR_ONE(atomic);
#endif
#ifdef CONFIG_DIFFTEST_CMOINVALEVENT
  UIT_CLEAR_ONE(cmo_inval);
#endif
#ifdef CONFIG_DIFFTEST_CRITICALERROREVENT
  UIT_CLEAR_ONE(critical_error);
#endif
#ifdef CONFIG_DIFFTEST_L1TLBEVENT
  UIT_CLEAR_ARRAY(l1tlb);
#endif
#ifdef CONFIG_DIFFTEST_L2TLBEVENT
  UIT_CLEAR_ARRAY(l2tlb);
#endif
#ifdef CONFIG_DIFFTEST_LOADEVENT
  UIT_CLEAR_ARRAY(load);
#endif
#ifdef CONFIG_DIFFTEST_LRSCEVENT
  UIT_CLEAR_ONE(lrsc);
#endif
#ifdef CONFIG_DIFFTEST_MHPMEVENTOVERFLOWEVENT
  UIT_CLEAR_ONE(mhpmevent_overflow);
#endif
#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
  UIT_CLEAR_ONE(non_reg_interrupt_pending);
#endif
#ifdef CONFIG_DIFFTEST_REFILLEVENT
  UIT_CLEAR_ARRAY(refill);
#endif
#ifdef CONFIG_DIFFTEST_SBUFFEREVENT
  UIT_CLEAR_ARRAY(sbuffer);
#endif
#ifdef CONFIG_DIFFTEST_STOREEVENT
  UIT_CLEAR_ARRAY(store);
#endif
#ifdef CONFIG_DIFFTEST_SYNCAIAEVENT
  UIT_CLEAR_ONE(sync_aia);
#endif
#ifdef CONFIG_DIFFTEST_SYNCCUSTOMMFLUSHPWREVENT
  UIT_CLEAR_ONE(sync_custom_mflushpwr);
#endif
#ifdef CONFIG_DIFFTEST_UNCACHEMMSTOREEVENT
  UIT_CLEAR_ARRAY(uncache_mm_store);
#endif
#ifdef CONFIG_DIFFTEST_COMMITDATA
  UIT_CLEAR_ARRAY(commit_data);
#endif
#ifdef CONFIG_DIFFTEST_ARCHINTDELAYEDUPDATE
  UIT_CLEAR_ARRAY(regs_int_delayed);
#endif
#ifdef CONFIG_DIFFTEST_ARCHFPDELAYEDUPDATE
  UIT_CLEAR_ARRAY(regs_fp_delayed);
#endif
#undef UIT_CLEAR_ONE
#undef UIT_CLEAR_ARRAY
}

int Difftest::uit_ingest() {
  const auto &clock = dut->uit_clock;
  if (clock.coreReset) {
    if (uit.released) return uit.error("warm reset is unsupported");
    return 0;
  }
  uit.released = true;
#ifdef CONFIG_DIFFTEST_FDIOBSERVATION
  if (fdi_ingest()) return 1;
#endif
  if (proxy->uit_caps().enabled_features != (clock.enabled ? DIFFTEST_UIT_FEATURES : DIFFTEST_UIT_F_UART_TX)) return uit.error("DUT and reference feature configuration mismatch");
  if (clock.epoch != uit.epoch) return uit.error("observation epoch mismatch");
  if (dut->trap.hasTrap && !uit.raw_terminal_seen) {
    uit.terminal_trap = dut->trap;
    uit.raw_terminal_seen = true;
    uit.prefix("raw_terminal");
    fprintf(uit.trace, ",\"cycle\":%lu,\"pc\":\"0x%lx\",\"code\":%lu,\"instruction_count\":%lu}\n", dut->trap.cycleCnt, dut->trap.pc, dut->trap.code, dut->trap.instrCnt);
  }
  const auto &terminal = dut->uit_terminal;
  if (terminal.valid) {
    if (uit.terminal_seen || terminal.epoch != uit.epoch || !terminal.uid ||
        (uit.initialized && terminal.afterCount <= uit.retired)) return uit.error("invalid or duplicate terminal identity", terminal.uid);
    uit.terminal = terminal;
    uit.terminal_seen = true;
    uit.prefix("terminal");
    fprintf(uit.trace, ",\"uid\":%lu,\"cycle\":%lu,\"after_count\":%lu,\"pc\":\"0x%lx\",\"raw_trap_seen\":%s}\n", terminal.uid, terminal.cycle, terminal.afterCount, terminal.pc, uit.raw_terminal_seen ? "true" : "false");
  }
  if (uit.terminal_seen && uit.raw_terminal_seen && uit.terminal.pc != uit.terminal_trap.pc) return uit.error("raw trap and terminal identity disagree", uit.terminal.uid);
  const auto &a = dut->uit_access;
  if (a.valid) {
    // UIDs follow ROB allocation, while zero-source CSR reads may execute out of order.
    // Keep each sample by identity; retirement selects the reference execution order.
    if (a.epoch != uit.epoch || !a.uid || uit.accepted.count(a.uid) || uit.closed.count(a.uid)) return uit.error("duplicate or invalid access identity", a.uid);
    if (uit.accesses.size() >= UitBridge::capacity) return uit.error("access queue overflow", a.uid);
    if (!UitBridge::controlled(a.instr) || a.isUret != (a.instr == 0x00200073)) return uit.error("access instruction metadata mismatch", a.uid);
    if (!a.isUret && (a.csr != (a.instr >> 20) || a.funct3 != ((a.instr >> 12) & 7))) return uit.error("access CSR metadata mismatch", a.uid);
    if (a.sampleKind > 2 || (a.sampleKind == 2 && a.sampleValue > 1)) return uit.error("invalid sample payload", a.uid);
    if ((!a.legal || !a.needRead || a.isUret) && a.sampleKind) return uit.error("unexpected sample", a.uid);
    const auto expected_kind = a.legal && a.needRead && !a.isUret ? (a.csr == 0x800 ? 1 : a.csr == 0x44 ? 2 : 0) : 0;
    if (a.sampleKind != expected_kind) return uit.error("missing or wrong-address sample", a.uid);
    UitBridge::Access record{};
    record.request = a;
    uit.accesses.emplace(a.uid, record);
    uit.accepted.insert(a.uid);
    uit.prefix("access");
    fprintf(uit.trace, ",\"rob\":%u,\"robflag\":%u", a.robIdx, a.robFlag);
    fprintf(uit.trace, ",\"uid\":%lu,\"cycle\":%lu,\"pc\":\"0x%lx\",\"instruction\":\"0x%08x\",\"csr\":%u,\"funct3\":%u,\"sample_kind\":%u,\"sample_payload\":\"0x%lx\",\"legal\":%u,\"need_read\":%u,\"pre\":", a.uid, a.cycle, a.pc, a.instr, a.isUret ? 65535 : a.csr, a.funct3, a.sampleKind, a.sampleValue, a.legal, a.needRead);
    uit_log_bank(uit.trace, UIT_BANK(a, pre_));
    fprintf(uit.trace, ",\"mstateen0\":\"0x%lx\",\"sstateen0\":\"0x%lx\",\"mode\":%lu,\"v\":%lu,\"debug\":%lu}\n", a.pre_mstateen0, a.pre_sstateen0, a.pre_privilegeMode, a.pre_virtMode, a.pre_debugMode);
  }
  const auto &r = dut->uit_response;
  if (r.valid) {
    auto found = uit.accesses.find(r.uid);
    if (r.epoch != uit.epoch || found == uit.accesses.end() || found->second.responded || r.cycle < found->second.request.cycle) return uit.error("missing access or duplicate response", r.uid);
    found->second.response = r; found->second.responded = true;
    uit.prefix("response");
    fprintf(uit.trace, ",\"uid\":%lu,\"cycle\":%lu,\"rdata\":\"0x%lx\",\"illegal\":%u,\"virtual_fault\":%u}\n", r.uid, r.cycle, r.rdata, r.illegal, r.virtualFault);
  }
  const auto &s = dut->uit_snapshot;
  if (s.valid) {
    if (s.epoch != uit.epoch || !s.uid) return uit.error("snapshot identity mismatch", s.uid);
    if (s.kind == 3) {
      if (!s.eventSeq || uit.seen_events.count(s.eventSeq) || uit.events.size() >= UitBridge::capacity) return uit.error("duplicate event snapshot or overflow", s.uid);
      uit.events.emplace(s.eventSeq, s); uit.seen_events.insert(s.eventSeq);
    } else {
      auto found = uit.accesses.find(s.uid);
      if (found == uit.accesses.end() || found->second.captured || (s.kind != 1 && s.kind != 2) || s.cycle < found->second.request.cycle || (s.kind == 2) != bool(found->second.request.isUret) || s.robIdx != found->second.request.robIdx || s.robFlag != found->second.request.robFlag) return uit.error("unmatched or duplicate access snapshot", s.uid);
      found->second.snapshot = s; found->second.captured = true;
    }
    uit.prefix("snapshot");
    fprintf(uit.trace, ",\"rob\":%u,\"robflag\":%u", s.robIdx, s.robFlag);
    fprintf(uit.trace, ",\"uid\":%lu,\"cycle\":%lu,\"event_seq\":%lu,\"before_count\":%lu,\"kind\":%u,\"pc\":\"0x%lx\",\"target\":\"0x%lx\",\"write_seen\":%u,\"write_data\":\"0x%lx\",\"post\":", s.uid, s.cycle, s.eventSeq, s.beforeCount, s.kind, s.pc, s.target, s.writeSeen, s.writeData);
    uit_log_bank(uit.trace, UIT_BANK(s, post_)); fprintf(uit.trace, "}\n");
  }
  for (const auto &c : dut->uit_cancel) {
    if (!c.valid) continue;
    if (c.epoch != uit.epoch || c.reason < 1 || c.reason > 3 || c.hadEffect || uit.canceled.count(c.uid)) return uit.error("illegal or duplicate cancellation after effect", c.uid);
    uit.canceled.insert(c.uid);
    auto found = uit.accesses.find(c.uid);
    if (c.reason != 2 && found != uit.accesses.end()) { uit.accesses.erase(found); uit.closed.insert(c.uid); }
    uit.prefix("cancel");
    fprintf(uit.trace, ",\"uid\":%lu,\"cycle\":%lu,\"reason\":%u,\"had_effect\":%u}\n", c.uid, c.cycle, c.reason, c.hadEffect);
  }
  const auto &u = dut->uit_uart;
  if (u.valid) {
    if (u.epoch != uit.epoch || u.address != DIFFTEST_UIT_UART_TX || u.length != 1 || uit.uart.size() >= UitBridge::capacity) {
      fprintf(stderr, "UIT06 UART observation: epoch=%lu cycle=%lu address=0x%lx length=%u data=0x%lx queued=%zu\n", u.epoch, u.cycle, u.address, u.length, u.data, uit.uart.size());
      return uit.error("invalid UART observation");
    }
    // The observer aligns the AXI beat to the addressed lane. AXI4UART consumes
    // only that byte; a byte store may replicate data into unused upper lanes.
    auto byte = u;
    byte.data &= 0xff;
    uit.uart.push_back(byte);
  }
  return 0;
}

bool Difftest::uit_ready(const DiffTestState &frame) {
  for (int i = 0; i < CONFIG_DIFF_COMMIT_WIDTH; i++) {
    if (!frame.commit[i].valid) continue;
#ifdef CONFIG_DIFFTEST_FDIOBSERVATION
    if (!fdi.ready(frame.uit_retire[i].uid, frame.commit[i].instr)) return false;
#endif
    if (UitBridge::controlled(frame.commit[i].instr)) {
      auto found = uit.accesses.find(frame.uit_retire[i].uid);
      if (found == uit.accesses.end() || !found->second.responded || !found->second.captured) return false;
    }
  }
  if (frame.event.valid) {
    auto found = uit.events.find(frame.event.eventSeq);
    if (found == uit.events.end()) return false;
#ifdef CONFIG_DIFFTEST_FDIOBSERVATION
    if (!fdi.event_ready(frame.event.eventSeq, found->second.uid, frame.event.exceptionInst,
                         bool(frame.event.interrupt))) return false;
#endif
    const bool disabled_uret_decode = !frame.uit_clock.enabled && frame.event.exceptionInst == 0x00200073 && frame.event.exception == 2 && !frame.event.interrupt && !uit.accesses.count(found->second.uid);
    if (UitBridge::controlled(frame.event.exceptionInst) && !disabled_uret_decode) {
      auto access = uit.accesses.find(found->second.uid);
      if (access == uit.accesses.end() || !access->second.responded || !access->second.captured) return false;
    }
  }
  return true;
}

int Difftest::uit_step() {
#if defined(CONFIG_DIFFTEST_SQUASH) || defined(CONFIG_DIFFTEST_REPLAY) || defined(CONFIG_DIFFTEST_BATCH) || defined(CONFIG_DIFFTEST_DELTA) || defined(ENABLE_RUNHEAD) || defined(BASIC_DIFFTEST_ONLY) || defined(VM_SAVABLE) || defined(DEBUG_MODE_DIFF)
  return uit.error("unsupported execution mode");
#endif
  if (NUM_CORES != 1) return uit.error("only one hart is supported");
  if (!uit.trace) {
    const char *path = getenv("UIT06_TRACE_PATH");
    if (!path || !(uit.trace = fopen(path, "wx"))) return uit.error("fresh UIT06_TRACE_PATH is required");
    const auto &caps = proxy->uit_caps();
    if (const char *fault = getenv("UIT06_FAULT_KIND")) {
      const std::set<std::string> allowed{"gpr", "ustatus", "uie", "utvec", "uscratch", "uepc", "ucause", "utval", "hu_boundary", "hu_target", "uret_target"};
      if (!allowed.count(fault)) return uit.error("unsupported comparison fault injection");
      uit.fault_kind = fault;
    }
    uit.prefix("caps");
    fprintf(uit.trace, ",\"reference_path\":\"%s\",\"abi\":%u,\"features\":%lu,\"xlen\":%u,\"vlen\":%u,\"legacy_regcpy_bytes\":%u,\"legacy_regcpy_arity\":%u}\n", proxy->reference_path().c_str(), caps.version, caps.enabled_features, caps.xlen, caps.vlen, caps.legacy_regcpy_bytes, caps.legacy_regcpy_arity);
  }
  if (uit_ingest()) return 1;
  if (!uit.released) { uit_clear_captured_valid(*dut); return 0; }
  if (uit.frames.size() >= UitBridge::capacity) return uit.error("comparison frame FIFO overflow");
  uit.frames.emplace_back(new DiffTestState(*dut));
  uit_clear_captured_valid(*dut);
  auto *live = dut;
  while (!uit.frames.empty() && uit_ready(*uit.frames.front())) {
    dut = uit.frames.front().get();
    int result = check_all();
    dut = live;
    if (result) { uit.failed = true; return result; }
    uit.frames.pop_front();
  }
  return uit_check_uart();
}

int Difftest::uit_compare_bank(const std::array<uint64_t, 8> &expected, uint64_t uid, const char *stage, uint64_t event) {
  DifftestUitState actual{};
  if (proxy->uit_state(actual) != DIFFTEST_UIT_OK) return uit.error("reference state export failed", uid);
  if (actual.version != DIFFTEST_UIT_VERSION || actual.bytes != sizeof(actual) || actual.hart != uint32_t(id) || actual.epoch != uit.epoch || actual.last_control_seq != uit.control_seq) return uit.error("reference state header mismatch", uid);
  const std::array<uint64_t, 8> values{actual.ustatus, actual.uie, actual.utvec, actual.uscratch, actual.uepc, actual.ucause, actual.utval, actual.in_handler};
  auto comparison = expected;
  if (!uit.fault_used && strcmp(stage, "post") == 0) {
    static const uint16_t addresses[] = {0x000, 0x004, 0x005, 0x040, 0x041, 0x042, 0x043};
    auto access = uit.accesses.find(uid);
    for (size_t i = 0; i < 7; i++) {
      if (uit.fault_kind == uit_bank_names[i] && access != uit.accesses.end() && access->second.request.legal && access->second.request.csr == addresses[i]) {
        comparison[i] ^= 1;
        uit.inject(uit_bank_names[i], uid, expected[i], comparison[i]);
      }
    }
  }
  bool equal = comparison == values;
  for (size_t i = 0; i < 7; i++) { uit.compare_attempts[i]++; uit.compare_passes[i] += comparison[i] == values[i]; }
  uit.prefix("compare");
  fprintf(uit.trace, ",\"uid\":%lu,\"control_seq\":%lu,\"event_seq\":%lu,\"stage\":\"%s\",\"pass\":%s,\"dut\":", uid, uit.control_seq + (strcmp(stage, "pre") == 0), event, stage, equal ? "true" : "false");
  uit_log_bank(uit.trace, comparison); fprintf(uit.trace, ",\"ref\":"); uit_log_bank(uit.trace, values); fprintf(uit.trace, "}\n");
  if (!equal) return uit.error("ordinary user architectural state mismatch", uid);
  return 0;
}

int Difftest::uit_execute(uint64_t uid, uint32_t instruction, uint64_t pc, bool fault) {
  auto found = uit.accesses.find(uid);
  if (found == uit.accesses.end() || !found->second.responded || !found->second.captured) return uit.error("missing controlled transaction", uid);
  auto access = found->second;
  const auto &a = access.request;
  if (a.pc != pc || a.instr != instruction || uit.closed.count(uid)) return uit.error("wrong dynamic transaction", uid);
  proxy->sync();
  if (proxy->pc != pc || a.pre_debugMode || proxy->csr.privilegeMode != a.pre_privilegeMode || proxy->hcsr.virtMode != a.pre_virtMode) return uit.error("controlled execution PC or mode mismatch", uid);
  if (uit_compare_bank(UIT_BANK(a, pre_), uid, "pre")) return 1;
  DifftestUitExecRequest request{};
  request.version = DIFFTEST_UIT_VERSION; request.bytes = sizeof(request);
  request.hart = id; request.kind = a.isUret ? DIFFTEST_UIT_URET : DIFFTEST_UIT_CSR;
  request.epoch = uit.epoch; request.transaction_uid = uid; request.control_seq = ++uit.control_seq;
  request.diagnostic_pc = pc; request.instruction = instruction;
  request.csr = a.isUret ? 0xffff : a.csr; request.funct3 = a.isUret ? 0 : a.funct3;
  request.sample_kind = a.sampleKind; request.sample_payload = a.sampleValue;
  DifftestUitExecResult result{};
  const int rc = proxy->uit_exec(request, result);
  if (rc != DIFFTEST_UIT_OK) { fprintf(stderr, "UIT06 reference exec error %d\n", rc); return uit.error("reference rejected controlled execution", uid); }
  proxy->sync();
  uit.controlled_exec++; uit.all_instr += !fault;
  uit.sample_timer += a.sampleKind == 1; uit.sample_pending += a.sampleKind == 2;
  uit.uret += a.isUret && !fault;
  uit.prefix("exec");
  fprintf(uit.trace, ",\"uid\":%lu,\"control_seq\":%lu,\"pc_before\":\"0x%lx\",\"pc_after\":\"0x%lx\",\"instruction\":\"0x%08x\",\"csr\":%u,\"sample_kind\":%u,\"payload\":\"0x%lx\",\"sample_consumed\":%u,\"outcome\":%u,\"csr_write_valid\":%u,\"csr_write_value\":\"0x%lx\"}\n", uid, uit.control_seq, pc, proxy->pc, instruction, request.csr, request.sample_kind, request.sample_payload, result.sample_consumed, result.outcome, result.csr_write_valid, result.csr_write_value);
  if (result.version != DIFFTEST_UIT_VERSION || result.bytes != sizeof(result) || result.hart != uint32_t(id) || result.epoch != uit.epoch || result.transaction_uid != uid || result.control_seq != uit.control_seq || result.outcome != (fault ? DIFFTEST_UIT_ISA_EXCEPTION : DIFFTEST_UIT_RETIRED) || result.sample_consumed != (a.sampleKind != 0)) return uit.error("controlled execution outcome mismatch", uid);
  if (fault != bool(access.response.illegal || access.response.virtualFault)) return uit.error("DUT response outcome mismatch", uid);
  if (!fault && a.sampleKind) {
    const uint64_t expected_read = a.sampleKind == 1 ? a.sampleValue : a.sampleValue << 4;
    if (access.response.rdata != expected_read) return uit.error("DUT CSR response differs from its read sample", uid);
  }
  if (!fault && access.snapshot.writeSeen && (!result.csr_write_valid || access.snapshot.writeData != result.csr_write_value)) return uit.error("DUT CSR write request differs from reference calculation", uid);
  if (uit_compare_bank(UIT_BANK(access.snapshot, post_), uid, "post")) return 1;
  if (!fault && a.isUret && !uit.fault_used && uit.fault_kind == "uret_target") {
    const auto original = access.snapshot.target;
    access.snapshot.target ^= 2;
    uit.inject("uret_target", uid, original, access.snapshot.target);
  }
  if (!fault && a.isUret && proxy->pc != access.snapshot.target) return uit.error("URET target mismatch", uid);
  uit.accesses.erase(found); uit.closed.insert(uid);
  return 0;
}

int Difftest::uit_event() {
  auto found = uit.events.find(dut->event.eventSeq);
  if (found == uit.events.end()) return uit.error("missing architectural event snapshot");
  auto event = found->second;
  if (event.eventSeq != uit.event_seq + 1 || event.beforeCount != uit.retired || event.pc != dut->event.exceptionPC) return uit.error("architectural event order or identity mismatch", event.uid);
  proxy->sync();
  if (dut->event.irToHU && !uit.fault_used && uit.fault_kind == "hu_boundary") {
    const auto original = event.pc;
    event.pc ^= 2;
    uit.inject("hu_boundary", event.uid, original, event.pc);
  }
  if (proxy->pc != event.pc) return uit.error("reference PC differs from event boundary", event.uid);
  const uint64_t pc_before = proxy->pc;
#ifdef CONFIG_DIFFTEST_FDIOBSERVATION
  if (fdi_before_event(event)) return 1;
#endif
  const bool decode_fault = !dut->uit_clock.enabled && !dut->event.interrupt && dut->event.exceptionInst == 0x00200073 && dut->event.exception == 2 && !uit.accesses.count(event.uid);
  if (dut->event.irToHU) {
    if (dut->event.interrupt != 4 || dut->event.exception || dut->event.hasNMI || dut->event.irToHS || dut->event.irToVS || dut->event.virtualInterruptIsHvictlInject) return uit.error("invalid HU event type", event.uid);
    DifftestUitHUEvent request{};
    request.version = DIFFTEST_UIT_VERSION; request.bytes = sizeof(request); request.hart = id;
    request.event_kind = DIFFTEST_UIT_HU_TIMER; request.epoch = uit.epoch;
    request.event_uid = event.uid; request.control_seq = ++uit.control_seq;
    request.boundary_pc = event.pc; request.diagnostic_target = event.target;
    request.prior_instruction_count = uit.retired - uit.initial_retired;
    if (proxy->uit_event(request) != DIFFTEST_UIT_OK) return uit.error("reference rejected HU event", event.uid);
    state->record_interrupt(event.pc, 0, 4); uit.hu_events++; progress = true;
  } else if (dut->event.interrupt) {
    do_interrupt();
  } else if (UitBridge::controlled(dut->event.exceptionInst) &&
             !decode_fault) {
    state->record_exception(event.pc, dut->event.exceptionInst, dut->event.exception);
    if (uit_execute(event.uid, dut->event.exceptionInst, event.pc, true)) return 1;
    progress = true;
  } else {
    do_exception();
  }
  proxy->sync();
#ifdef CONFIG_DIFFTEST_FDIOBSERVATION
  if (fdi_after_boundary()) return 1;
#endif
  if (dut->event.irToHU && !uit.fault_used && uit.fault_kind == "hu_target") {
    const auto original = event.target;
    event.target ^= 2;
    uit.inject("hu_target", event.uid, original, event.target);
  }
  uit.prefix("event");
  fprintf(uit.trace, ",\"rob\":%u,\"robflag\":%u,\"frame_cycle\":%lu", event.robIdx, event.robFlag, dut->uit_clock.cycle);
  fprintf(uit.trace, ",\"instruction\":\"0x%08x\",\"exception_cause\":%u,\"decode_fault\":%s", dut->event.exceptionInst, dut->event.exception, decode_fault ? "true" : "false");
  fprintf(uit.trace, ",\"uid\":%lu,\"event_seq\":%lu,\"control_seq\":%lu,\"kind\":\"%s\",\"before_count\":%lu,\"pc_before\":\"0x%lx\",\"pc_after\":\"0x%lx\",\"dut_pc\":\"0x%lx\",\"dut_target\":\"0x%lx\"}\n", event.uid, event.eventSeq, uit.control_seq, dut->event.irToHU ? "hu_timer" : dut->event.interrupt ? "interrupt" : "exception", event.beforeCount, pc_before, proxy->pc, event.pc, event.target);
  if (proxy->pc != event.target) return uit.error("architectural event target mismatch", event.uid);
  if (uit_compare_bank(UIT_BANK(event, post_), event.uid, "event", event.eventSeq)) return 1;
#define UIT_COPY_CSR(name) dut->csr.name = event.csrState_##name;
  UIT_COPY_CSR(privilegeMode) UIT_COPY_CSR(mstatus) UIT_COPY_CSR(sstatus) UIT_COPY_CSR(mepc)
  UIT_COPY_CSR(sepc) UIT_COPY_CSR(mtval) UIT_COPY_CSR(stval) UIT_COPY_CSR(mtvec)
  UIT_COPY_CSR(stvec) UIT_COPY_CSR(mcause) UIT_COPY_CSR(scause) UIT_COPY_CSR(satp)
  UIT_COPY_CSR(mip) UIT_COPY_CSR(mie) UIT_COPY_CSR(mscratch) UIT_COPY_CSR(sscratch)
  UIT_COPY_CSR(mideleg) UIT_COPY_CSR(medeleg)
#undef UIT_COPY_CSR
#define UIT_COPY_HCSR(name) dut->hcsr.name = event.hcsrState_##name;
  UIT_COPY_HCSR(virtMode) UIT_COPY_HCSR(mtval2) UIT_COPY_HCSR(mtinst) UIT_COPY_HCSR(hstatus)
  UIT_COPY_HCSR(hideleg) UIT_COPY_HCSR(hedeleg) UIT_COPY_HCSR(hcounteren) UIT_COPY_HCSR(htval)
  UIT_COPY_HCSR(htinst) UIT_COPY_HCSR(hgatp) UIT_COPY_HCSR(vsstatus) UIT_COPY_HCSR(vstvec)
  UIT_COPY_HCSR(vsepc) UIT_COPY_HCSR(vscause) UIT_COPY_HCSR(vstval) UIT_COPY_HCSR(vsatp) UIT_COPY_HCSR(vsscratch)
#undef UIT_COPY_HCSR
  uit.event_seq = event.eventSeq; uit.events.erase(found); dut->event.valid = 0;
  return 0;
}

int Difftest::uit_check_uart() {
  if (!uit.initialized) return 0;
  while (!uit.uart.empty()) {
    DifftestUitTx tx{};
    const int rc = proxy->uit_tx(tx);
    if (rc == DIFFTEST_UIT_EMPTY) return 0;
    if (rc != DIFFTEST_UIT_OK) return uit.error("reference UART export failed");
    const auto actual = uit.uart.front(); uit.uart.pop_front();
    bool equal = tx.version == DIFFTEST_UIT_VERSION && tx.bytes == sizeof(tx) && tx.epoch == uit.epoch && tx.hart == 0 && tx.address == actual.address && tx.len == actual.length && tx.data == actual.data;
    uit.prefix("uart");
    fprintf(uit.trace, ",\"dut_cycle\":%lu,\"reference_pc\":\"0x%lx\",\"address\":\"0x%lx\",\"dut_byte\":%lu,\"ref_byte\":%lu,\"pass\":%s}\n", actual.cycle, tx.pc, tx.address, actual.data, tx.data, equal ? "true" : "false");
    if (!equal) return uit.error("UART output mismatch");
    uit.uart_compares++;
  }
  return 0;
}

int Difftest::uit_finalize() {
  if (uit.finalized) return uit.failed;
  if (uit_check_uart()) uit.failed = true;
  if (!uit.terminal_seen || !uit.raw_terminal_seen || !uit.terminal_compared) uit.error("terminal instruction has not been compared");
  if (!uit.fault_kind.empty() && !uit.fault_used) uit.error("requested comparison fault was not exercised");
#ifdef CONFIG_DIFFTEST_STOREEVENT
  if (!store_event_queue.empty()) uit.error("uncompared DUT stores at termination");
#endif
  if (!uit.initialized || !uit.frames.empty() || !uit.accesses.empty() || !uit.events.empty() || !uit.uart.empty() || uit.all_instr != uit.retired - uit.initial_retired) uit.error("unclosed transactions or retirement mismatch at termination");
  DifftestUitTx tx{};
  if (uit.initialized && proxy->uit_tx(tx) != DIFFTEST_UIT_EMPTY) uit.error("unmatched reference UART output at termination");
#ifdef CONFIG_DIFFTEST_FDIOBSERVATION
  if (fdi_finalize()) uit.failed = true;
#endif
  uit.summary();
  return uit.failed;
}

int Difftest::uit_status() {
  if (uit.failed) return STATE_ABORT;
  const int reference_status = proxy ? proxy->get_status() : 0;
  if (reference_status && (!uit.terminal_seen || !uit.raw_terminal_seen || !uit.terminal_compared)) {
    uit.error("reference ended before the terminal comparison");
    return STATE_ABORT;
  }
  if (!uit.terminal_compared) return STATE_RUNNING;
  if (!uit.raw_terminal_seen || !uit.terminal_seen) { uit.error("missing raw terminal marker"); return STATE_ABORT; }
  if (uit.terminal_trap.code || reference_status != STATE_SIM_EXIT) uit.error("DUT or reference termination failed");
  if (uit_finalize()) return STATE_ABORT;
  return STATE_GOODTRAP;
}
#undef UIT_BANK
#endif
