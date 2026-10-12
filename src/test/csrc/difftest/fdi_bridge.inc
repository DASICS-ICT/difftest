#ifdef CONFIG_DIFFTEST_FDIOBSERVATION

static void fdi_log_words(FILE *trace, const FdiBank &bank) {
  fputc('[', trace);
  for (size_t i = 0; i < bank.size(); ++i) fprintf(trace, "%s\"0x%016lx\"", i ? "," : "", bank[i]);
  fputc(']', trace);
}

int Difftest::fdi_ingest() {
  if (!fdi_trace) {
    const char *path = getenv("FDI_TRACE_PATH");
    if (!path || !(fdi_trace = fopen(path, "wx"))) return uit.error("fresh FDI_TRACE_PATH is required");
  }
  // Indexed lanes preserve simultaneous access post, trap post, and cancellation
  // evidence. CSR and call share lanes under the producer's serialization check.
  static_assert(sizeof(dut->fdi_observation) / sizeof(dut->fdi_observation[0]) == 4,
                "FDI transport requires four independent observation lanes");
  std::vector<FdiObservation> packets;
  for (size_t lane = 0; lane < 4; ++lane) {
    const auto &source = dut->fdi_observation[lane];
    if (!source.valid) continue;
    if ((lane == 0 && source.kind != FDI_RESET && source.kind != FDI_CSR_PRE && source.kind != FDI_CALL_PRE) ||
        (lane == 1 && source.kind != FDI_CSR_POST && source.kind != FDI_CALL_POST) || (lane == 2 && source.kind != FDI_TRAP_POST) ||
        (lane == 3 && source.kind != FDI_CANCEL)) return uit.error("FDI observation is in the wrong lane", source.uid);
    FdiObservation packet;
#define FDI_COPY(name) packet.name = source.name
    FDI_COPY(kind); FDI_COPY(epoch); FDI_COPY(uid); FDI_COPY(cycle); FDI_COPY(pc);
    FDI_COPY(eventSeq); FDI_COPY(beforeCount); FDI_COPY(instruction); FDI_COPY(robIdx);
    FDI_COPY(robFlag); FDI_COPY(csrAddress); FDI_COPY(readNeeded); FDI_COPY(writeNeeded);
    FDI_COPY(permitted); FDI_COPY(actualWrite); FDI_COPY(responseIllegal); FDI_COPY(responseVirtual);
    FDI_COPY(cancelReason);
#undef FDI_COPY
    std::copy(std::begin(source.words), std::end(source.words), packet.words.begin());
    fprintf(fdi_trace, "{\"type\":\"observation\",\"kind\":%u,\"epoch\":%lu,\"uid\":%lu,\"cycle\":%lu,"
            "\"rob\":%u,\"robflag\":%u,\"pc\":\"0x%lx\",\"instruction\":\"0x%08x\",\"csr\":%u,"
            "\"read_needed\":%u,\"write_needed\":%u,\"permitted\":%u,\"actual_write\":%u,"
            "\"response_illegal\":%u,\"response_virtual\":%u,\"cancel_reason\":%u,\"event_seq\":%lu,"
            "\"before_count\":%lu,\"words\":", packet.kind, packet.epoch, packet.uid, packet.cycle,
            packet.robIdx, packet.robFlag, packet.pc, packet.instruction, packet.csrAddress,
            packet.readNeeded, packet.writeNeeded, packet.permitted, packet.actualWrite,
            packet.responseIllegal, packet.responseVirtual, packet.cancelReason, packet.eventSeq, packet.beforeCount);
    fdi_log_words(fdi_trace, packet.words); fputs("}\n", fdi_trace);
    packets.push_back(packet);
  }
  if (fdi.observe_frame(packets)) return uit.error(fdi.error().c_str());
  fflush(fdi_trace);
  return 0;
}

int Difftest::fdi_before_retire(int index) {
  const auto &identity = dut->uit_retire[index];
  const auto &commit = dut->commit[index];
  const FdiBoundary boundary{identity.epoch, identity.uid, commit.pc, identity.beforeCount, identity.afterCount,
                            0, commit.instr, identity.robIdx, identity.robFlag};
  DifftestFdiState reference{};
  if (proxy->fdi.read(reference) || fdi.before(boundary, reference, false))
    return uit.error("FDI pre-retirement comparison failed", identity.uid);
  fprintf(fdi_trace, "{\"type\":\"reference_before\",\"uid\":%lu,\"event_seq\":0,\"model_pc\":\"0x%lx\",\"words\":",
          identity.uid, reference.model_pc);
  fdi_log_words(fdi_trace, FdiReference::bank_of(reference)); fputs("}\n", fdi_trace);
  return 0;
}

int Difftest::fdi_before_event(const DifftestUserTimerSnapshot &event) {
  // The existing event path remains the sole owner of reference execution.
  // Synchronous fault cancellation retains its accepted UID until this point.
  const FdiBoundary boundary{event.epoch, event.uid, event.pc, event.beforeCount, event.beforeCount,
                            event.eventSeq, dut->event.exceptionInst, event.robIdx, event.robFlag,
                            bool(dut->event.interrupt)};
  DifftestFdiState reference{};
  if (proxy->fdi.read(reference) || fdi.before(boundary, reference, true))
    return uit.error("FDI pre-event comparison failed", event.uid);
  fprintf(fdi_trace, "{\"type\":\"reference_before\",\"uid\":%lu,\"event_seq\":%lu,\"model_pc\":\"0x%lx\",\"words\":",
          event.uid, event.eventSeq, reference.model_pc);
  fdi_log_words(fdi_trace, FdiReference::bank_of(reference)); fputs("}\n", fdi_trace);
  return 0;
}

int Difftest::fdi_after_boundary() {
  DifftestFdiState reference{};
  const bool pass = !proxy->fdi.read(reference) && !fdi.after(reference);
  fprintf(fdi_trace, "{\"type\":\"reference_after\",\"uid\":%lu,\"event_seq\":%lu,\"epoch\":%lu,\"model_pc\":\"0x%lx\",\"pass\":%s,\"words\":",
          fdi.current_uid(), fdi.current_event_sequence(), reference.epoch, reference.model_pc, pass ? "true" : "false");
  fdi_log_words(fdi_trace, FdiReference::bank_of(reference)); fputs("}\n", fdi_trace); fflush(fdi_trace);
  return pass ? 0 : uit.error("FDI post-boundary comparison failed");
}

int Difftest::fdi_finalize() {
  if (fdi_finalized) return fdi.failed();
  const bool pass = proxy->fdi.active() && !fdi.finalize();
  fdi_finalized = true;
  if (fdi_trace) {
    fprintf(fdi_trace, "{\"type\":\"summary\",\"status\":\"%s\",\"epoch\":%lu,\"retirement_comparisons\":%lu,"
            "\"event_comparisons\":%lu,\"canceled_accesses\":%lu,\"pending\":%zu}\n",
            pass ? "PASS" : "FAIL", fdi.epoch(), fdi.compared_retirements(), fdi.compared_events(),
            fdi.canceled_accesses(), fdi.pending());
    fflush(fdi_trace);
  }
  return pass ? 0 : uit.error("FDI comparison did not close all observations");
}

#endif
