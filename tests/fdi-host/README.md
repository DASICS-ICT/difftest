# FDI host checks

`run-tests.py --output-dir <new-directory>` compiles the production lifecycle
and ledger against fake APIs and synthetic observations. It checks ABI shapes,
independent natural reset, import order, raw projection invariants, all 52
comparison words, delayed retirement, synchronous and asynchronous trap
boundaries, cancellation, duplicate or missing identities, and final closure.
The tests do not execute RTL or a reference ISA model.

`run-proxy-tests.py --generated-dir <directory-with-diffstate.h>
--output-dir <new-directory>` compiles the actual `RefProxy` against fake shared
libraries and syntax-checks the complete production `difftest.cpp`. If the
provided header lacks observers, the runner adds explicitly synthetic UIT/FDI
declarations only to its output fixture. That checks C++ integration, not the
generated DPI ABI. The production interface header is also usable from C11.

Both runners preserve commands, exit codes, stdout, stderr, and a JSON report
in a new output directory. Use separate directories for failed and corrected
runs. Build concurrency is capped at eight small native compiler jobs.

An enabled production observer requires the existing UIT retirement transport
and a fresh `FDI_TRACE_PATH` in addition to the existing UIT trace path. The FDI
trace records raw observed and reference words and a final closure result.
All four observation lanes must carry the current physical bank from their
stated sampling cycle, including cancellation. The host first checks the
whole cycle, then handles transaction records; it never imports an FDI bank.

True validation additionally requires the generated observer layout, real RTL
accept/effect/cancel/retirement evidence, and an independently executing NEMU
reference. Passing these native fixtures does not establish that chain.

`replay-reference.py --trace <RTL-log> --reference <NEMU-shared-library>
--generated-dir <directory-with-diffstate.h> --output-dir <new-directory>`
consumes the `FDI_REFERENCE_BEGIN` / `FDI_REFERENCE_END` region produced by
the real wrapper and shared UID observer test. It independently constructs
the fixed 104-instruction M-mode image, initializes x1 once, and uses the
production proxy and ledger to compare each real retired UID after one NEMU
instruction. It preserves the original trace and checks a separate canonical
single-word mutation. This evidence covers the local CSR hardware, observer,
host ledger, and reference together; the harness drives ROB allocation and
retirement inputs, so it is not full-processor execution.
