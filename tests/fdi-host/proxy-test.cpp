#define main unused_uit_proxy_main
#include "../user-timer-proxy/proxy-test.cpp"
#undef main

int main(int argc, char **argv) {
  require(argc == 3, "reference path and test");
  difftest_ref_so = argv[1];
  const std::string test = argv[2];
  NemuProxy proxy(0, 0);
  if (test == "constructor") return 0;
  DiffTestState dut{};
  initialize_dut(dut);
  if (test == "import_before_dut_reset") { proxy.regcpy(&dut); require(false, "unverified import accepted"); }
  require(!proxy.fdi.verify_dut_reset(FdiBank{}, 7), "independent DUT reset gate");
  proxy.regcpy(&dut);
  if (test == "duplicate_startup_import") { proxy.regcpy(&dut); require(false, "second import accepted"); }
  require(!proxy.fdi.initialize(), "FDI initializes without mutating its bank");
  require(proxy.uit_init(7, DIFFTEST_UIT_FEATURES) == 0, "existing UIT initialization preserved");
  DifftestFdiState before{}, after{};
  require(!proxy.fdi.read(before), "FDI read after UIT init");
  if (test == "runtime_import") { proxy.sync(true); require(false, "runtime import accepted"); }
  proxy.sync();
  require(!proxy.fdi.read(after) && !memcmp(&before, &after, sizeof(before)), "ordinary export preserves FDI");
  require(proxy.get_reg_size() == 1400 && proxy.uit_caps().legacy_csrcpy_bytes == 32768,
          "ordinary transfer layout unchanged");
  puts("FDI_PROXY_UNIT_PASS: production proxy with fake reference");
  return 0;
}
