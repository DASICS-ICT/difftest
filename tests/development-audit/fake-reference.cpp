// Reuse the ABI fixture; this library never executes processor instructions.
#define difftest_uit_query_caps fixture_query_caps
#include "../user-timer-proxy/fake-reference.cpp"
#undef difftest_uit_query_caps

extern "C" int32_t difftest_uit_query_caps(void *out, uint32_t bytes) {
  const int32_t rc = fixture_query_caps(out, bytes);
  if (rc) return rc;
  auto *caps = static_cast<DifftestUitCaps *>(out);
  const char *enabled = getenv("FAKE_DEVELOPMENT_ENABLED");
  caps->enabled_features = enabled ? strtoull(enabled, nullptr, 0) : 0;
  return 0;
}
