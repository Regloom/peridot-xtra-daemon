#pragma once
// Shared HTTPS core: host review/tests OR dedicated Android HTTPS-only probe.
// This does NOT enable the refresh owner or any LOC variant on Android.
#if defined(XTRA_ANDROID_HTTPS_PROBE) || defined(XTRA_ANDROID_REFRESH_ONCE) || defined(XTRA_ANDROID_REFRESH_DAEMON)
#if !defined(__ANDROID__) || defined(XTRA_HOST_HTTPS_ADAPTER) || defined(XTRA_HOST_TEST) || defined(XTRA_REFRESH_HTTPS_FAKE)
#error Android HTTPS-only profile cannot select host/fake modes
#endif
#elif !defined(XTRA_HOST_HTTPS_ADAPTER) || defined(__ANDROID__)
#error HTTPS adapter is explicitly host-only except dedicated Android HTTPS probe
#endif
#if !defined(XTRA_ANDROID_REFRESH_ONCE) && !defined(XTRA_ANDROID_REFRESH_DAEMON) && ( \
    defined(XTRA_ANDROID_EXPERIMENT) || defined(XTRA_ANDROID_LIMITS_DIAGNOSTIC) || \
    defined(XTRA_ANDROID_QCCI_OBSERVER) || defined(XTRA_ANDROID_STATUS_OBSERVER) || \
    defined(XTRA_ANDROID_STATUS_LIMITS_SEQUENCE) || defined(XTRA_ANDROID_SUPPORT_OBSERVER) || \
    defined(XTRA_ANDROID_EVENT29_OBSERVER) || defined(XTRA_ANDROID_EVENT29_SENDER) || \
    defined(XTRA_DEVICE_POLICY_TEST))
#error HTTPS adapter is explicitly host-only; no LOC/device-policy target
#endif
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace xtra::https_host {
constexpr const char* kEndpoint = "https://qualcomm.psds.grapheneos.org/xtra3Mgrbeji.bin";
enum class TrustMode { CaFile, CaPath };
struct TrustStore {
    TrustMode mode = TrustMode::CaFile;
    std::string path;  // explicit local trust material, never event/server supplied
};
struct Policy {
    uint32_t event_max_file_bytes = 0;  // externally validated SAME-session event only
    unsigned timeout_ms = 0, connect_timeout_ms = 0;
    std::string ca_bundle;  // legacy explicit CaFile; cannot be combined with trust
    TrustStore trust;
};
struct Result {
    const char* error = nullptr;
    std::vector<uint8_t> bytes;  // populated only on bounded complete success
    bool tls_policy_configured = false;
    bool cleanup_unknown = false;
    long http_status = 0;  // 0 = not observed by final receipt check
    int curl_completion_code = -1;  // -1 = no DONE message observed
    // Backend may be a fake in tests. These fields never authenticate XTRA or
    // establish LOC freshness, consent/exclusion, modem acceptance or usability.
};
// No URL, cookie, credential or proxy override API. Caller MUST keep this outside
// LOC callbacks and in a separately bounded worker: resolver/cleanup may block.
// A fresh easy/multi handle is used once. No retry or background rearm.
Result downloadFixed(const Policy&, const std::function<bool()>& continue_allowed);
}
