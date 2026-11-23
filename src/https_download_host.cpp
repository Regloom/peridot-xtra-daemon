#include "https_download_host.h"
#include <curl/curl.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <string_view>

namespace xtra::https_host {
namespace {
using Clock = std::chrono::steady_clock;
constexpr size_t kLocalCap = 1024 * 1024, kHeaderCap = 16384;

struct State {
    std::function<bool()> allowed;
    Clock::time_point deadline;
    size_t cap, header_bytes = 0;
    const char* error = nullptr;
    bool status_seen = false, headers_done = false, length_seen = false;
    bool encoding_seen = false, transfer_seen = false;
    uint64_t length = 0;
    std::vector<uint8_t> data;

    void fail(const char* reason) { if (!error) error = reason; }
    bool check() noexcept {
        if (error) return false;
        try {
            if (!allowed()) fail("cancelled");
        } catch (...) { fail("policy_callback_failed"); }
        if (Clock::now() >= deadline) fail("deadline");
        return !error;
    }
};

bool iequal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        auto c = a[i];
        if (c >= 'A' && c <= 'Z') c = char(c + ('a' - 'A'));
        if (c != b[i]) return false;
    }
    return true;
}
std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

size_t header(char* p, size_t size, size_t count, void* cookie) noexcept {
    auto& s = *static_cast<State*>(cookie);
    if (!s.check()) return 0;
    if (size && count > std::numeric_limits<size_t>::max() / size) { s.fail("header_overflow"); return 0; }
    const size_t n = size * count;
    if (!n || n > kHeaderCap - s.header_bytes) { s.fail("headers_too_large"); return 0; }
    s.header_bytes += n;
    std::string_view line(p, n);
    if (line.size() < 2 || line.substr(line.size() - 2) != "\r\n") { s.fail("malformed_header"); return 0; }
    line.remove_suffix(2);
    if (line.substr(0, 5) == "HTTP/") {
        if (s.status_seen || line.size() < 12 || line.substr(0, 9) != "HTTP/1.1 " ||
            line.substr(9, 3) != "200" || (line.size() > 12 && line[12] != ' ')) {
            s.fail("http_status_rejected"); return 0;
        }
        s.status_seen = true;
        return n;
    }
    if (!s.status_seen || s.headers_done) { s.fail("unexpected_header_or_trailer"); return 0; }
    if (line.empty()) {
        if (s.length_seen && s.transfer_seen) { s.fail("ambiguous_body_framing"); return 0; }
        s.headers_done = true;
        return n;
    }
    const auto colon = line.find(':');
    if (!colon || colon == std::string_view::npos || line.front() == ' ' || line.front() == '\t') {
        s.fail("malformed_header"); return 0;
    }
    const auto name = line.substr(0, colon), value = trim(line.substr(colon + 1));
    if (iequal(name, "content-length")) {
        if (s.length_seen || value.empty()) { s.fail("invalid_content_length"); return 0; }
        s.length_seen = true;
        for (char c : value) {
            if (c < '0' || c > '9' || s.length > (std::numeric_limits<uint64_t>::max() - unsigned(c - '0')) / 10) {
                s.fail("invalid_content_length"); return 0;
            }
            s.length = s.length * 10 + unsigned(c - '0');
        }
        if (s.length > s.cap) { s.fail("body_exceeds_event_limits"); return 0; }
    } else if (iequal(name, "content-encoding")) {
        if (s.encoding_seen || !iequal(value, "identity")) { s.fail("encoded_body_rejected"); return 0; }
        s.encoding_seen = true;
    } else if (iequal(name, "transfer-encoding")) {
        if (s.transfer_seen || !iequal(value, "chunked")) { s.fail("transfer_encoding_rejected"); return 0; }
        s.transfer_seen = true;
    }
    return n;
}

size_t body(char* p, size_t size, size_t count, void* cookie) noexcept {
    auto& s = *static_cast<State*>(cookie);
    if (!s.check()) return 0;
    if (size && count > std::numeric_limits<size_t>::max() / size) { s.fail("body_overflow"); return 0; }
    const size_t n = size * count;
    if (!s.headers_done) { s.fail("body_before_headers"); return 0; }
    if (n > s.cap - s.data.size() || (s.length_seen && n > s.length - s.data.size())) {
        s.fail("body_exceeds_event_limits"); return 0;
    }
    try { s.data.insert(s.data.end(), p, p + n); }
    catch (...) { s.fail("body_allocation_failed"); return 0; }
    return n;
}

struct Handles {
    CURL* easy = nullptr;
    CURLM* multi = nullptr;
    curl_slist* headers = nullptr;
    bool added = false, closed = false, abandoned = false;
    bool close() {
        if (closed) return !abandoned;
        closed = true;
        if (added && curl_multi_remove_handle(multi, easy) != CURLM_OK) { abandoned = true; return false; }
        if (multi && curl_multi_cleanup(multi) != CURLM_OK) { abandoned = true; return false; }
        if (easy) curl_easy_cleanup(easy);
        curl_slist_free_all(headers);
        return true;
    }
    ~Handles() { close(); }
};

bool hasHttps(const curl_version_info_data* info) {
    if (!info || !info->protocols) return false;
    for (auto p = info->protocols; *p; ++p) if (std::string_view(*p) == "https") return true;
    return false;
}
bool forbiddenEnvironment() {
    // Never change the host environment. Refuse key logging/backend/trust
    // overrides BEFORE curl global init. Proxy environment is separately disabled.
    for (const auto* name : {"SSLKEYLOGFILE", "CURL_SSL_BACKEND", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"}) {
        const auto* value = std::getenv(name);
        if (value && *value) return true;
    }
    return false;
}
}

Result downloadFixed(const Policy& policy, const std::function<bool()>& allowed) {
    Result result;
    const bool legacy = !policy.ca_bundle.empty();
    const auto mode = policy.trust.mode;
    const auto& trust_path = legacy ? policy.ca_bundle : policy.trust.path;
    const bool valid_trust = (mode == TrustMode::CaFile || mode == TrustMode::CaPath) &&
        !(legacy && (!policy.trust.path.empty() || mode != TrustMode::CaFile)) &&
        !trust_path.empty() && trust_path.front() == '/' && trust_path.find('\0') == std::string::npos;
    if (!allowed || !policy.event_max_file_bytes || !policy.timeout_ms || policy.timeout_ms > 60000 ||
        !policy.connect_timeout_ms || policy.connect_timeout_ms > policy.timeout_ms || !valid_trust) {
        result.error = "invalid_explicit_policy"; return result;
    }
    if (forbiddenEnvironment()) { result.error = "network_environment_override_rejected"; return result; }
    auto state = std::make_unique<State>(State{allowed, Clock::now() + std::chrono::milliseconds(policy.timeout_ms),
        std::min(kLocalCap, size_t(policy.event_max_file_bytes)), 0, nullptr, false, false, false, false, false, 0, {}});
    if (!state->check()) { result.error = state->error; return result; }
    static std::once_flag once;
    static CURLcode initialized = CURLE_FAILED_INIT;
    std::call_once(once, [] { initialized = curl_global_init(CURL_GLOBAL_DEFAULT); });
    if (initialized != CURLE_OK) { result.error = "curl_initialization_failed"; return result; }
    const auto* version = curl_version_info(CURLVERSION_NOW);
    if (!version || version->version_num < 0x075500 || !(version->features & CURL_VERSION_SSL) ||
        !(version->features & CURL_VERSION_ASYNCHDNS) || !hasHttps(version)) {
        result.error = "unsupported_host_curl_features"; return result;
    }
    Handles h;
    h.easy = curl_easy_init(); h.multi = curl_multi_init();
    const auto finish = [&]() -> Result {
        result.error = state->error;
        if (!h.close()) {
            result.error = "cleanup_state_unknown"; result.cleanup_unknown = true;
            state.release();  // keep callback context alive, leak handles until worker exit
            return std::move(result);
        }
        if (state->check()) result.bytes = std::move(state->data);
        result.error = state->error;
        return std::move(result);
    };
    if (!h.easy || !h.multi) { state->fail("curl_handle_allocation_failed"); return finish(); }
    for (const auto* line : {"Accept: application/octet-stream", "Accept-Encoding: identity"}) {
        auto* next = curl_slist_append(h.headers, line);
        if (!next) { state->fail("header_allocation_failed"); return finish(); }
        h.headers = next;
    }
    const auto option = [&](CURLoption key, auto value) {
        if (!state->error && curl_easy_setopt(h.easy, key, value) != CURLE_OK) state->fail("curl_option_rejected");
    };
    option(CURLOPT_URL, kEndpoint);
    option(CURLOPT_PROTOCOLS_STR, "https"); option(CURLOPT_REDIR_PROTOCOLS_STR, "https");
    option(CURLOPT_FOLLOWLOCATION, 0L); option(CURLOPT_MAXREDIRS, 0L);
    option(CURLOPT_SSL_VERIFYPEER, 1L); option(CURLOPT_SSL_VERIFYHOST, 2L);
    option(CURLOPT_CAINFO, mode == TrustMode::CaFile ? trust_path.c_str() : static_cast<const char*>(nullptr));
    option(CURLOPT_CAPATH, mode == TrustMode::CaPath ? trust_path.c_str() : static_cast<const char*>(nullptr));
    option(CURLOPT_SSLVERSION, long(CURL_SSLVERSION_TLSv1_2));
    option(CURLOPT_PROXY, ""); option(CURLOPT_NOPROXY, "*"); option(CURLOPT_NETRC, long(CURL_NETRC_IGNORED));
    option(CURLOPT_HTTPAUTH, long(CURLAUTH_NONE)); option(CURLOPT_PROXYAUTH, long(CURLAUTH_NONE));
    option(CURLOPT_HSTS_CTRL, 0L);
    // Fresh easy handle, no share/Alt-Svc options: engine stays disabled by default.
    // ALTSVC_CTRL=0 is INVALID (43), while nonzero or ALTSVC(NULL) initializes it.
    option(CURLOPT_UNRESTRICTED_AUTH, 0L); option(CURLOPT_SSL_SESSIONID_CACHE, 0L);
    option(CURLOPT_AUTOREFERER, 0L); option(CURLOPT_VERBOSE, 0L); option(CURLOPT_NOSIGNAL, 1L);
    option(CURLOPT_HTTPGET, 1L); option(CURLOPT_HTTP_VERSION, long(CURL_HTTP_VERSION_1_1));
    option(CURLOPT_HTTP_CONTENT_DECODING, 0L); option(CURLOPT_HTTP_TRANSFER_DECODING, 1L);
    option(CURLOPT_TIMEOUT_MS, long(policy.timeout_ms)); option(CURLOPT_CONNECTTIMEOUT_MS, long(policy.connect_timeout_ms));
    option(CURLOPT_USERAGENT, "Android-PSDS"); option(CURLOPT_HTTPHEADER, h.headers);
    option(CURLOPT_HEADERFUNCTION, header); option(CURLOPT_HEADERDATA, state.get());
    option(CURLOPT_WRITEFUNCTION, body); option(CURLOPT_WRITEDATA, state.get());
    option(CURLOPT_FRESH_CONNECT, 1L); option(CURLOPT_FORBID_REUSE, 1L);
    if (state->error) return finish();
    result.tls_policy_configured = true;
    if (!state->check()) return finish();
    if (curl_multi_add_handle(h.multi, h.easy) != CURLM_OK) { state->fail("curl_add_failed"); return finish(); }
    h.added = true;
    bool done = false;
    while (!done && state->check()) {
        int running = 0;
        if (curl_multi_perform(h.multi, &running) != CURLM_OK) { state->fail("curl_perform_failed"); break; }
        if (!state->check()) break;
        int remaining = 0;
        while (auto* message = curl_multi_info_read(h.multi, &remaining)) {
            if (message->msg != CURLMSG_DONE || message->easy_handle != h.easy || done) {
                state->fail("unexpected_curl_completion"); break;
            }
            done = true;
            result.curl_completion_code = static_cast<int>(message->data.result);
            if (message->data.result != CURLE_OK) state->fail("https_transport_failed");
        }
        if (done || state->error) break;
        if (!running) { state->fail("missing_curl_completion"); break; }
        int fds = 0;
        if (curl_multi_poll(h.multi, nullptr, 0, 20, &fds) != CURLM_OK) { state->fail("curl_poll_failed"); break; }
    }
    if (!state->error) {
        long status = 0, redirects = -1, verify = -1;
        char* effective = nullptr;
        if (!done || !state->headers_done || state->data.empty() ||
            (state->length_seen && state->length != state->data.size())) state->fail("incomplete_or_empty_body");
        else if (curl_easy_getinfo(h.easy, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK ||
            curl_easy_getinfo(h.easy, CURLINFO_REDIRECT_COUNT, &redirects) != CURLE_OK ||
            curl_easy_getinfo(h.easy, CURLINFO_SSL_VERIFYRESULT, &verify) != CURLE_OK ||
            curl_easy_getinfo(h.easy, CURLINFO_EFFECTIVE_URL, &effective) != CURLE_OK ||
            status != 200 || redirects || verify || !effective || std::string_view(effective) != kEndpoint)
             state->fail("final_https_receipt_rejected");
        result.http_status = status;
    }
    return finish();
}
}
