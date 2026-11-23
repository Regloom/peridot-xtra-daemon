// Offline C API double for libcurl. NO sockets, DNS, TLS or HTTP implementation.
#include <curl/curl.h>
#include "fake_curl_control.h"
#include <chrono>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <map>
#include <new>
#include <sstream>
#include <string>
#include <thread>

namespace {
std::string mode;
unsigned globals = 0, options = 0, adds = 0, removes = 0, polls = 0, performs = 0;
unsigned easy_cleanups = 0, multi_cleanups = 0, phase = 0;
unsigned alt_svc_attempts = 0, share_attempts = 0, easy_creations = 0, transfer_creations = 0;
bool policy_seen = false;
std::map<CURLoption, long> longs;
std::map<CURLoption, std::string> strings;
std::map<CURLoption, bool> null_strings;
curl_write_callback on_header = nullptr, on_body = nullptr;
void* header_data = nullptr;
void* body_data = nullptr;
curl_slist* request_headers = nullptr;
CURL* current = nullptr;
CURLMsg completed{};
bool message_ready = false;
bool is(const char* name) { return mode == name; }

bool send_header(const std::string& line) {
    return on_header && on_header(const_cast<char*>(line.data()), 1, line.size(), header_data) == line.size();
}
void done(CURLcode result = CURLE_OK) {
    completed.msg = CURLMSG_DONE;
    completed.easy_handle = is("wrong_completion_handle") ? nullptr : current;
    completed.data.result = result;
    message_ready = true;
}
bool options_safe() {
    for (auto key : {CURLOPT_SSL_VERIFYPEER, CURLOPT_SSL_VERIFYHOST, CURLOPT_SSLVERSION,
            CURLOPT_FOLLOWLOCATION, CURLOPT_MAXREDIRS, CURLOPT_NETRC, CURLOPT_HTTPAUTH, CURLOPT_PROXYAUTH,
            CURLOPT_AUTOREFERER, CURLOPT_VERBOSE, CURLOPT_NOSIGNAL, CURLOPT_HTTPGET, CURLOPT_HTTP_VERSION,
            CURLOPT_HSTS_CTRL, CURLOPT_HTTP_CONTENT_DECODING, CURLOPT_HTTP_TRANSFER_DECODING,
            CURLOPT_FRESH_CONNECT, CURLOPT_FORBID_REUSE, CURLOPT_UNRESTRICTED_AUTH, CURLOPT_SSL_SESSIONID_CACHE,
            CURLOPT_CONNECTTIMEOUT_MS, CURLOPT_TIMEOUT_MS}) if (!longs.count(key)) return false;
    for (auto key : {CURLOPT_URL, CURLOPT_PROTOCOLS_STR, CURLOPT_REDIR_PROTOCOLS_STR, CURLOPT_PROXY,
            CURLOPT_NOPROXY, CURLOPT_USERAGENT, CURLOPT_CAPATH, CURLOPT_CAINFO}) if (!strings.count(key)) return false;
    return !alt_svc_attempts && !share_attempts && transfer_creations == 1 &&
        strings[CURLOPT_URL] == "https://qualcomm.psds.grapheneos.org/xtra3Mgrbeji.bin" &&
        strings[CURLOPT_PROTOCOLS_STR] == "https" && strings[CURLOPT_REDIR_PROTOCOLS_STR] == "https" &&
        strings[CURLOPT_PROXY].empty() && strings[CURLOPT_NOPROXY] == "*" &&
        strings[CURLOPT_USERAGENT] == "Android-PSDS" &&
        ((null_strings[CURLOPT_CAPATH] && !null_strings[CURLOPT_CAINFO] && strings[CURLOPT_CAINFO] == "/fake/ca.pem") ||
         (null_strings[CURLOPT_CAINFO] && !null_strings[CURLOPT_CAPATH] && strings[CURLOPT_CAPATH] == "/fake/cacerts")) &&
        longs[CURLOPT_SSL_VERIFYPEER] == 1 && longs[CURLOPT_SSL_VERIFYHOST] == 2 &&
        longs[CURLOPT_SSLVERSION] == CURL_SSLVERSION_TLSv1_2 &&
        longs[CURLOPT_FOLLOWLOCATION] == 0 && longs[CURLOPT_MAXREDIRS] == 0 &&
        longs[CURLOPT_NETRC] == CURL_NETRC_IGNORED && longs[CURLOPT_HTTPAUTH] == 0 && longs[CURLOPT_PROXYAUTH] == 0 &&
        longs[CURLOPT_AUTOREFERER] == 0 && longs[CURLOPT_VERBOSE] == 0 && longs[CURLOPT_NOSIGNAL] == 1 &&
        longs[CURLOPT_HTTPGET] == 1 && longs[CURLOPT_HTTP_VERSION] == CURL_HTTP_VERSION_1_1 &&
        longs[CURLOPT_HSTS_CTRL] == 0 &&
        longs[CURLOPT_HTTP_CONTENT_DECODING] == 0 && longs[CURLOPT_HTTP_TRANSFER_DECODING] == 1 &&
        longs[CURLOPT_FRESH_CONNECT] == 1 && longs[CURLOPT_FORBID_REUSE] == 1 &&
        longs[CURLOPT_UNRESTRICTED_AUTH] == 0 && longs[CURLOPT_SSL_SESSIONID_CACHE] == 0 &&
        longs[CURLOPT_CONNECTTIMEOUT_MS] > 0 && longs[CURLOPT_TIMEOUT_MS] >= longs[CURLOPT_CONNECTTIMEOUT_MS] &&
        request_headers && request_headers->next && !request_headers->next->next &&
        std::string(request_headers->data) == "Accept: application/octet-stream" &&
        std::string(request_headers->next->data) == "Accept-Encoding: identity" &&
        on_header && on_body && header_data && body_data;
}
}

void fakeCurlConfigure(const char* name) { mode = name; }
bool fakeCurlContinue() {
    if (is("policy_throw")) throw 1;
    if (is("cancel_initial")) return false;
    if (is("cancel_wait") && polls) return false;
    if (is("cancel_body") && phase >= 2) return false;
    if (is("cancel_after_completion") && phase >= 3) return false;
    if (is("cancel_cleanup") && removes) return false;
    return true;
}
const char* fakeCurlStats() {
    static std::string output;
    std::ostringstream out;
    out << "{\"global_inits\":" << globals << ",\"options\":" << options
        << ",\"adds\":" << adds << ",\"removes\":" << removes << ",\"polls\":" << polls
        << ",\"performs\":" << performs << ",\"easy_cleanups\":" << easy_cleanups
        << ",\"multi_cleanups\":" << multi_cleanups << ",\"policy_safe\":"
        << (policy_seen ? "true" : "false") << ",\"alt_svc_attempts\":" << alt_svc_attempts
        << ",\"share_attempts\":" << share_attempts << ",\"easy_creations\":" << easy_creations
        << ",\"real_network_requests\":0}";
    output = out.str();
    return output.c_str();
}

// Required link-time marker for the integrated fake-LOC owner. Real libcurl
// does not provide it, so accidentally linking that backend fails before runtime.
extern "C" unsigned xtraFakeCurlOnly() { return 0x4355524c; }

extern "C" CURLcode curl_global_init(long) { ++globals; return is("init_fail") ? CURLE_FAILED_INIT : CURLE_OK; }
extern "C" curl_version_info_data* curl_version_info(CURLversion) {
    static const char* protocols[] = {"https", nullptr};
    static const char* none[] = {"http", nullptr};
    static curl_version_info_data info{};
    info.version_num = is("old_version") ? 0x075400 : 0x080e01;
    info.features = (is("no_tls") ? 0 : CURL_VERSION_SSL) | (is("sync_dns") ? 0 : CURL_VERSION_ASYNCHDNS);
    info.protocols = is("no_https") ? none : protocols;
    return &info;
}
extern "C" CURL* curl_easy_init() {
    if (is("easy_alloc_fail")) return nullptr;
    ++easy_creations; ++transfer_creations;
    // Fresh per-transfer fixture state: a long-lived daemon downloads many times per process.
    phase = 0; message_ready = false; policy_seen = false; current = nullptr;
    longs.clear(); strings.clear(); null_strings.clear(); request_headers = nullptr;
    on_header = on_body = nullptr; header_data = body_data = nullptr;
    return reinterpret_cast<CURL*>(new int(1));
}
extern "C" CURLM* curl_multi_init() {
    if (is("multi_alloc_fail")) return nullptr;
    return reinterpret_cast<CURLM*>(new int(2));
}
extern "C" CURLcode curl_easy_setopt(CURL*, CURLoption key, ...) {
    ++options;
    if (is("option_fail") && key == CURLOPT_SSL_VERIFYHOST) return CURLE_UNKNOWN_OPTION;
    if ((is("ca_info_fail") && key == CURLOPT_CAINFO) ||
        (is("ca_path_fail") && key == CURLOPT_CAPATH)) return CURLE_BAD_FUNCTION_ARGUMENT;
    va_list args;
    va_start(args, key);
    if (key == CURLOPT_ALTSVC_CTRL) {
        ++alt_svc_attempts;
        const auto mask = va_arg(args, long);
        va_end(args);
        return mask ? CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;  // actual curl semantics
    }
    if (key == CURLOPT_ALTSVC) ++alt_svc_attempts;
    if (key == CURLOPT_SHARE) {
        ++share_attempts;
        (void)va_arg(args, CURLSH*);
        va_end(args);
        return CURLE_OK;
    }
    if (key == CURLOPT_HEADERFUNCTION) on_header = va_arg(args, curl_write_callback);
    else if (key == CURLOPT_WRITEFUNCTION) on_body = va_arg(args, curl_write_callback);
    else if (key == CURLOPT_HEADERDATA) header_data = va_arg(args, void*);
    else if (key == CURLOPT_WRITEDATA) body_data = va_arg(args, void*);
    else if (key == CURLOPT_HTTPHEADER) request_headers = va_arg(args, curl_slist*);
    else if (long(key) < CURLOPTTYPE_OBJECTPOINT) longs[key] = va_arg(args, long);
    else {
        const auto* value = va_arg(args, const char*);
        null_strings[key] = value == nullptr;
        strings[key] = value ? value : "";
    }
    va_end(args);
    return CURLE_OK;
}
extern "C" curl_slist* curl_slist_append(curl_slist* first, const char* value) {
    if (is("header_alloc_fail")) return nullptr;
    auto* node = new curl_slist{::strdup(value), nullptr};
    if (!first) return node;
    auto* tail = first;
    while (tail->next) tail = tail->next;
    tail->next = node;
    return first;
}
extern "C" void curl_slist_free_all(curl_slist* list) {
    while (list) { auto* next = list->next; std::free(list->data); delete list; list = next; }
}
extern "C" CURLMcode curl_multi_add_handle(CURLM*, CURL* easy) {
    ++adds; current = easy;
    if (is("inject_altsvc")) curl_easy_setopt(easy, CURLOPT_ALTSVC_CTRL, long(CURLALTSVC_H1));
    if (is("inject_altsvc_file")) curl_easy_setopt(easy, CURLOPT_ALTSVC, "/FAKE_NEVER_READ");
    if (is("inject_share")) curl_easy_setopt(easy, CURLOPT_SHARE, static_cast<CURLSH*>(nullptr));
    policy_seen = options_safe();
    return is("add_fail") || !policy_seen ? CURLM_BAD_EASY_HANDLE : CURLM_OK;
}
extern "C" CURLMcode curl_multi_perform(CURLM*, int* running) {
    ++performs; *running = 1;
    if (is("perform_fail")) return CURLM_INTERNAL_ERROR;
    if (is("pending") || is("cancel_wait") || is("poll_fail")) return CURLM_OK;
    if (phase == 0) {
        bool ok = true;
        if (is("body_before_headers")) {
            char byte = 'x';
            ok = on_body(&byte, 1, 1, body_data) == 1;
        } else {
            ok = send_header(is("redirect") ? "HTTP/1.1 302 Found\r\n" : is("http500") ? "HTTP/1.1 500 Error\r\n" : "HTTP/1.1 200 OK\r\n");
            if (ok && !is("no_length") && !is("chunked") && !is("streamed_over_cap"))
                ok = send_header(is("large_length") ? "Content-Length: 9999999999\r\n" :
                    is("negative_length") ? "Content-Length: -1\r\n" :
                    is("overflow_length") ? "Content-Length: 18446744073709551616\r\n" :
                    is("empty") ? "Content-Length: 0\r\n" :
                    is("truncated") ? "Content-Length: 3001\r\n" : "Content-Length: 3000\r\n");
            if (ok && is("duplicate_length")) ok = send_header("content-length: 3000\r\n");
            if (ok && is("gzip")) ok = send_header("Content-Encoding: gzip\r\n");
            if (ok && is("identity")) ok = send_header("Content-Encoding: identity\r\n");
            if (ok && (is("chunked") || is("ambiguous_framing"))) ok = send_header("Transfer-Encoding: chunked\r\n");
            if (ok && is("large_headers")) ok = send_header("X-Large: " + std::string(17000, 'x') + "\r\n");
            if (ok && is("folded_header")) ok = send_header(" content-length: 3000\r\n");
            if (ok && is("malformed_header")) ok = send_header("not-a-header\r\n");
            if (ok) ok = send_header("\r\n");
        }
        phase = 1;
        if (!ok) { done(CURLE_WRITE_ERROR); *running = 0; }
    } else if (phase == 1) {
        phase = 2;
        if (is("empty")) return CURLM_OK;
        std::string data(is("oversized_body") ? 3001 : 3000, 'x');
        if (is("slow_body")) std::this_thread::sleep_for(std::chrono::milliseconds(40));
        size_t n;
        if (is("body_size_overflow")) n = on_body(data.data(), size_t(-1), 2, body_data);
        else n = on_body(data.data(), 1, data.size(), body_data);
        if (n != data.size()) { done(CURLE_WRITE_ERROR); *running = 0; }
    } else {
        phase = 3;
        if (is("trailer") && !send_header("Content-Length: 3000\r\n")) done(CURLE_WRITE_ERROR);
        else done(is("tls_failure") ? CURLE_PEER_FAILED_VERIFICATION : CURLE_OK);
        *running = 0;
        if (is("missing_completion")) message_ready = false;
    }
    return CURLM_OK;
}
extern "C" CURLMcode curl_multi_poll(CURLM*, curl_waitfd*, unsigned int, int, int* fds) {
    ++polls; *fds = 0;
    if (is("poll_fail")) return CURLM_INTERNAL_ERROR;
    if (is("pending")) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    return CURLM_OK;
}
extern "C" CURLMsg* curl_multi_info_read(CURLM*, int* remaining) {
    *remaining = 0;
    if (!message_ready) return nullptr;
    message_ready = false;
    return &completed;
}
extern "C" CURLcode curl_easy_getinfo(CURL*, CURLINFO key, ...) {
    if (is("getinfo_fail")) return CURLE_BAD_FUNCTION_ARGUMENT;
    va_list args;
    va_start(args, key);
    if (key == CURLINFO_EFFECTIVE_URL) {
        auto** value = va_arg(args, char**);
        *value = const_cast<char*>(is("effective_url_changed") ? "https://PRIVATE_WRONG_ORIGIN/" : "https://qualcomm.psds.grapheneos.org/xtra3Mgrbeji.bin");
    } else {
        auto* value = va_arg(args, long*);
        *value = key == CURLINFO_RESPONSE_CODE ? (is("wrong_final_status") ? 500 : 200) :
            key == CURLINFO_REDIRECT_COUNT ? (is("redirect_count") ? 1 : 0) : (is("verify_result") ? 1 : 0);
    }
    va_end(args);
    return CURLE_OK;
}
extern "C" CURLMcode curl_multi_remove_handle(CURLM*, CURL*) {
    ++removes;
    return is("remove_fail") ? CURLM_INTERNAL_ERROR : CURLM_OK;
}
extern "C" CURLMcode curl_multi_cleanup(CURLM* multi) {
    ++multi_cleanups;
    if (is("cleanup_fail")) return CURLM_INTERNAL_ERROR;
    delete reinterpret_cast<int*>(multi);
    return CURLM_OK;
}
extern "C" void curl_easy_cleanup(CURL* easy) { ++easy_cleanups; transfer_creations = 0; delete reinterpret_cast<int*>(easy); }  // one handle per transfer
