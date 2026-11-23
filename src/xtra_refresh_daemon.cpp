// Resident XTRA refresh daemon (replaces /vendor/bin/xtra-daemon; started by
// loc_launcher as uid gps in vendor_location_xtra_daemon). Design: DAEMON_DESIGN.md.
//
// * One process, no child processes, no process-table scans, no JVM. Idle = blocked on a condvar woken
//   only by LOC callbacks or SIGTERM (dedicated sigwait thread): zero periodic wakeups.
// * Acts ONLY on a modem-initiated 0x29 received by its own LOC client, and injects
//   with that event's limits in the SAME session (proven r8 cycle). Never induces
//   events, never sends limits/status queries, never retries a modem request.
// * Consent = the stock switch: loc_launcher starts this only while A-GPS is on
//   (persist.sys.xtra-daemon.enabled); a change restarts loc_launcher and kills us.
// * Rate limits: >=6 h between successes, failure back-off 15 min/1 h/6 h,
//   <=4 downloads per 24 h. Never exit on transient errors (launcher would count
//   restarts and ground us); exit 0 only for permanent environment mismatch.
#if defined(XTRA_ANDROID_REFRESH_DAEMON)
#if !defined(__ANDROID__) || !defined(__aarch64__) || defined(XTRA_DAEMON_HOST_TEST) || defined(XTRA_HOST_TEST)
#error Android refresh daemon requires the actual Android arm64 target
#endif
#elif defined(XTRA_DAEMON_HOST_TEST)
#if defined(__ANDROID__) || !defined(XTRA_HOST_HTTPS_ADAPTER)
#error Daemon host tests require host HTTPS adapter selector and fake libraries
#endif
#else
#error Dedicated XTRA_ANDROID_REFRESH_DAEMON or XTRA_DAEMON_HOST_TEST selector required
#endif

#include "loc_abi.h"
#include "file_digest.h"
#include "https_download_host.h"
#include "xtra_protocol.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <vector>
#ifdef XTRA_ANDROID_REFRESH_DAEMON
#include <android/log.h>
#endif

namespace {
using Clock = std::chrono::steady_clock;
using namespace xtra::protocol;
constexpr const char* kVersion = "0.16.1-refresh-daemon";
constexpr size_t kLocalCap = 1024 * 1024;  // local resource cap, NOT a modem limit

struct Config {
    std::string library = "/vendor/lib64/libloc_api_v02.so";
    // Reviewed vendor LOC builds -> exact IDL minor its service lookup accepts
    // (LOC_LIB_20261115_ABI_REVIEW.md). Any other library: disabled, exit 0.
    std::vector<std::pair<std::string, int32_t>> libraries{
        {"aad764ce43e477cbb48f7444c17f3210cce7235ffb28d039ccd1bdf5f4db13c2", 161},
        {"9e55b90b1a0c2e31c5921d97cdf3b2a75834713596488c1bcf60371aa1a1a781", 170}};
    int32_t host_minor = 0;  // HOST fake only (empty table)
    std::string state_dir = "/data/vendor/location/peridot-xtra";
    std::string ca_path = "/system/etc/security/cacerts";
    int64_t success_gap_ms = 6LL * 3600 * 1000;
    std::array<int64_t, 3> backoff_ms{{15LL * 60 * 1000, 3600LL * 1000, 6LL * 3600 * 1000}};
    unsigned daily_cap = 4;
    int64_t day_ms = 24LL * 3600 * 1000;
    unsigned download_ms = 45000, transfer_ms = 60000, part_ms = 5000;
    int64_t reopen_min_ms = 30000, reopen_max_ms = 600000;
};

void log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void log(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
#ifdef XTRA_ANDROID_REFRESH_DAEMON
    __android_log_vprint(ANDROID_LOG_INFO, "peridot-xtra", fmt, args);
#else
    std::vfprintf(stderr, fmt, args);
    std::fputc('\n', stderr);
    std::fflush(stderr);
#endif
    va_end(args);
}
int64_t wallMs() {
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    return int64_t(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}
// ---- process-wide stop (SIGTERM/SIGINT via sigwait thread, no signal-handler work) ----
std::atomic<bool> stopping{false};
std::mutex stop_mutex;
std::condition_variable stop_cv;
std::condition_variable* session_cv = nullptr;  // current session's cv, under stop_mutex
std::mutex* session_mutex = nullptr;

void requestStop() {
    stopping = true;
    std::lock_guard<std::mutex> lock(stop_mutex);
    if (session_mutex) { std::lock_guard<std::mutex> l(*session_mutex); session_cv->notify_all(); }
    stop_cv.notify_all();
}
bool sleepInterruptible(int64_t ms) {
    std::unique_lock<std::mutex> lock(stop_mutex);
    return !stop_cv.wait_for(lock, std::chrono::milliseconds(std::max<int64_t>(ms, 0)), [] { return stopping.load(); });
}

// ---- persisted rate-limit state (root-only? no: uid gps, /data/vendor/location) ----
struct Limits {
    int64_t last_success = 0, next_allowed = 0, window_start = 0;
    unsigned failures = 0, window_count = 0;
};
class StateStore {
public:
    explicit StateStore(Config c) : cfg_(std::move(c)) {}
    Limits load(int64_t now) {
        Limits l;
        mkdir(cfg_.state_dir.c_str(), 0700);
        FILE* f = std::fopen((cfg_.state_dir + "/state").c_str(), "re");
        if (!f) return l;  // first run: no restriction
        long long a, b, c; unsigned d, e; char tail = 0;
        const int n = std::fscanf(f, "v1 %lld %lld %lld %u %u%c", &a, &b, &c, &d, &e, &tail);
        std::fclose(f);
        if (n != 6 || tail != '\n' || a < 0 || b < 0 || c < 0) {
            log("state corrupt: conservative back-off");
            l.next_allowed = now + cfg_.backoff_ms[0];
            return l;
        }
        l.last_success = a; l.next_allowed = b; l.window_start = c; l.failures = d; l.window_count = e;
        // A clock moved backwards must never shorten waits: clamp future stamps to now.
        if (l.last_success > now) l.last_success = now;
        if (l.window_start > now) l.window_start = now;
        return l;
    }
    bool save(const Limits& l) {
        const std::string path = cfg_.state_dir + "/state", tmp = path + ".tmp";
        const int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) { log("state save failed errno=%d", errno); return false; }
        char line[128];
        const int n = std::snprintf(line, sizeof(line), "v1 %lld %lld %lld %u %u\n", (long long)l.last_success,
                                    (long long)l.next_allowed, (long long)l.window_start, l.failures, l.window_count);
        const bool ok = n > 0 && write(fd, line, size_t(n)) == n && fsync(fd) == 0;
        close(fd);
        if (!ok || rename(tmp.c_str(), path.c_str())) { log("state save failed errno=%d", errno); return false; }
        return true;
    }
private:
    Config cfg_;
};
const char* deferral(const Config& cfg, Limits& l, int64_t now) {
    if (l.last_success && now >= l.last_success && now - l.last_success < cfg.success_gap_ms) return "recent_success";
    if (now < l.next_allowed) return "backoff";
    if (now - l.window_start >= cfg.day_ms || now < l.window_start) { l.window_start = now; l.window_count = 0; }
    if (l.window_count >= cfg.daily_cap) return "daily_cap";
    return nullptr;
}

// ---- one LOC client session ----
struct Session {
    std::mutex mutex;
    std::condition_variable cv;
    locClientHandleType handle = nullptr;
    bool busy = false, event_pending = false, service_lost = false;
    std::array<uint8_t, kEventBytes> event{};
    // part exchange
    bool waiting = false, received = false, unexpected = false;
    std::array<uint8_t, kIndicationBytes> indication{};
    uint64_t events_ignored = 0;
};
void eventCallback(locClientHandleType, uint32_t id, locClientEventIndUnionType payload, void* cookie) {
    if (!cookie) return;
    auto& s = *static_cast<Session*>(cookie);
    std::lock_guard<std::mutex> lock(s.mutex);
    if (id != kEvent || !payload.payload) return;
    if (s.busy || s.event_pending) { ++s.events_ignored; return; }  // never a second transfer
    std::memcpy(s.event.data(), payload.payload, kEventBytes);   // pinned event-table size
    s.event_pending = true;
    s.cv.notify_all();
}
void responseCallback(locClientHandleType handle, uint32_t id, locClientRespIndUnionType payload, uint32_t size, void* cookie) {
    if (!cookie) return;
    auto& s = *static_cast<Session*>(cookie);
    std::lock_guard<std::mutex> lock(s.mutex);
    if (!s.waiting || s.received || handle != s.handle || id != kInject || size != kIndicationBytes || !payload.payload) {
        s.unexpected = true;
    } else {
        std::memcpy(s.indication.data(), payload.payload, kIndicationBytes);
        s.received = true;
    }
    s.cv.notify_all();
}
void errorCallback(locClientHandleType, locClientErrorEnumType, void* cookie) {
    if (!cookie) return;
    auto& s = *static_cast<Session*>(cookie);
    std::lock_guard<std::mutex> lock(s.mutex);
    s.service_lost = true;
    s.cv.notify_all();
}

using Open = locClientStatusEnumType (*)(locClientEventMaskType, const locClientCallbacksType*, locClientHandleType*, const void*);
using Send = locClientStatusEnumType (*)(locClientHandleType, uint32_t, locClientReqUnionType);
using Close = locClientStatusEnumType (*)(locClientHandleType*);
using Size = bool (*)(uint32_t, size_t*);
using Service = qmi_idl_service_object* (*)(int32_t, int32_t, int32_t);
struct Loc { Open open; Send send; Close close; };

// Same strict rules as the accepted r8 transfer. Returns nullptr on reported acceptance.
const char* transfer(Session& s, const Loc& loc, const Config& cfg, const std::vector<uint8_t>& data,
                     const EventInfo& info, unsigned& acked, uint64_t& mask) {
    const unsigned chunk = std::min(kMaxPart, info.max_part);
    const size_t total = (data.size() + chunk - 1) / chunk;
    if (data.size() > info.max_file || total > 65535) return "file_exceeds_limits";
    const auto deadline = Clock::now() + std::chrono::milliseconds(cfg.transfer_ms);
    for (unsigned part = 1; part <= total; ++part) {
        const size_t offset = size_t(part - 1) * chunk, length = std::min<size_t>(chunk, data.size() - offset);
        const auto request = makePartRequest(data.size(), total, part, data.data() + offset, length);
        {
            std::lock_guard<std::mutex> lock(s.mutex);
            if (s.service_lost) return "service_lost";
            if (s.unexpected) return "unexpected_indication";
            s.waiting = true; s.received = false;
        }
        if (stopping) return "stopping";
        const auto part_deadline = std::min(deadline, Clock::now() + std::chrono::milliseconds(cfg.part_ms));
        const int status = loc.send(s.handle, kInject, locClientReqUnionType{request.bytes.data()});  // no lock held
        std::unique_lock<std::mutex> lock(s.mutex);
        if (status) { s.waiting = false; return status == 6 ? "transport_timeout" : "transport_failure"; }
        s.cv.wait_until(lock, part_deadline, [&] { return s.received || s.unexpected || s.service_lost || stopping.load(); });
        s.waiting = false;
        if (s.service_lost) return "service_lost";
        if (s.unexpected) return "unexpected_indication";
        if (stopping) return "stopping";
        if (!s.received) return "indication_timeout";
        const auto reply = decodePartIndication(s.indication);
        if (reply.status) return reply.status == 10 ? "version_check_failure" : "modem_rejection";
        if (reply.part_present != 1 || reply.mask_present > 1) return "invalid_injection_presence";
        if (reply.part != part) return "mismatched_part_number";
        if (part != total && reply.mask_present) return "premature_final_mask";
        ++acked;
        if (part == total) {
            if (reply.mask_present != 1) return "acceptance_not_confirmed";
            mask = reply.mask;
            if (!(mask & kKnownConstellations)) return "acceptance_not_confirmed";
        }
    }
    return nullptr;
}

// One event -> at most one download -> at most one transfer. Updates limits.
void cycle(Session& s, const Loc& loc, const Config& cfg, StateStore& store, Limits& limits,
           const std::array<uint8_t, kEventBytes>& event) {
    EventInfo info;
    if (const char* bad = decodeEvent(event, info)) { log("event ignored reason=%s", bad); return; }
    const int64_t now = wallMs();
    if (const char* why = deferral(cfg, limits, now)) { log("event deferred reason=%s", why); store.save(limits); return; }
    ++limits.window_count;  // stays counted in memory even when it cannot be persisted
    // Fail closed: an attempt that cannot be persisted would escape the limits after a restart.
    if (!store.save(limits)) { log("event deferred reason=state_unwritable"); return; }
    xtra::https_host::Policy policy;
    policy.event_max_file_bytes = info.max_file;
    policy.timeout_ms = cfg.download_ms;
    policy.connect_timeout_ms = std::min(10000u, cfg.download_ms);
    policy.trust = {xtra::https_host::TrustMode::CaPath, cfg.ca_path};
    auto fetched = xtra::https_host::downloadFixed(policy, [&] {
        std::lock_guard<std::mutex> lock(s.mutex);
        return !stopping.load() && !s.service_lost;
    });
    const char* error = nullptr;
    unsigned acked = 0; uint64_t mask = 0;
    if (fetched.cleanup_unknown) error = "download_cleanup_unknown";
    else if (fetched.error) error = fetched.error;
    else if (!fetched.tls_policy_configured || fetched.http_status != 200 || fetched.curl_completion_code != 0 ||
             fetched.bytes.empty() || fetched.bytes.size() > std::min<size_t>(kLocalCap, info.max_file))
        error = "invalid_download_result";
    if (!error) error = transfer(s, loc, cfg, fetched.bytes, info, acked, mask);
    const int64_t done = wallMs();
    if (!error) {
        limits.last_success = done; limits.failures = 0; limits.next_allowed = done + cfg.success_gap_ms;
        log("cycle accepted bytes=%zu sha256=%s parts=%u mask=0x%llx", fetched.bytes.size(),
            xtra::fileSha256(fetched.bytes.data(), fetched.bytes.size()).c_str(), acked, (unsigned long long)mask);
    } else if (std::strcmp(error, "stopping")) {
        limits.failures = std::min(limits.failures + 1, 100u);
        limits.next_allowed = done + cfg.backoff_ms[std::min<size_t>(limits.failures - 1, cfg.backoff_ms.size() - 1)];
        log("cycle failed reason=%s http=%ld bytes=%zu acked=%u", error, fetched.http_status, fetched.bytes.size(), acked);
    }
    store.save(limits);
}

// Exact IDL minor for a reviewed library, or 0 for any other/unreadable file.
int32_t libraryMinor(const Config& cfg) {
    if (cfg.libraries.empty()) return cfg.host_minor;
    const int fd = open(cfg.library.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    std::vector<uint8_t> bytes;
    uint8_t buffer[65536];
    for (ssize_t n; (n = read(fd, buffer, sizeof(buffer))) != 0;) {
        if (n < 0) { if (errno == EINTR) continue; close(fd); return 0; }
        bytes.insert(bytes.end(), buffer, buffer + n);
        if (bytes.size() > 16 * 1024 * 1024) { close(fd); return 0; }
    }
    close(fd);
    const std::string sha = xtra::fileSha256(bytes.data(), bytes.size());
    for (const auto& known : cfg.libraries)
        if (known.first == sha) return known.second;
    return 0;
}

int run(const Config& cfg) {
    // Block termination signals in every thread (incl. vendor LOC threads created later);
    // a dedicated thread converts them into an orderly stop without async-unsafe work.
    sigset_t set;
    sigemptyset(&set); sigaddset(&set, SIGTERM); sigaddset(&set, SIGINT); sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
    std::signal(SIGPIPE, SIG_IGN);
    std::thread([set] { int sig = 0; sigwait(&set, &sig); requestStop(); }).detach();

    log("start version=%s", kVersion);
    // An updated vendor LOC library may change the reconstructed ABI: refuse permanently.
    // Exit 0 = loc_launcher does not restart us (no restart storm, no grounding).
    const int32_t minor = libraryMinor(cfg);
    if (!minor) { log("vendor LOC library hash mismatch: disabled"); return 0; }
    log("vendor LOC library reviewed idl_minor=%d", minor);
    void* so = dlopen(cfg.library.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!so) { log("vendor LOC library load failed: disabled"); return 0; }
#ifdef XTRA_DAEMON_HOST_TEST
    using Fake = uint32_t (*)();
    const auto fake = reinterpret_cast<Fake>(dlsym(so, "xtraFakeLocOnly"));
    if (!fake || fake() != 0x58545241) { log("fake LOC required"); return 0; }
#endif
    Loc loc{reinterpret_cast<Open>(dlsym(so, "locClientOpen")), reinterpret_cast<Send>(dlsym(so, "locClientSendReq")),
            reinterpret_cast<Close>(dlsym(so, "locClientClose"))};
    const auto size = reinterpret_cast<Size>(dlsym(so, "locClientGetSizeByRespIndId"));
    const auto service = reinterpret_cast<Service>(dlsym(so, "loc_get_service_object_internal_v02"));
    size_t inject_size = 0;
    if (!loc.open || !loc.send || !loc.close || !size || !service || !service(2, minor, 6) ||
        !size(kInject, &inject_size) || inject_size != kIndicationBytes) { log("unsupported LOC layout: disabled"); return 0; }

    StateStore store(cfg);
    Limits limits = store.load(wallMs());
    int64_t reopen_ms = cfg.reopen_min_ms;
    const locClientCallbacksType callbacks{sizeof(callbacks), eventCallback, responseCallback, errorCallback};
    while (!stopping) {
        // Session objects are never freed: provider callbacks may outlive a failed close.
        auto* s = new Session;
        {
            std::lock_guard<std::mutex> lock(stop_mutex);
            session_mutex = &s->mutex; session_cv = &s->cv;
        }
        locClientHandleType handle = nullptr;
        const int opened = loc.open(kMask, &callbacks, &handle, s);
        if (opened || !handle) {
            log("LOC open failed status=%d; retry in %llds", opened, (long long)(reopen_ms / 1000));
            if (!sleepInterruptible(reopen_ms)) break;
            reopen_ms = std::min(reopen_ms * 2, cfg.reopen_max_ms);
            continue;
        }
        { std::lock_guard<std::mutex> lock(s->mutex); s->handle = handle; }
        log("LOC client open mask=0x20; waiting for modem XTRA requests");
        bool lost = false;
        while (!stopping && !lost) {
            std::array<uint8_t, kEventBytes> event{};
            {
                std::unique_lock<std::mutex> lock(s->mutex);
                s->cv.wait(lock, [&] { return stopping.load() || s->service_lost || s->event_pending; });
                if (stopping) break;
                if (s->service_lost) { lost = true; break; }
                event = s->event; s->event_pending = false; s->busy = true; s->unexpected = false;
            }
            log("modem XTRA request received");
            cycle(*s, loc, cfg, store, limits, event);
            std::lock_guard<std::mutex> lock(s->mutex);
            s->busy = false;
            lost = s->service_lost;
        }
        const int closed = loc.close(&handle);
        if (closed || handle) log("LOC close failed status=%d", closed);
        if (stopping) break;
        log("LOC service lost; reopen in %llds", (long long)(reopen_ms / 1000));
        if (!sleepInterruptible(reopen_ms)) break;
        reopen_ms = std::min(reopen_ms * 2, cfg.reopen_max_ms);
    }
    log("stop");
    return 0;
}
}  // namespace

#ifdef XTRA_DAEMON_HOST_TEST
extern void fakeCurlConfigure(const char*);
int main(int argc, char** argv) {
    // HOST fake-only harness: library, state dir [, IDL minor]; compressed time profile.
    if (argc != 3 && argc != 4) return 2;
    fakeCurlConfigure(getenv("MOCK_CURL_MODE") ? getenv("MOCK_CURL_MODE") : "success");
    Config cfg;
    cfg.library = argv[1]; cfg.libraries.clear(); cfg.host_minor = argc == 4 ? std::atoi(argv[3]) : 161; cfg.state_dir = argv[2]; cfg.ca_path = "/fake/cacerts";
    cfg.success_gap_ms = 1500; cfg.backoff_ms = {{400, 800, 1200}}; cfg.daily_cap = 3; cfg.day_ms = 6000;
    cfg.download_ms = 1000; cfg.transfer_ms = 2000; cfg.part_ms = 400; cfg.reopen_min_ms = 200; cfg.reopen_max_ms = 400;
    return run(cfg);
}
#else
int main(int, char**) {
    // Arguments are never parsed: izat.conf PROCESS_ARGUMENT is empty, and the launcher
    // may still pass an empty token. No flag can change paths, limits or the endpoint.
    return run(Config{});
}
#endif
