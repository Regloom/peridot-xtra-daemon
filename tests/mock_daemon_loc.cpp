// HOST fake LOC for the resident daemon. No modem, network or vendor library access.
// MOCK_DAEMON_SCRIPT: comma list "event@MS" / "loss@MS" (ms since library load),
// delivered to whichever client is open at that moment (dropped if none).
// MOCK_DAEMON_ACK: success | reject2 | nomask | silent ; MOCK_OPEN_FAIL: N first opens fail.
// MOCK_EVENT_PROFILE: xtra | navic | mask2 ; MOCK_DAEMON_TRACE: append-only text trace.
// MOCK_IDL_MINOR: the only service minor the fake lookup accepts (default 161).
#include "loc_abi.h"
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
const auto loaded = Clock::now();
std::mutex mutex;
locClientCallbacksType callbacks{};
void* cookie = nullptr;
int storage;
bool open_now = false;
unsigned opens = 0;
bool scheduler_started = false;

std::string env(const char* name, const char* fallback) { const char* v = std::getenv(name); return v ? v : fallback; }
void trace(const std::string& line) {
    const char* path = std::getenv("MOCK_DAEMON_TRACE");
    if (!path) return;
    if (FILE* f = std::fopen(path, "a")) { std::fprintf(f, "%s\n", line.c_str()); std::fclose(f); }
}
void put(uint8_t* p, uint64_t v, size_t n) { for (size_t i = 0; i < n; ++i) p[i] = uint8_t(v >> (8 * i)); }
uint64_t get(const uint8_t* p, size_t n) { uint64_t v = 0; for (size_t i = 0; i < n; ++i) v |= uint64_t(p[i]) << (8 * i); return v; }

void deliverEvent() {
    std::array<uint8_t, 832> e{};
    put(e.data(), std::strtoul(env("MOCK_MAX_FILE", "133120").c_str(), nullptr, 10), 4);
    put(e.data() + 4, std::strtoul(env("MOCK_MAX_PART", "10240").c_str(), nullptr, 10), 4);
    e[8] = 1; put(e.data() + 12, 3, 4);
    std::memcpy(e.data() + 16, "PRIVATE_SERVER_URL", 18);
    const std::string profile = env("MOCK_EVENT_PROFILE", "xtra");
    e[0x310] = 1; put(e.data() + 0x318, profile == "mask2" ? 2 : 1, 8);
    e[0x330] = 1; put(e.data() + 0x334, profile == "navic" ? 2 : 1, 4); put(e.data() + 0x338, 72, 4);
    locClientCallbacksType cb; void* c;
    { std::lock_guard<std::mutex> lock(mutex); if (!open_now) { trace("event dropped(no client)"); return; } cb = callbacks; c = cookie; }
    trace("event");
    cb.eventIndCb(&storage, 0x29, locClientEventIndUnionType{e.data()}, c);
    e.fill(0xff);  // transient provider buffer
}
void deliverLoss() {
    locClientCallbacksType cb; void* c;
    { std::lock_guard<std::mutex> lock(mutex); if (!open_now) return; cb = callbacks; c = cookie; }
    trace("loss");
    cb.errorCb(&storage, eLOC_CLIENT_ERROR_SERVICE_UNAVAILABLE, c);
}
void runScript() {
    const std::string script = env("MOCK_DAEMON_SCRIPT", "");
    size_t pos = 0;
    while (pos < script.size()) {
        const size_t end = std::min(script.find(',', pos), script.size());
        const std::string item = script.substr(pos, end - pos);
        pos = end + 1;
        const auto at = item.find('@');
        if (at == std::string::npos) continue;
        std::this_thread::sleep_until(loaded + std::chrono::milliseconds(std::stol(item.substr(at + 1))));
        if (item.compare(0, at, "event") == 0) deliverEvent();
        else if (item.compare(0, at, "loss") == 0) deliverLoss();
    }
}
}  // namespace

extern "C" uint32_t xtraFakeLocOnly() { return 0x58545241; }
extern "C" qmi_idl_service_object* loc_get_service_object_internal_v02(int32_t a, int32_t b, int32_t c) {
    const int32_t minor = int32_t(std::strtol(env("MOCK_IDL_MINOR", "161").c_str(), nullptr, 10));
    return a == 2 && b == minor && c == 6 ? reinterpret_cast<qmi_idl_service_object*>(&storage) : nullptr;
}
extern "C" bool locClientGetSizeByRespIndId(uint32_t id, size_t* n) { *n = 24; return id == 0xa7; }
extern "C" locClientStatusEnumType locClientOpen(locClientEventMaskType mask, const locClientCallbacksType* cb,
                                                 locClientHandleType* handle, const void* data) {
    std::lock_guard<std::mutex> lock(mutex);
    ++opens;
    trace("open mask=" + std::to_string(mask));
    if (mask != 0x20 || cb->size != 32 || !cb->eventIndCb || !cb->respIndCb || !cb->errorCb)
        return eLOC_CLIENT_FAILURE_INVALID_PARAMETER;
    if (opens <= std::strtoul(env("MOCK_OPEN_FAIL", "0").c_str(), nullptr, 10)) return eLOC_CLIENT_FAILURE_SERVICE_NOT_PRESENT;
    callbacks = *cb; cookie = const_cast<void*>(data); *handle = &storage; open_now = true;
    if (!scheduler_started) { scheduler_started = true; std::thread(runScript).detach(); }
    return eLOC_CLIENT_SUCCESS;
}
extern "C" locClientStatusEnumType locClientSendReq(locClientHandleType handle, uint32_t id, locClientReqUnionType request) {
    if (handle != &storage || id != 0xa7 || !request.payload) {
        trace("send REJECTED id=" + std::to_string(id));
        return eLOC_CLIENT_FAILURE_INVALID_MESSAGE_ID;
    }
    const auto* p = static_cast<const uint8_t*>(request.payload);
    const unsigned part = unsigned(get(p + 6, 2)), total = unsigned(get(p + 4, 2)), length = unsigned(get(p + 8, 4));
    trace("send part=" + std::to_string(part) + "/" + std::to_string(total) + " len=" + std::to_string(length) +
          " size=" + std::to_string(get(p, 4)) + " format=" + std::to_string(p[0x40c]) + " fileinfo=" + std::to_string(p[0x414]));
    const std::string ack = env("MOCK_DAEMON_ACK", "success");
    if (ack == "silent") return eLOC_CLIENT_SUCCESS;
    std::array<uint8_t, 24> r{};
    put(r.data(), ack == "reject2" && part == 2 ? 10 : 0, 4);
    r[4] = 1; put(r.data() + 6, part, 2);
    if (part == total && ack != "nomask") { r[8] = 1; put(r.data() + 16, 0x3f, 8); }
    locClientCallbacksType cb; void* c;
    { std::lock_guard<std::mutex> lock(mutex); cb = callbacks; c = cookie; }
    cb.respIndCb(&storage, 0xa7, locClientRespIndUnionType{r.data()}, 24, c);
    r.fill(0xff);
    return eLOC_CLIENT_SUCCESS;
}
extern "C" locClientStatusEnumType locClientClose(locClientHandleType* handle) {
    std::lock_guard<std::mutex> lock(mutex);
    trace("close");
    open_now = false;
    *handle = nullptr;
    return eLOC_CLIENT_SUCCESS;
}
