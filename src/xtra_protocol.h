#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace xtra::protocol {

// Native decoded LOC buffers for the reviewed vendor IDLs, not wire TLVs.
inline constexpr uint32_t kEvent = 0x29, kInject = 0xa7;
inline constexpr uint64_t kMask = 0x20;
inline constexpr size_t kEventBytes = 832, kIndicationBytes = 24, kRequestBytes = 1056;
inline constexpr unsigned kMaxPart = 1024;
inline constexpr uint64_t kKnownConstellations = 0x3f;

struct EventInfo { uint32_t max_file = 0, max_part = 0; };

inline uint64_t little(const uint8_t* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v |= uint64_t(p[i]) << (8 * i);
    return v;
}

inline void put(uint8_t* p, uint64_t v, size_t n) {
    for (size_t i = 0; i < n; ++i) p[i] = uint8_t(v >> (8 * i));
}

inline const char* decodeEvent(const std::array<uint8_t, kEventBytes>& e, EventInfo& info) {
    for (size_t off : {size_t(8), size_t(0x310), size_t(0x320), size_t(0x328), size_t(0x330)})
        if (e[off] > 1) return "invalid_event_presence";
    info.max_file = uint32_t(little(e.data(), 4));
    info.max_part = uint32_t(little(e.data() + 4, 4));
    if (e[8] && little(e.data() + 12, 4) > 3) return "invalid_server_count";
    if (!info.max_file || !info.max_part) return "zero_limits";
    if (e[0x330] != 1 || int32_t(little(e.data() + 0x334, 4)) != 1 ||
        e[0x310] != 1 || little(e.data() + 0x318, 8) != 1) return "unreviewed_event_profile";
    return nullptr;
}

// The owner validates file size, part count and part geometry before calling.
// Keep the native buffer aligned for the vendor decoder's aggregate reads.
struct alignas(8) PartRequest { std::array<uint8_t, kRequestBytes> bytes{}; };

inline PartRequest makePartRequest(size_t file_size, size_t parts, unsigned part,
                                   const uint8_t* chunk, size_t length) {
    PartRequest request;
    put(request.bytes.data(), file_size, 4);
    put(request.bytes.data() + 4, parts, 2);
    put(request.bytes.data() + 6, part, 2);
    put(request.bytes.data() + 8, length, 4);
    std::memcpy(request.bytes.data() + 12, chunk, length);
    request.bytes[0x40c] = 1;  // explicit format 0; fileInfo omitted
    return request;
}

struct PartIndication {
    uint32_t status;
    uint8_t part_present, mask_present;
    unsigned part;
    uint64_t mask;
};

inline PartIndication decodePartIndication(const std::array<uint8_t, kIndicationBytes>& r) {
    return {uint32_t(little(r.data(), 4)), r[4], r[8], unsigned(little(r.data() + 6, 2)),
            little(r.data() + 16, 8)};
}

}  // namespace xtra::protocol
