#pragma once

#include <cstddef>
#include <cstdint>

// Minimal reconstructed ABI, not a drop-in Qualcomm header. Keep these typedefs
// global: the shipped library's cross-DSO CFI names include the union/enum names.
// Android-build callback type IDs statically match the vendor checks.
// Actual linker/CFI behavior on the device remains UNVERIFIED.
typedef void* locClientHandleType;
typedef uint64_t locClientEventMaskType;
typedef enum {
    eLOC_CLIENT_SUCCESS = 0,
    eLOC_CLIENT_FAILURE_GENERAL = 1,
    eLOC_CLIENT_FAILURE_UNSUPPORTED = 2,
    eLOC_CLIENT_FAILURE_INVALID_PARAMETER = 3,
    eLOC_CLIENT_FAILURE_ENGINE_BUSY = 4,
    eLOC_CLIENT_FAILURE_PHONE_OFFLINE = 5,
    eLOC_CLIENT_FAILURE_TIMEOUT = 6,
    eLOC_CLIENT_FAILURE_SERVICE_NOT_PRESENT = 7,
    eLOC_CLIENT_FAILURE_SERVICE_VERSION_UNSUPPORTED = 8,
    eLOC_CLIENT_FAILURE_CLIENT_VERSION_UNSUPPORTED = 9,
    eLOC_CLIENT_FAILURE_INVALID_HANDLE = 10,
    eLOC_CLIENT_FAILURE_INTERNAL = 11,
    eLOC_CLIENT_FAILURE_NOT_INITIALIZED = 12,
    eLOC_CLIENT_FAILURE_NOT_ENOUGH_MEMORY = 13,
    eLOC_CLIENT_FAILURE_INVALID_MESSAGE_ID = 14
} locClientStatusEnumType;
struct qmi_idl_service_object;
typedef enum { eLOC_CLIENT_ERROR_SERVICE_UNAVAILABLE = 1 } locClientErrorEnumType;
typedef union { const void* payload; } locClientEventIndUnionType;
typedef union { const void* payload; } locClientRespIndUnionType;
typedef union { const void* payload; } locClientReqUnionType;

typedef void (*locClientEventIndCbType)(locClientHandleType, uint32_t,
                                      locClientEventIndUnionType, void*);
typedef void (*locClientRespIndCbType)(locClientHandleType, uint32_t,
                                     locClientRespIndUnionType, uint32_t, void*);
typedef void (*locClientErrorCbType)(locClientHandleType, locClientErrorEnumType, void*);
typedef struct {
    uint32_t size;
    locClientEventIndCbType eventIndCb;
    locClientRespIndCbType respIndCb;
    locClientErrorCbType errorCb;
} locClientCallbacksType;

// Exported synchronous 0x1E helper. Its pointee type mangles to
// _ZTSF23locClientStatusEnumTypePvPKjjPmE, whose cross-DSO CFI ID
// 0xf96478a4b3d5e645 is accepted for this target by the pinned vendor __cfi_check.
typedef locClientStatusEnumType (*locClientSupportMsgCheckType)(
    locClientHandleType, const uint32_t*, uint32_t, uint64_t*);

static_assert(sizeof(void*) == 8, "Only the recovered 64-bit ABI is supported");
static_assert(sizeof(locClientCallbacksType) == 32);
static_assert(offsetof(locClientCallbacksType, respIndCb) == 16);
static_assert(sizeof(locClientReqUnionType) == 8);
static_assert(sizeof(locClientErrorEnumType) == 4);
static_assert(sizeof(locClientStatusEnumType) == 4);

namespace xtra {
constexpr uint32_t kQuery = 0xb0;
constexpr size_t kResponseBytes = 0x670;
// Configuration=0, version omitted. Candidate only, not proven side-effect-free.
struct Query {
    uint32_t configuration = 0;
    uint8_t version_present = 0;
    uint8_t major = 0;
    uint8_t minor = 0;
    uint8_t padding = 0;
};
static_assert(sizeof(Query) == 8);
static_assert(offsetof(Query, version_present) == 4);
}  // namespace xtra
