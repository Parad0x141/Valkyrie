#pragma once

enum class ValkStatus : uint32_t
{
    OK = 0,
    ERR_DRIVER_DELETE_FAILED = 1,
    ERR_DRIVER_ALREADY_UNLOADED = 2,
    WARN_ETW_MUTE_FAILED = 3,
    ERR_NO_MEMORY = 4,
    ERR_READ_FAILED = 5,
    ERR_PATTERN_NOT_FOUND = 6,
    ERR_WRITE_FAILED = 7,
    ERR_ACCESS_DENIED = 8,
    ERR_KERNEL_ADDRESS_NOT_FOUND = 9,
    ERR_EXPORT_NOT_FOUND = 10,
    ERR_MODULE_NOT_FOUND = 11,
    ERR_HOOK_FAILED = 12,
    ERR_NOT_FOUND = 13,
    ERR_LOCK_FAILED = 14,
    ERR_RESOLVE_FAILED = 15,
    ERR_SYSGATE_MODULE_NOT_FOUND = 16,
    ERR_SYSGATE_HOOK_FAILED = 17,
    ERR_SYSGATE_HOOK_DETECTED = 18,
    ERR_SYSGATE_CALL_FAILED = 19
};


inline bool ValkSucceeded(ValkStatus e) { return e == ValkStatus::OK; }
inline bool ValkFailed(ValkStatus e) { return e != ValkStatus::OK; }