#pragma once
#include <cstdint>
namespace nsl {
/* Original BeginFetch/Completed/Failed; NETWORKING section 15. The platform
 * owns HTTP and validation. Available configuration survives refresh failure. */
struct SnsConfigFetchPolicy {
    enum Action { None, Retry, Refresh };
    int state = 1;
    uint32_t completed = 0;
    bool available = false, active = false;
    bool begin(bool force = false) {
        if (active || (available && !force)) return false;
        active = true;
        if (!available) state = state < 0 ? -10 : 3;
        return true;
    }
    bool alternate_realm() const {
        return completed > 1 && completed < 0x80000000u && !(completed & 1);
    }
    Action complete(bool accepted) {
        active = false;
        ++completed;
        if (accepted) {
            available = true; state = 100;
            return completed == 1 ? Refresh : None;
        }
        // Original CMP/B.GT treats the wrapping 32-bit count as signed.
        if (completed <= 2 || completed >= 0x80000000u) return Retry;
        if (!available) state = -101;
        return None;
    }
    // Local HTTP allocation/start failure, outside the original factory provider.
    void cannot_start() {
        active = false;
        if (!available) state = -101;
    }
};
}
