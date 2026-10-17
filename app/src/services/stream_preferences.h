#pragma once
#include <stdbool.h>
#include <stdint.h>
/* View of three user controls. The full protobuf remains authoritative. */
typedef struct sl_stream_preferences {
    uint32_t quality, bitrate_kbps; /* bitrate retains the int32 wire bit pattern. */
    bool unreliable_fec;
} sl_stream_preferences;
