#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Local resource bound, not a Steam protocol maximum. */
#define SL_REMOTE_FRAME_MAX 65536
typedef struct sl_proto_reader {
    const uint8_t *data;
    size_t size, offset;
    bool invalid;
} sl_proto_reader;
typedef struct sl_proto_field {
    uint32_t number;
    unsigned wire;
    uint64_t value;
    const uint8_t *bytes;
    size_t size;
} sl_proto_field;
typedef struct sl_proto_writer {
    uint8_t *data;
    size_t size, capacity;
    bool invalid;
} sl_proto_writer;
bool sl_proto_next(sl_proto_reader *, sl_proto_field *);
bool sl_proto_done(const sl_proto_reader *);
void sl_proto_uint(sl_proto_writer *, unsigned number, uint64_t);
void sl_proto_fixed64(sl_proto_writer *, unsigned number, uint64_t);
void sl_proto_bytes(sl_proto_writer *, unsigned number, const void *, size_t);

/* RFC 6455: a server stream is unmasked; client frames MUST be masked.
 * Decode consumes one complete frame; 0=need more, -1=malformed, 1=frame.
 * Fragment assembly and interleaved control frames belong to the caller. */
typedef struct sl_ws_frame {
    unsigned opcode;
    bool final;
    const uint8_t *payload;
    size_t size, consumed;
} sl_ws_frame;
int sl_ws_decode(const uint8_t *, size_t, sl_ws_frame *);
size_t sl_ws_encode(uint8_t *, size_t, unsigned opcode, const void *, size_t,
                    const uint8_t mask[4]);
bool sl_ws_accept(const char *key, char out[29]);
/* Validates status, Upgrade, Connection and exactly one matching accept header. */
bool sl_ws_upgrade_valid(const uint8_t *, size_t, const char *expected_accept);
