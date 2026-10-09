#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Must run before SDL/Mesa, network or background workers. */
bool sl_system_preflight(void);
bool sl_system_init(void);
bool sl_system_running(void);
void sl_system_shutdown(void);
bool sl_system_random(void *data, size_t size);
const char *sl_system_data_dir(void);
/* Font memory remains valid until shutdown; desktop returns a filename. */
const void *sl_system_font(int index, size_t *size, const char **path);
uint64_t sl_system_now(void);

/* Bounded, best-effort diagnostic output; never called on the input path. */
void sl_system_log(const char *message);

/* Obtain on the resolving worker; cancellation may be requested by its owner. */
uint32_t sl_system_dns_begin(void);
void sl_system_dns_cancel(uint32_t handle);

const char *sl_system_locale(void);

/* Platform facts and application policy, copied into IHS before session start.
 * Unknown values stay zero; no guessed hardware or OS identities. */
typedef enum sl_system_stream_form_factor {
    SL_STREAM_FORM_UNKNOWN,
    SL_STREAM_FORM_COMPUTER,
} sl_system_stream_form_factor;
typedef struct sl_system_stream_info {
    char system_info[1024];
    const char *decoder_info;
    uint32_t maximum_decode_bitrate_kbps;
    uint32_t maximum_burst_bitrate_kbps;
    bool can_suspend;
    sl_system_stream_form_factor form_factor;
} sl_system_stream_info;
sl_system_stream_info sl_system_streaming_info(void);
