/* Diagnostic initial-config input only. Product code does not include this.
 * File operations stay on the existing setup/runtime owner. Capture the saved
 * FEC field before starting that owner; preserve that field on normal saves,
 * forwarding all other settings and current authorization data unchanged. */
#pragma once
#include "protobuf/remoteplay.pb-c.h"
#include "stream_settings.h"
#include <stdlib.h>
#include <string.h>

static int probe_fec_mode = -1; /* saved=-1, off=0, on=1 */
static bool probe_fec_original_set, probe_fec_original_has, probe_fec_original_value;
static unsigned probe_fec_loads, probe_fec_saves, probe_fec_profiles, probe_fec_io_errors;

int __real_sl_stream_settings_load(sl_stream_settings *, const char *);
int __wrap_sl_stream_settings_load(sl_stream_settings *s, const char *directory) {
    int result = __real_sl_stream_settings_load(s, directory);
    if (probe_fec_mode < 0)
        return result;
    ++probe_fec_loads;
    if (result < 0) {
        ++probe_fec_io_errors;
        return result;
    }
    if (!probe_fec_original_set) {
        probe_fec_original_has = s->config->has_enable_unreliable_fec;
        probe_fec_original_value = s->config->enable_unreliable_fec;
        probe_fec_original_set = true;
    }
    s->config->has_enable_unreliable_fec = true;
    s->config->enable_unreliable_fec = probe_fec_mode != 0;
    return result;
}
bool __real_sl_stream_settings_save(sl_stream_settings *, const char *);
bool __wrap_sl_stream_settings_save(sl_stream_settings *s, const char *directory) {
    if (probe_fec_mode < 0 || !probe_fec_original_set)
        return __real_sl_stream_settings_save(s, directory);
    protobuf_c_boolean has = s->config->has_enable_unreliable_fec;
    protobuf_c_boolean value = s->config->enable_unreliable_fec;
    s->config->has_enable_unreliable_fec = probe_fec_original_has;
    s->config->enable_unreliable_fec = probe_fec_original_value;
    bool result = __real_sl_stream_settings_save(s, directory);
    s->config->has_enable_unreliable_fec = has;
    s->config->enable_unreliable_fec = value;
    ++probe_fec_saves;
    if (!result)
        ++probe_fec_io_errors;
    return result;
}
bool __real_sl_auth_save(const sl_auth_store *, const char *);
bool __wrap_sl_auth_save(const sl_auth_store *store, const char *directory) {
    if (probe_fec_mode < 0 || !probe_fec_original_set)
        return __real_sl_auth_save(store, directory);
    /* The profile contains sixteen hosts. Do not add another full profile to
     * the runtime owner's stack on top of the normal persistence frames. */
    sl_auth_store *saved = malloc(sizeof(*saved));
    ++probe_fec_profiles;
    if (!saved) {
        ++probe_fec_io_errors;
        return false;
    }
    memcpy(saved, store, sizeof(*saved));
    saved->unreliable_fec = probe_fec_original_value;
    bool result = __real_sl_auth_save(saved, directory);
    free(saved);
    if (!result)
        ++probe_fec_io_errors;
    return result;
}
static bool probe_fec_preview(sl_auth_store *store, const char *directory) {
    sl_stream_settings settings;
    if (!sl_stream_settings_init(&settings, store))
        return false;
    /* Direct wrapper call also covers setup: preview's internal call to Load
     * lives in the same translation unit and cannot be GNU --wrap interposed. */
    int loaded = __wrap_sl_stream_settings_load(&settings, directory);
    if (loaded >= 0 && !probe_fec_original_set) {
        probe_fec_original_has = settings.config->has_enable_unreliable_fec;
        probe_fec_original_value = settings.config->enable_unreliable_fec;
        probe_fec_original_set = true;
    }
    bool result = loaded >= 0 || probe_fec_mode < 0;
    if (result)
        sl_stream_settings_project(&settings, store);
    sl_stream_settings_destroy(&settings);
    return result;
}
