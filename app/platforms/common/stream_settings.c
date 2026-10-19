/* Official main: file load 0x7a5a50, save 0x7a5b34; shell UI saves only.
 * File I/O and protobuf storage are kept off rendering/input/session workers. */
#include "stream_settings.h"
#include "protobuf/remoteplay.pb-c.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { EDIT_QUALITY = 1, EDIT_BITRATE = 2, EDIT_FEC = 4 };
static sl_stream_preferences preferences(const sl_auth_store *view) {
    return (sl_stream_preferences){view->quality, view->bitrate_kbps, view->unreliable_fec};
}
static uint8_t *pack(const CStreamingClientConfig *config, size_t *size) {
    *size = cstreaming_client_config__get_packed_size(config);
    uint8_t *bytes = malloc(*size ? *size : 1);
    if (bytes)
        cstreaming_client_config__pack(config, bytes);
    return bytes;
}
static bool replace(sl_stream_settings *s, const uint8_t *wire, size_t size) {
    CStreamingClientConfig *config = cstreaming_client_config__unpack(NULL, size, wire);
    if (!config)
        return false;
    if (s->config)
        cstreaming_client_config__free_unpacked(s->config, NULL);
    s->config = config;
    return true;
}
bool sl_stream_settings_init(sl_stream_settings *s, const sl_auth_store *legacy) {
    memset(s, 0, sizeof(*s));
    if (pthread_mutex_init(&s->lock, NULL))
        return false;
    atomic_init(&s->published_revision, 0);
    if (!replace(s, NULL, 0)) {
        pthread_mutex_destroy(&s->lock);
        return false;
    }
    s->previous_ui = preferences(legacy);
    s->config->has_quality = true;
    s->config->quality = legacy->quality == 1   ? k_EStreamQualityFast
                         : legacy->quality == 2 ? k_EStreamQualityBeautiful
                                                : k_EStreamQualityBalanced;
    s->config->has_desired_bitrate_kbps = true;
    s->config->desired_bitrate_kbps = (int32_t)legacy->bitrate_kbps;
    if (legacy->unreliable_fec) {
        s->config->has_enable_unreliable_fec = true;
        s->config->enable_unreliable_fec = true;
    }
    s->dirty = true; /* One-time migration when the full file is absent. */
    return true;
}
void sl_stream_settings_destroy(sl_stream_settings *s) {
    free(s->pending);
    cstreaming_client_config__free_unpacked(s->config, NULL);
    pthread_mutex_destroy(&s->lock);
    memset(s, 0, sizeof(*s));
}
static bool paths(const char *dir, char *path, char *tmp, char *backup) {
    return snprintf(path, 512, "%s/streaming_settings.bin", dir) < 512 &&
           snprintf(tmp, 512, "%s/streaming_settings.tmp", dir) < 512 &&
           snprintf(backup, 512, "%s/streaming_settings.bak", dir) < 512;
}
int sl_stream_settings_load(sl_stream_settings *s, const char *directory) {
    char path[512], tmp[512], backup[512];
    if (!paths(directory, path, tmp, backup)) {
        s->dirty = false;
        return -1;
    }
    FILE *file = fopen(path, "rb");
    bool recover = false;
    if (!file && errno == ENOENT) {
        file = fopen(backup, "rb");
        recover = file != NULL;
    }
    if (!file) {
        if (errno == ENOENT)
            return 1;
        s->dirty = false;
        return -1;
    }
    int result = -1;
    CStreamingClientConfig *candidate = NULL;
    if (!fseek(file, 0, SEEK_END)) {
        long length = ftell(file);
        if (length >= 0 && (uintmax_t)length < SIZE_MAX && !fseek(file, 0, SEEK_SET)) {
            uint8_t *bytes = malloc((size_t)length + 1);
            if (bytes) {
                if (fread(bytes, 1, (size_t)length, file) == (size_t)length && fgetc(file) == EOF &&
                    !ferror(file)) {
                    candidate = cstreaming_client_config__unpack(NULL, (size_t)length, bytes);
                    result = candidate ? 0 : -2;
                }
                free(bytes);
            }
        }
    }
    if (fclose(file))
        result = -1;
    if (result == 0 && recover && rename(backup, path))
        result = -1;
    /* Unlike the original in-place failed parser, never adopt a partial value.
     * Do not overwrite a malformed/unreadable existing file on startup. */
    if (result == 0) {
        cstreaming_client_config__free_unpacked(s->config, NULL);
        s->config = candidate;
    } else if (candidate)
        cstreaming_client_config__free_unpacked(candidate, NULL);
    s->dirty = false;
    return result;
}
static bool publish_file(const char *tmp, const char *path, const char *backup) {
    if (!rename(tmp, path))
        return true;
    if (errno != EEXIST && errno != ENOTEMPTY)
        return false;
    if (remove(backup) && errno != ENOENT)
        return false;
    if (rename(path, backup))
        return false;
    if (!rename(tmp, path)) {
        remove(backup);
        return true;
    }
    int saved = errno;
    rename(backup, path);
    errno = saved;
    return false;
}
bool sl_stream_settings_save(sl_stream_settings *s, const char *directory) {
    char path[512], tmp[512], backup[512];
    if (!paths(directory, path, tmp, backup))
        return false;
    if (mkdir(directory, 0700) && errno != EEXIST)
        return false;
    size_t size;
    uint8_t *bytes = pack(s->config, &size);
    if (!bytes)
        return false;
    FILE *file = fopen(tmp, "wb");
    if (!file) {
        free(bytes);
        return false;
    }
    bool ok = fwrite(bytes, 1, size, file) == size;
    free(bytes);
    if (fflush(file))
        ok = false;
    if (ok && fsync(fileno(file)) && errno != ENOSYS && errno != EINVAL)
        ok = false;
    if (fclose(file))
        ok = false;
    if (ok)
        ok = publish_file(tmp, path, backup);
    if (ok)
        s->dirty = false;
    else
        remove(tmp);
    return ok;
}
void sl_stream_settings_project(const sl_stream_settings *s, sl_auth_store *view) {
    view->quality = s->config->quality == k_EStreamQualityFast        ? 1
                    : s->config->quality == k_EStreamQualityBeautiful ? 2
                                                                      : 0;
    view->bitrate_kbps = (uint32_t)s->config->desired_bitrate_kbps;
    view->unreliable_fec = s->config->enable_unreliable_fec;
}
void sl_stream_settings_preview(sl_auth_store *view, const char *directory) {
    sl_stream_settings settings;
    if (!sl_stream_settings_init(&settings, view))
        return;
    sl_stream_settings_load(&settings, directory);
    sl_stream_settings_project(&settings, view);
    sl_stream_settings_destroy(&settings);
}
void sl_stream_settings_receive(IHS_Session *session, const uint8_t *wire, size_t size, void *ctx) {
    (void)session;
    sl_stream_settings *s = ctx;
    if (!s || (!wire && size))
        return;
    uint8_t *copy = malloc(size ? size : 1);
    if (!copy)
        return;
    if (size)
        memcpy(copy, wire, size);
    pthread_mutex_lock(&s->lock);
    uint8_t *old = s->pending;
    s->pending = copy;
    s->pending_size = size;
    s->config_order = ++s->sequence;
    atomic_store(&s->published_revision, s->sequence);
    pthread_mutex_unlock(&s->lock);
    free(old);
}
void sl_stream_settings_note_ui(sl_stream_settings *s, const sl_auth_store *view) {
    sl_stream_preferences now = preferences(view);
    pthread_mutex_lock(&s->lock);
    unsigned mask = (now.quality != s->previous_ui.quality ? EDIT_QUALITY : 0) |
                    (now.bitrate_kbps != s->previous_ui.bitrate_kbps ? EDIT_BITRATE : 0) |
                    (now.unreliable_fec != s->previous_ui.unreliable_fec ? EDIT_FEC : 0);
    s->previous_ui = now;
    if (mask) {
        s->edit = now;
        s->edit_mask |= mask;
        uint64_t order = ++s->sequence;
        s->ui_revision = order;
        atomic_store(&s->published_revision, s->sequence);
        for (unsigned i = 0; i < 3; ++i)
            if (mask & (1u << i))
                s->edit_order[i] = order;
    }
    pthread_mutex_unlock(&s->lock);
}
static bool edit_preferences(sl_stream_settings *s, unsigned mask, sl_stream_preferences prefs) {
    bool changed = false;
    EStreamQualityPreference quality = prefs.quality == 1   ? k_EStreamQualityFast
                                       : prefs.quality == 2 ? k_EStreamQualityBeautiful
                                                            : k_EStreamQualityBalanced;
    if ((mask & EDIT_QUALITY) && s->config->quality != quality) {
        s->config->quality = quality;
        s->config->has_quality = true;
        changed = true;
    }
    if ((mask & EDIT_BITRATE) && s->config->desired_bitrate_kbps != (int32_t)prefs.bitrate_kbps) {
        s->config->desired_bitrate_kbps = (int32_t)prefs.bitrate_kbps;
        s->config->has_desired_bitrate_kbps = true;
        changed = true;
    }
    if ((mask & EDIT_FEC) && s->config->enable_unreliable_fec != prefs.unreliable_fec) {
        s->config->enable_unreliable_fec = prefs.unreliable_fec;
        s->config->has_enable_unreliable_fec = true;
        changed = true;
    }
    return changed;
}
bool sl_stream_settings_drain(sl_stream_settings *s) {
    pthread_mutex_lock(&s->lock);
    uint8_t *wire = s->pending;
    size_t size = s->pending_size;
    uint64_t config_order = s->config_order;
    unsigned before = 0, after = 0, mask = s->edit_mask;
    sl_stream_preferences prefs = s->edit;
    for (unsigned i = 0; i < 3; ++i)
        if (mask & (1u << i)) {
            if (wire && (int64_t)(s->edit_order[i] - config_order) > 0)
                after |= 1u << i;
            else
                before |= 1u << i;
        }
    s->pending = NULL;
    s->pending_size = 0;
    s->edit_mask = 0;
    s->applied_revision = s->sequence;
    pthread_mutex_unlock(&s->lock);
    bool changed = edit_preferences(s, before, prefs);
    if (wire) {
        changed = replace(s, wire, size) || changed;
        free(wire);
    }
    changed = edit_preferences(s, after, prefs) || changed;
    s->dirty = s->dirty || changed;
    return changed;
}
bool sl_stream_settings_apply(const sl_stream_settings *s, IHS_Session *session) {
    size_t size;
    uint8_t *wire = pack(s->config, &size);
    if (!wire)
        return false;
    bool ok = IHS_SessionSetStreamingClientConfig(session, wire, size, true);
    free(wire);
    return ok;
}

uint64_t sl_stream_settings_revision(const sl_stream_settings *s) {
    return atomic_load(&s->published_revision);
}

void sl_stream_settings_ack_ui(sl_stream_settings *s, const sl_stream_preferences *view,
                               uint64_t revision) {
    pthread_mutex_lock(&s->lock);
    if (revision >= s->ui_revision) {
        s->previous_ui = *view;
        s->ui_revision = revision;
    }
    pthread_mutex_unlock(&s->lock);
}

bool sl_stream_settings_apply_limited(const sl_stream_settings *s, IHS_Session *session,
                                      const sl_stream_request_limits *limits) {
    size_t size;
    uint8_t *wire = pack(s->config, &size);
    if (!wire)
        return false;
    CStreamingClientConfig *request = cstreaming_client_config__unpack(NULL, size, wire);
    free(wire);
    if (!request)
        return false;
    if (limits->width && (limits->force_resolution || !request->desired_resolution_x ||
                          request->desired_resolution_x > limits->width)) {
        request->has_desired_resolution_x = true;
        request->desired_resolution_x = limits->width;
    }
    if (limits->height && (limits->force_resolution || !request->desired_resolution_y ||
                           request->desired_resolution_y > limits->height)) {
        request->has_desired_resolution_y = true;
        request->desired_resolution_y = limits->height;
    }
    if (limits->fps &&
        (!request->desired_framerate_numerator || !request->desired_framerate_denominator ||
         (uint64_t)request->desired_framerate_numerator >
             (uint64_t)request->desired_framerate_denominator * limits->fps)) {
        request->has_desired_framerate_numerator = request->has_desired_framerate_denominator =
            true;
        request->desired_framerate_numerator = limits->fps;
        request->desired_framerate_denominator = 1;
    }
    if (!limits->hevc && request->enable_video_hevc) {
        request->has_enable_video_hevc = true;
        request->enable_video_hevc = false;
    }
    wire = pack(request, &size);
    cstreaming_client_config__free_unpacked(request, NULL);
    if (!wire)
        return false;
    bool ok = IHS_SessionSetStreamingClientConfig(session, wire, size, true);
    free(wire);
    return ok;
}

bool sl_stream_settings_preset(sl_stream_settings *s, sl_stream_preset preset) {
    if (!s || !s->config || preset < SL_PRESET_KEEP || preset > SL_PRESET_FAST)
        return false;
    if (preset == SL_PRESET_KEEP)
        return true;
    CStreamingClientConfig value = CSTREAMING_CLIENT_CONFIG__INIT;
    const CStreamingClientConfig *old = s->config;
    /* Original helper c85868 retains presence as well as the field value.
     * Do not copy the rest of the proto/unknowns into a factory that clears it. */
#define KEEP(field)                                                                                \
    do {                                                                                           \
        value.has_##field = old->has_##field;                                                      \
        memcpy(&value.field, &old->field, sizeof(value.field));                                    \
    } while (0)
    KEEP(enable_hardware_decoding);
    KEEP(enable_performance_overlay);
    KEEP(enable_video_streaming);
    KEEP(enable_audio_streaming);
    KEEP(enable_input_streaming);
    KEEP(audio_channels);
    KEEP(enable_performance_icons);
    KEEP(enable_microphone_streaming);
    KEEP(p2p_scope);
    KEEP(enable_audio_uncompressed);
    KEEP(enable_video_av1);
    KEEP(windowed);
    KEEP(window_pixel_density);
    KEEP(window_width);
    KEEP(window_height);
    KEEP(window_position_x);
    KEEP(window_position_y);
    KEEP(window_frame_offset_x);
    KEEP(window_frame_offset_y);
#undef KEEP
    value.controller_overlay_hotkey = old->controller_overlay_hotkey;
    CStreamVideoLimit quality = CSTREAM_VIDEO_LIMIT__INIT;
    CStreamVideoMode mode = CSTREAM_VIDEO_MODE__INIT;
    if (preset != SL_PRESET_DEFAULT) {
        value.has_quality = true;
        value.quality = preset == SL_PRESET_FAST ? k_EStreamQualityFast : k_EStreamQualityBeautiful;
        value.has_enable_video_hevc = value.has_enable_unreliable_fec = true;
        value.enable_video_hevc = value.enable_unreliable_fec = true;
        if (preset != SL_PRESET_FAST) {
            value.has_desired_bitrate_kbps = true;
            value.desired_bitrate_kbps = 0;
            mode.width = preset == SL_PRESET_ENHANCED_4K ? 3840 : 1920;
            mode.height = preset == SL_PRESET_ENHANCED_4K ? 2160 : 1080;
            quality.mode = &mode;
            value.quality_limit = &quality;
        }
    }
    size_t size;
    uint8_t *wire = pack(&value, &size);
    if (!wire)
        return false;
    bool ok = replace(s, wire, size); /* Deep-copy before retiring old hotkey. */
    free(wire);
    if (!ok)
        return false;
    s->dirty = true;
    pthread_mutex_lock(&s->lock);
    s->applied_revision = ++s->sequence;
    atomic_store(&s->published_revision, s->sequence);
    pthread_mutex_unlock(&s->lock);
    return true;
}

bool sl_stream_settings_network_test_plan(const sl_stream_settings *s, IHS_NetworkTestMode *mode,
                                          uint32_t *target) {
    if (!s || !s->config || !mode || !target)
        return false;
    int32_t bitrate = s->config->desired_bitrate_kbps;
    if (bitrate < -1)
        return false; /* Public dedicated Session accepts positive int32 targets. */
    *mode = bitrate > 0 ? IHS_NetworkTestFixed : IHS_NetworkTestBandwidth;
    *target = bitrate > 0                                       ? (uint32_t)bitrate
              : bitrate == 0                                    ? 250000
              : s->config->quality == k_EStreamQualityFast      ? 10000
              : s->config->quality == k_EStreamQualityBeautiful ? 30000
                                                                : 15000;
    return true;
}
unsigned sl_stream_settings_network_test_recommendation(const sl_stream_settings *s,
                                                        const IHS_NetworkTestResult *result) {
    if (!s || !s->config || !result || !result->valid ||
        result->status != IHS_NetworkTestComplete || result->mode != IHS_NetworkTestBandwidth)
        return 0;
    /* Original c711ec/f0 uses signed W24/B.LT, not unsigned throughput. */
    bool high = result->previousTargetKbps >= 100000 && result->previousTargetKbps <= INT32_MAX;
    return high ? (s->config->quality == k_EStreamQualityBeautiful ? 0 : 2)
                : (s->config->quality == k_EStreamQualityFast ? 0 : 1);
}
