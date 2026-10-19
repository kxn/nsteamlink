#include "protobuf/remoteplay.pb-c.h"
#include "session/channels/ch_control.h"
#include "session/session_pri.h"
#include "stream_settings.h"
#include "ui/ui_events.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool no_replace, fail_publish, fail_close;
int __real_rename(const char *, const char *);
int __wrap_rename(const char *from, const char *to) {
    if (no_replace && !access(to, F_OK)) {
        errno = EEXIST;
        return -1;
    }
    if (fail_publish && strstr(from, "streaming_settings.tmp") && access(to, F_OK)) {
        errno = EIO;
        return -1;
    }
    return __real_rename(from, to);
}
int __real_fclose(FILE *);
int __wrap_fclose(FILE *f) {
    int result = __real_fclose(f);
    if (fail_close) {
        fail_close = false;
        errno = EIO;
        return EOF;
    }
    return result;
}
static const uint8_t enabled[] = {0xc8, 0x01, 0x01};
static const uint8_t disabled[] = {0xc8, 0x01, 0x00};
static sl_auth_store legacy(void) {
    sl_auth_store s = {.device_id = 123, .bitrate_kbps = 6000, .sound = true};
    memset(s.secret, 0x5a, sizeof(s.secret));
    strcpy(s.device_name, "identity-retained");
    return s;
}
static void put(const char *path, const uint8_t *data, size_t size) {
    FILE *f = fopen(path, "wb");
    assert(f);
    if (size)
        assert(fwrite(data, 1, size, f) == size);
    assert(!fclose(f));
}
static void check_file(const char *path, const uint8_t *data, size_t size) {
    FILE *f = fopen(path, "rb");
    assert(f);
    uint8_t *wire = malloc(size + 1);
    assert(wire);
    assert(fread(wire, 1, size + 1, f) == size && (!size || !memcmp(data, wire, size)));
    free(wire);
    assert(!fclose(f));
}
static void publish(sl_stream_settings *s, const uint8_t *data, size_t size) {
    sl_stream_settings_receive(NULL, data, size, s);
    assert(sl_stream_settings_drain(s));
}
static void storage(void) {
    char dir[] = "/tmp/nsl-stream-settings-XXXXXX";
    assert(mkdtemp(dir));
    char path[512], tmp[512], backup[512];
    snprintf(path, sizeof(path), "%s/streaming_settings.bin", dir);
    snprintf(tmp, sizeof(tmp), "%s/streaming_settings.tmp", dir);
    snprintf(backup, sizeof(backup), "%s/streaming_settings.bak", dir);
    sl_auth_store view = legacy();
    sl_stream_settings s;
    assert(sl_stream_settings_init(&s, &view));
    assert(sl_stream_settings_load(&s, dir) == 1 && s.dirty);
    publish(&s, enabled, sizeof(enabled));
    assert(sl_stream_settings_save(&s, dir) && !s.dirty);
    check_file(path, enabled, sizeof(enabled));
    // A late failure must not adopt partial parsed state or destroy the prior file.
    put(path, disabled, sizeof(disabled));
    fail_close = true;
    assert(sl_stream_settings_load(&s, dir) == -1 && s.config->enable_unreliable_fec);
    put(path, (const uint8_t *)"\xc8\x01\x00\x80", 4);
    assert(sl_stream_settings_load(&s, dir) == -2 && s.config->enable_unreliable_fec && !s.dirty);
    check_file(path, (const uint8_t *)"\xc8\x01\x00\x80", 4);
    put(path, enabled, sizeof(enabled));
    publish(&s, disabled, sizeof(disabled));
    fail_close = true;
    assert(!sl_stream_settings_save(&s, dir));
    check_file(path, enabled, sizeof(enabled));
    assert(access(tmp, F_OK));
    no_replace = true;
    fail_publish = true;
    assert(!sl_stream_settings_save(&s, dir));
    check_file(path, enabled, sizeof(enabled));
    fail_publish = false;
    assert(sl_stream_settings_save(&s, dir));
    check_file(path, disabled, sizeof(disabled));
    assert(access(tmp, F_OK) && access(backup, F_OK));
    no_replace = false;
    assert(!rename(path, backup));
    assert(sl_stream_settings_load(&s, dir) == 0 && !s.config->enable_unreliable_fec);
    assert(!access(path, F_OK) && access(backup, F_OK));
    put(path, NULL, 0);
    assert(sl_stream_settings_load(&s, dir) == 0);
    assert(!s.config->enable_unreliable_fec && s.config->desired_bitrate_kbps == -1);
    sl_stream_settings_project(&s, &view);
    assert(view.device_id == 123 && view.secret[0] == 0x5a && view.bitrate_kbps == UINT32_MAX);
    assert(sl_auth_save(&view, dir));
    sl_auth_store reload;
    assert(sl_auth_load(&reload, dir) == 0);
    assert(reload.device_id == view.device_id && !memcmp(reload.secret, view.secret, 32));
    assert(reload.bitrate_kbps == UINT32_MAX);
    sl_stream_settings_destroy(&s);
    assert(!unlink(path));
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    assert(!unlink(path));
    assert(!rmdir(dir));
}
static void ordering(void) {
    sl_auth_store view = legacy();
    sl_stream_settings s;
    assert(sl_stream_settings_init(&s, &view));
    // Interleaved edits need per-field ordering: the older FEC edit loses to
    // the complete host config; a later quality edit must not resurrect it.
    view.unreliable_fec = true;
    sl_stream_settings_note_ui(&s, &view);
    sl_stream_settings_receive(NULL, disabled, sizeof(disabled), &s);
    view.quality = 2;
    sl_stream_settings_note_ui(&s, &view);
    assert(sl_stream_settings_drain(&s));
    assert(!s.config->enable_unreliable_fec && s.config->quality == k_EStreamQualityBeautiful);
    assert(s.applied_revision == 3);
    // A projected view actually seen by the UI establishes the next edit baseline.
    sl_stream_preferences shown = {
        .quality = 2, .bitrate_kbps = UINT32_MAX, .unreliable_fec = false};
    sl_stream_settings_ack_ui(&s, &shown, s.applied_revision);
    view.quality = 2;
    view.bitrate_kbps = UINT32_MAX;
    view.unreliable_fec = true;
    sl_stream_settings_note_ui(&s, &view);
    assert(sl_stream_settings_drain(&s));
    assert(s.config->enable_unreliable_fec);
    sl_stream_settings_ack_ui(&s, &shown, 2); // Stale observer cannot change the baseline.
    sl_stream_settings_note_ui(&s, &view);
    assert(!sl_stream_settings_drain(&s));
    // A newer complete message restores defaults rather than retaining old fields.
    sl_stream_settings_receive(NULL, NULL, 0, &s);
    assert(sl_stream_settings_drain(&s));
    assert(!s.config->enable_unreliable_fec && s.config->quality == k_EStreamQualityBalanced);
    // UI-only registry/sound/language saves do not patch the complete config.
    sl_stream_settings_project(&s, &view);
    shown = (sl_stream_preferences){view.quality, view.bitrate_kbps, view.unreliable_fec};
    sl_stream_settings_ack_ui(&s, &shown, s.applied_revision);
    view.sound = !view.sound;
    view.registry.next_id++;
    sl_stream_settings_note_ui(&s, &view);
    assert(!sl_stream_settings_drain(&s));
    assert(!s.config->has_enable_unreliable_fec);
    sl_stream_settings_destroy(&s);
}
static IHS_Session *session(sl_stream_settings *settings) {
    static const uint8_t secret[32] = {0};
    IHS_ClientConfig client = {.deviceId = 1, .secretKey = secret, .deviceName = "settings"};
    IHS_SessionInfo info = {.sessionKeyLen = 32,
                            .address = {.ip.v4 = {IHS_IPAddressFamilyIPv4, {127, 0, 0, 1}}}};
    IHS_Session *s = IHS_SessionCreate(&client, &info);
    assert(s);
    IHS_TimerTaskStopImmediate(s->retransmission.timer);
    assert(sl_stream_settings_apply(settings, s));
    static const IHS_StreamSessionCallbacks callbacks = {.saveClientConfig =
                                                             sl_stream_settings_receive};
    IHS_SessionSetSessionCallbacks(s, &callbacks, settings);
    s->state.connectionState = IHS_SessionConnectionStateConnected; /* Controlled state; no host. */
    return s;
}
static void session_roundtrip(void) {
    char dir[] = "/tmp/nsl-stream-roundtrip-XXXXXX";
    assert(mkdtemp(dir));
    sl_auth_store view = legacy();
    sl_stream_settings settings;
    assert(sl_stream_settings_init(&settings, &view));
    IHS_Session *s = session(&settings);
    char hotkey[4097];
    memset(hotkey, 'x', sizeof(hotkey) - 1);
    hotkey[4096] = 0;
    CStreamVideoMode mode = CSTREAM_VIDEO_MODE__INIT;
    mode.width = 1280;
    mode.height = 720;
    CStreamVideoLimit limit = CSTREAM_VIDEO_LIMIT__INIT;
    limit.mode = &mode;
    CStreamVideoLimit *limits[] = {&limit, &limit};
    uint8_t unknown[] = {7};
    ProtobufCMessageUnknownField extra = {
        .tag = 150, .wire_type = PROTOBUF_C_WIRE_TYPE_VARINT, .len = 1, .data = unknown};
    CStreamingClientConfig config = CSTREAMING_CLIENT_CONFIG__INIT;
    config.has_enable_unreliable_fec = true;
    config.enable_unreliable_fec = true;
    config.has_desired_framerate_numerator = config.has_desired_framerate_denominator = true;
    config.desired_framerate_numerator = 60000;
    config.desired_framerate_denominator = 1001;
    config.controller_overlay_hotkey = hotkey;
    config.display_limit = &limit;
    config.n_decoder_limit = 2;
    config.decoder_limit = limits;
    config.base.n_unknown_fields = 1;
    config.base.unknown_fields = &extra;
    size_t size = cstreaming_client_config__get_packed_size(&config);
    uint8_t *wire = malloc(size);
    assert(wire);
    cstreaming_client_config__pack(&config, wire);
    assert(IHS_SessionSetStreamingClientConfig(s, wire, size, true));
    free(wire);
    memset(hotkey, 0, sizeof(hotkey)); // Callback must already own its copy.
    assert(sl_stream_settings_drain(&settings));
    assert(sl_stream_settings_save(&settings, dir));
    sl_stream_settings_project(&settings, &view);
    sl_stream_settings_ack_ui(
        &settings, &(sl_stream_preferences){view.quality, view.bitrate_kbps, view.unreliable_fec},
        settings.applied_revision);
    view.unreliable_fec = false;
    sl_stream_settings_note_ui(&settings, &view);
    assert(sl_stream_settings_drain(&settings) && sl_stream_settings_save(&settings, dir));
    assert(s->clientConfig->enable_unreliable_fec); // Manual UI save is next-session only.
    assert(!IHS_QueuePoll(s->sendQueue));
    IHS_SessionDestroy(s);
    sl_stream_settings_destroy(&settings);
    assert(sl_stream_settings_init(&settings, &view));
    assert(sl_stream_settings_load(&settings, dir) == 0);
    s = session(&settings);
    assert(!s->clientConfig->enable_unreliable_fec && s->clientConfig->n_decoder_limit == 2);
    assert(s->clientConfig->display_limit->mode->height == 720);
    assert(s->clientConfig->desired_framerate_numerator == 60000 &&
           s->clientConfig->desired_framerate_denominator == 1001);
    assert(s->clientConfig->desired_bitrate_kbps == -1 &&
           s->clientConfig->base.n_unknown_fields == 1);
    assert(strlen(s->clientConfig->controller_overlay_hotkey) == 4096);
    assert(!IHS_QueuePoll(s->sendQueue));
    IHS_SessionDestroy(s);
    sl_stream_settings_destroy(&settings);
    char path[512];
    snprintf(path, sizeof(path), "%s/streaming_settings.bin", dir);
    assert(!unlink(path));
    assert(!rmdir(dir));
}
static void request_limits(void) {
    sl_auth_store view = legacy();
    sl_stream_settings settings;
    assert(sl_stream_settings_init(&settings, &view));
    publish(&settings, NULL, 0);
    IHS_Session *s = session(&settings);
    const sl_stream_request_limits limits = {.width = 1280, .height = 720, .fps = 60};
    assert(sl_stream_settings_apply_limited(&settings, s, &limits));
    assert(s->clientConfig->desired_resolution_x == 1280 &&
           s->clientConfig->desired_resolution_y == 720 &&
           s->clientConfig->desired_framerate_numerator == 60 &&
           s->clientConfig->desired_framerate_denominator == 1);
    assert(!s->clientConfig->has_desired_bitrate_kbps &&
           s->clientConfig->desired_bitrate_kbps == -1 &&
           !s->clientConfig->has_enable_performance_overlay &&
           !s->clientConfig->enable_performance_overlay);
    assert(!settings.config->has_desired_resolution_x &&
           !settings.config->has_desired_framerate_numerator);
    // The callback copy must carry the request caps, not mutate the source.
    assert(settings.pending && sl_stream_settings_drain(&settings));
    CStreamingClientConfig *config = settings.config;
    config->has_desired_resolution_x = true;
    config->desired_resolution_x = 640;
    config->desired_framerate_numerator = 60000;
    config->desired_framerate_denominator = 1001;
    config->has_enable_video_hevc = true;
    config->enable_video_hevc = true;
    assert(sl_stream_settings_apply_limited(&settings, s, &limits));
    assert(s->clientConfig->desired_resolution_x == 640 &&
           s->clientConfig->desired_framerate_numerator == 60000 &&
           s->clientConfig->desired_framerate_denominator == 1001 &&
           !s->clientConfig->enable_video_hevc);
    assert(config->enable_video_hevc && config->desired_framerate_numerator == 60000);
    config->desired_framerate_numerator = 120;
    config->desired_framerate_denominator = 1;
    assert(sl_stream_settings_apply_limited(&settings, s, &limits));
    assert(s->clientConfig->desired_framerate_numerator == 60 &&
           config->desired_framerate_numerator == 120);
    assert(!IHS_QueuePoll(s->sendQueue));
    IHS_SessionDestroy(s);
    sl_stream_settings_destroy(&settings);
}
typedef struct {
    sl_stream_settings *settings;
    atomic_bool done;
} Publisher;
static void *producer(void *ctx) {
    Publisher *p = ctx;
    for (unsigned i = 0; i < 4000; ++i)
        sl_stream_settings_receive(NULL, i & 1 ? enabled : disabled, 3, p->settings);
    sl_stream_settings_receive(NULL, enabled, 3, p->settings);
    atomic_store(&p->done, true);
    return NULL;
}
static void concurrent(void) {
    sl_auth_store view = legacy();
    sl_stream_settings settings;
    assert(sl_stream_settings_init(&settings, &view));
    Publisher p = {.settings = &settings};
    atomic_init(&p.done, false);
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, producer, &p));
    do {
        sl_stream_settings_drain(&settings);
    } while (!atomic_load(&p.done));
    assert(!pthread_join(thread, NULL));
    sl_stream_settings_drain(&settings);
    assert(settings.config->enable_unreliable_fec && !settings.pending);
    sl_stream_settings_destroy(&settings);
}
static void ui_projection(void) {
    sl_auth_store view = legacy();
    sl_ui_model model;
    sl_ui_init(&model, &view);
    sl_stream_preferences prefs = {.quality = 2, .bitrate_kbps = 12000, .unreliable_fec = true};
    assert(sl_ui_stream_preferences(&model, &prefs, 5));
    assert(model.store.unreliable_fec && model.store.bitrate_kbps == 12000 &&
           model.store.quality == 2);
    assert(model.store.device_id == 123 && !memcmp(model.store.secret, view.secret, 32));
    sl_ui_action(&model, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&model, SL_OPEN_NETWORK_SETTINGS, 0);
    sl_ui_action(&model, SL_OPEN_BANDWIDTH, 0);
    assert(model.focus == 9 && model.layout.label_count > 0);
    model.command = (sl_command){.type = SL_CMD_SAVE};
    model.store.unreliable_fec = false;
    assert(!sl_ui_stream_preferences(&model, &prefs, 6) && !model.store.unreliable_fec);
    model.command = (sl_command){0};
    model.settings_revision = 7;
    assert(!sl_ui_stream_preferences(&model, &prefs, 6));
    prefs.unreliable_fec = false;
    assert(sl_ui_stream_preferences(&model, &prefs, 7));
    prefs.bitrate_kbps = UINT32_MAX;
    assert(sl_ui_stream_preferences(&model, &prefs, 8));
    assert(model.store.bitrate_kbps == UINT32_MAX);
}
int main(void) {
    IHS_Init();
    storage();
    ordering();
    session_roundtrip();
    request_limits();
    concurrent();
    ui_projection();
    IHS_Quit();
    puts("PASS full settings files, failure recovery, ordering, session reload, concurrency and UI "
         "projection");
    return 0;
}
