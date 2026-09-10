#include "artwork.h"
#include "media.h"
#include "platform/runtime.h"
#include "platform/system.h"
#include "platform/ui_renderer.h"
#include "sdl_input.h"
#include <SDL.h>
#include <assert.h>
#include <libavcodec/avcodec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static sl_ui_model ui;
static sl_ui_renderer *renderer;
static sl_input_router router;
static unsigned draws, remote_events;
static void draw(void *native, void *ctx) {
    (void)native;
    (void)ctx;
    sl_debug_snapshot d = {0};
    sl_ui_renderer_draw(renderer, &ui, &d);
    draws++;
}
static void event(const void *e, void *ctx) {
    (void)ctx;
    sl_sdl_input(e, &router);
}
static void remote(const sl_input_event *e, void *ctx) {
    (void)e;
    (void)ctx;
    remote_events++;
}
static void save_image(const char *name) {
    const char *dir = getenv("NSL_TEST_OUTPUT");
    if (!dir)
        return;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.bmp", dir, name);
    SDL_Surface *s = SDL_CreateRGBSurfaceWithFormat(0, 1280, 720, 32, SDL_PIXELFORMAT_RGBA32);
    assert(s);
    assert(sl_gfx_readback(sl_media_gfx(), NULL, s->pixels, (size_t)s->pitch * s->h, s->pitch));
    assert(SDL_SaveBMP(s, path) == 0);
    SDL_FreeSurface(s);
}
static uint64_t region_hash(SDL_Rect box) {
    SDL_Surface *s = SDL_CreateRGBSurfaceWithFormat(0, box.w, box.h, 32, SDL_PIXELFORMAT_RGBA32);
    assert(s);
    sl_gfx_rect region = {box.x, box.y, box.w, box.h};
    assert(sl_gfx_readback(sl_media_gfx(), &region, s->pixels, (size_t)s->pitch * s->h, s->pitch));
    uint64_t hash = 14695981039346656037ULL;
    for (int y = 0; y < s->h; ++y)
        for (int x = 0; x < s->w * 4; ++x) {
            hash ^= ((unsigned char *)s->pixels)[y * s->pitch + x];
            hash *= 1099511628211ULL;
        }
    SDL_FreeSurface(s);
    return hash;
}
static void tap(int x, int y) {
    SDL_Event e = {.type = SDL_MOUSEBUTTONDOWN};
    e.button.button = SDL_BUTTON_LEFT;
    e.button.x = x;
    e.button.y = y;
    SDL_PushEvent(&e);
    e.type = SDL_MOUSEBUTTONUP;
    SDL_PushEvent(&e);
    stream_media_present();
}
static void key(SDL_Keycode k) {
    SDL_Event e = {.type = SDL_KEYDOWN};
    e.key.keysym.sym = k;
    SDL_PushEvent(&e);
    e.type = SDL_KEYUP;
    SDL_PushEvent(&e);
    stream_media_present();
    sl_ui_tick(&ui, ui.now + 220);
    stream_media_present();
}
static void decode(const char *path) {
    FILE *f = fopen(path, "rb");
    assert(f);
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    rewind(f);
    uint8_t *bytes = calloc(1, length + AV_INPUT_BUFFER_PADDING_SIZE);
    assert(bytes);
    assert(fread(bytes, 1, length, f) == (size_t)length);
    fclose(f);
    IHS_StreamVideoConfig c = {.codec = IHS_StreamVideoCodecH264, .width = 1280, .height = 720};
    assert(stream_media_video_start(NULL, &c) == 0);
    AVCodecParserContext *parser = av_parser_init(AV_CODEC_ID_H264);
    AVCodecContext *ctx = avcodec_alloc_context3(NULL);
    assert(parser && ctx);
    size_t pos = 0;
    int id = 0;
    while (pos < (size_t)length) {
        uint8_t *out;
        int size;
        int consumed = av_parser_parse2(parser, ctx, &out, &size, bytes + pos, (int)(length - pos),
                                        AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
        assert(consumed >= 0);
        pos += consumed;
        if (size) {
            IHS_Buffer buf = {.data = out, .size = size, .capacity = size};
            assert(stream_media_video_submit(NULL, ++id, &buf, IHS_StreamVideoFrameKeyFrame) ==
                   IHS_StreamVideoSubmitOK);
            stream_media_present();
        } else if (!consumed)
            break;
    }
    stream_media_snapshot s;
    stream_media_get_snapshot(&s);
    assert(s.displayed_frames > 0 && s.upload_samples > 0);
#if NSL_DIAGNOSTICS
    assert(s.render.samples == s.displayed_frames);
    assert(s.render.prep_us > 0 && s.render.age_us >= s.render.prep_us);
    assert(s.render.uploads == s.displayed_frames);
    uint64_t prep_samples = s.render.samples, uploads = s.render.uploads;
    uint64_t redraws = s.render.redraws;
#endif
    unsigned shown = s.displayed_frames, before = draws;
    for (int i = 0; i < 5; ++i)
        stream_media_present();
    stream_media_get_snapshot(&s);
    assert(s.displayed_frames == shown && draws == before + 5);
#if NSL_DIAGNOSTICS
    assert(s.render.samples == prep_samples && s.render.uploads == uploads);
    assert(s.render.redraws == redraws + 5);
#endif
    save_image("stream-hint");
    ui.now = ui.stream_started_at + 4200;
    stream_media_present();
    save_image("stream");
    sl_ui_action(&ui, SL_OPEN_MENU, 0);
    stream_media_present();
    save_image("stream-menu");
    stream_media_get_snapshot(&s);
    assert(s.displayed_frames == shown);
    stream_media_video_stop(NULL);
    stream_media_present();
    av_parser_close(parser);
    avcodec_free_context(&ctx);
    free(bytes);
}
static bool no_artwork_network(const char *url, size_t limit, unsigned char **data, size_t *size,
                               void *context) {
    (void)url;
    (void)limit;
    (void)data;
    (void)size;
    (void)context;
    return false;
}
int main(int argc, char **argv) {
    assert(sl_system_init());
    assert(stream_media_init(sl_log));
    assert(sl_gfx_request_readback(sl_media_gfx()));
    renderer = sl_ui_renderer_create(sl_media_gfx());
    assert(renderer);
    sl_artwork *artwork = NULL;
    const char *art_dir = getenv("NSL_TEST_ARTWORK_DIR");
    if (art_dir) {
        artwork = sl_artwork_create(art_dir, no_artwork_network, NULL);
        assert(artwork);
        sl_ui_renderer_set_artwork(renderer, artwork);
    }
    sl_auth_store s = {.sound = true};
    sl_host_registry_init(&s.registry);
    sl_ui_init(&ui, &s);
    ui.now = sl_system_now();
    sl_input_init(&router, &ui, remote, NULL, NULL);
    sl_media_hooks(draw, event, NULL);
    stream_media_present();
    save_image("empty");
    tap(1140, 660);
    assert(ui.page == SL_OPTIONS);
    assert(ui.command.type == SL_CMD_NONE);
    key(SDLK_ESCAPE);
    assert(ui.page == SL_HOME);
    sl_host h = {.client_id = 123, .instance_id = 2};
    strcpy(h.name, "DESKTOP-7K2P9");
    strcpy(h.address, "192.168.1.24");
    strcpy(h.system, "Windows");
    sl_host_observe(&ui.store.registry, &h, ui.now);
    sl_ui_layout(&ui);
    stream_media_present();
    save_image("unpaired");
    tap(900, 660);
    assert(ui.page == SL_HOME && ui.command.type == SL_CMD_NONE);
    SDL_Event touch = {.type = SDL_FINGERDOWN};
    touch.tfinger.fingerId = 123;
    touch.tfinger.x = .9f;
    touch.tfinger.y = .92f;
    SDL_PushEvent(&touch);
    touch.type = SDL_FINGERUP;
    SDL_PushEvent(&touch);
    stream_media_present();
    assert(ui.page == SL_OPTIONS && ui.command.type == SL_CMD_NONE);
    key(SDLK_ESCAPE);
    ui.store.registry.hosts[0].paired = true;
    ui.store.registry.hosts[0].account = 1;
    ui.store.registry.hosts[0].games[0].id = 413150;
    strcpy(ui.store.registry.hosts[0].games[0].name, "星露谷物语");
    sl_ui_layout(&ui);
    stream_media_present();
    save_image("paired");
    if (artwork) {
        /* Offline fixture rendering exercises queue -> decode -> texture upload -> fade. */
        for (int i = 0; i < 100; ++i) {
            sl_ui_tick(&ui, ui.now + 10);
            stream_media_present();
            SDL_Delay(5);
        }
        save_image("paired-artwork");
        ui.focus = 40;
        stream_media_present();
        sl_ui_tick(&ui, ui.now + 200);
        stream_media_present();
        save_image("paired-artwork-focused");
    }
    /* Fixture duplicates artwork only to exercise a four-card viewport. */
    for (int i = 1; i < 4; ++i)
        ui.store.registry.hosts[0].games[i] = ui.store.registry.hosts[0].games[0];
    sl_ui_layout(&ui);
    stream_media_present();
    save_image("carousel-start");
    strcpy(ui.store.registry.hosts[0].games[0].name, "Girls Made Pudding -少女布丁旅情-");
    strcpy(ui.store.registry.hosts[0].games[1].name, "很长的中文游戏标题：完整版本与附加内容");
    sl_ui_layout(&ui);
    stream_media_present();
    save_image("title-start");
    SDL_Rect selected_title = {76, 508, 392, 54}, other_title = {540, 508, 392, 54};
    uint64_t initial_title = region_hash(selected_title), still_title = region_hash(other_title);
    sl_ui_tick(&ui, ui.now + 1000);
    stream_media_present();
    assert(initial_title == region_hash(selected_title));
    for (int i = 0; i < 240; ++i) {
        sl_ui_tick(&ui, ui.now + 16);
        stream_media_present();
    }
    save_image("title-scroll");
    assert(initial_title != region_hash(selected_title));
    assert(still_title == region_hash(other_title));
    sl_ui_action(&ui, SL_RIGHT, 0);
    stream_media_present();
    save_image("title-switch");
    sl_ui_action(&ui, SL_LEFT, 0);
    stream_media_present();
    assert(initial_title == region_hash(selected_title));

    for (int i = 0; i < 3; ++i)
        sl_ui_action(&ui, SL_RIGHT, 0);
    for (int i = 0; i < 40; ++i) {
        sl_ui_tick(&ui, ui.now + 16);
        stream_media_present();
    }
    save_image("carousel-end");
    h.client_id = 124;
    strcpy(h.name, "DESKTOP-B");
    strcpy(h.address, "192.168.1.25");
    sl_host_observe(&ui.store.registry, &h, ui.now);
    sl_ui_layout(&ui);
    stream_media_present();
    save_image("carousel-hosts");
    sl_ui_model before_launch = ui;
    sl_ui_action(&ui, SL_RECENT, 2);
    assert(ui.page == SL_CONNECTING && ui.launch_card.id == 42);
    assert(ui.launch_card.x < SL_GAMES_LEFT + 2 * SL_CARD_STEP);
    for (int i = 0; i <= 30; ++i) {
        if (i)
            sl_ui_tick(&ui, ui.now + 16);
        stream_media_present();
        char frame[48];
        snprintf(frame, sizeof(frame), "launch-%02d", i);
        save_image(frame);
    }
    ui = before_launch;
    sl_ui_layout(&ui);

    for (int p = SL_PAIRING; p <= SL_ERROR; ++p) {
        ui.page = p;
        ui.ending_game = p == SL_STOPPING;
        strcpy(ui.pairing_code, "4826");
        ui.pair_code_at = ui.now - 1800;
        sl_ui_layout(&ui);
        stream_media_present();
        sl_ui_tick(&ui, ui.now + 200);
        stream_media_present();
        char name[32];
        snprintf(name, sizeof(name), "page-%02d", p);
        save_image(name);
    }
    ui.page = SL_HOME;
    ui.depth = 0;
    ui.leaving = false;
    sl_ui_action(&ui, SL_OPEN_OPTIONS, 0);
    sl_ui_action(&ui, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&ui, SL_OPEN_QUALITY, 0);
    sl_ui_tick(&ui, ui.now + 220);
    sl_ui_action(&ui, SL_DOWN, 0);
    stream_media_present();
    save_image("quality-focused-unsaved");
    if (getenv("NSL_TEST_MOTION")) {
        ui.page = SL_HOME;
        ui.depth = 0;
        ui.leaving = false;
        sl_ui_layout(&ui);
        for (int frame = 0; frame < 120; ++frame) {
            if (frame == 9)
                sl_ui_action(&ui, SL_OPEN_OPTIONS, 0);
            if (frame == 28)
                sl_ui_action(&ui, SL_ACCEPT, 0);
            if (frame == 45 || frame == 80 || frame == 100)
                sl_ui_action(&ui, SL_BACK, 0);
            if (frame == 60)
                sl_ui_action(&ui, SL_OPEN_FORGET, 0);
            sl_ui_tick(&ui, ui.now + 33);
            stream_media_present();
            char name[32];
            snprintf(name, sizeof(name), "motion-%03d", frame);
            save_image(name);
        }
    }
    /* Render every screen in both languages with real font metrics. */
    for (int lang = SL_LANG_ZH_CN; lang <= SL_LANG_EN; ++lang) {
        sl_i18n_set(lang);
        for (int p = SL_HOME; p <= SL_CLOSING; ++p) {
            ui.page = p;
            ui.depth = 0;
            ui.leaving = false;
            ui.streaming = p == SL_STREAM || p == SL_MENU || p == SL_BANDWIDTH;
            ui.ending_game = p == SL_STOPPING;
            ui.debug = p == SL_STREAM;
            ui.stream_started_at = ui.now;
            ui.entered_at = ui.now > 500 ? ui.now - 500 : 0;
            strcpy(ui.error,
                   sl_tr(p == SL_INSTALL_RESULT ? SL_T_SHORTCUT_ADDED : SL_T_PROFILE_CORRUPT));
            sl_ui_layout(&ui);
            stream_media_present();
            char image[64];
            snprintf(image, sizeof(image), "i18n-%s-page-%02d", lang == SL_LANG_EN ? "en" : "zh",
                     p);
            save_image(image);
        }
    }
    sl_i18n_set(SL_LANG_ZH_CN);
    ui.page = SL_HOME;
    sl_ui_connected(&ui);
    sl_input_sync(&router);
    stream_media_present();
    if (argc > 1)
        decode(argv[1]);
    assert(remote_events == 0);
    /* Real Opus -> native SDL queue path, including switching back to UI output. */
    for (int channels = 1; channels <= 2; ++channels) {
        IHS_StreamAudioConfig config = {
            .codec = IHS_StreamAudioCodecOpus, .frequency = 48000, .channels = channels};
        assert(stream_media_audio_start(NULL, &config) == 0);
        IHS_Buffer silence = {0}; /* Opus packet-loss concealment is valid decoded PCM. */
        assert(stream_media_audio_submit(NULL, &silence) == 0);
        stream_media_snapshot snapshot;
        stream_media_get_snapshot(&snapshot);
        assert(snapshot.audio_active && snapshot.audio_frames == 1 &&
               snapshot.audio_decode_errors == 0);
        stream_media_audio_stop(NULL);
    }
    /* Same runtime creates/joins real discovery workers twice, without requesting a host stream. */
    char profile_dir[] = "/tmp/nsl-native-profile-XXXXXX";
    assert(mkdtemp(profile_dir));
    assert(setenv("NSL_DATA_DIR", profile_dir, 1) == 0);
    const char *dir = sl_system_data_dir();
    sl_auth_store auth;
    assert(sl_auth_load(&auth, dir) >= 0);
    char blocked_temp[512];
    snprintf(blocked_temp, sizeof(blocked_temp), "%s/profile.tmp", dir);
    assert(mkdir(blocked_temp, 0700) == 0);
    for (int launch = 0; launch < 2; ++launch) {
        sl_runtime *rt = sl_runtime_create(&auth);
        assert(rt);
        sl_command cancel = {.type = SL_CMD_CANCEL, .generation = 100 + launch};
        assert(sl_runtime_submit(rt, &cancel, &auth));
        bool stopped = false;
        uint64_t deadline = sl_system_now() + 5000;
        while (sl_system_now() < deadline && !stopped) {
            sl_runtime_event e;
            while (sl_runtime_poll(rt, &e)) {
                assert(e.type != SL_EVENT_FAILURE);
                if (e.type == SL_EVENT_STOPPED && e.generation == cancel.generation)
                    stopped = true;
            }
            stream_media_present();
            SDL_Delay(5);
        }
        assert(stopped);
        sl_runtime_destroy(rt);
    }
    sl_media_hooks(NULL, NULL, NULL);
    sl_artwork_destroy(artwork);
    artwork = NULL;
    sl_ui_renderer_destroy(renderer);
    stream_media_shutdown();
    assert(rmdir(blocked_temp) == 0);
    snprintf(blocked_temp, sizeof(blocked_temp), "%s/profile.bin", dir);
    assert(unlink(blocked_temp) == 0);
    assert(rmdir(dir) == 0);
    /* Reinitialize SDL/fonts in this process to catch stale static ownership. */
    assert(stream_media_init(sl_log));
    assert(sl_gfx_request_readback(sl_media_gfx()));
    renderer = sl_ui_renderer_create(sl_media_gfx());
    assert(renderer);
    sl_ui_init(&ui, &s);
    sl_media_hooks(draw, event, NULL);
    stream_media_present();
    sl_media_hooks(NULL, NULL, NULL);
    sl_artwork_destroy(artwork);
    artwork = NULL;
    sl_ui_renderer_destroy(renderer);
    stream_media_shutdown();
    sl_system_shutdown();
    puts("PASS native SDL mouse/touch/keyboard, all screens, cached video redraw/frame accounting, "
         "real runtime cancellation and two launches");
    return 0;
}
