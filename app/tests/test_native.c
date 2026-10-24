#include "artwork.h"
#include "media.h"
#include "platform/runtime.h"
#include "platform/system.h"
#include "platform/ui_renderer.h"
#include "sdl_input.h"
#include "ui/ui_events.h"
#include "stream_settings.h"
#include "services/special_settings.h"
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
static unsigned chromatic_pixels(SDL_Rect box) {
    SDL_Surface *s = SDL_CreateRGBSurfaceWithFormat(0, box.w, box.h, 32, SDL_PIXELFORMAT_RGBA32);
    assert(s);
    sl_gfx_rect region = {box.x, box.y, box.w, box.h};
    assert(sl_gfx_readback(sl_media_gfx(), &region, s->pixels, (size_t)s->pitch * s->h, s->pitch));
    unsigned count = 0;
    for (int y = 0; y < s->h; ++y)
        for (int x = 0; x < s->w; ++x) {
            const unsigned char *p = (const unsigned char *)s->pixels + y * s->pitch + x * 4;
            if (abs(p[0] - p[1]) > 2 || abs(p[1] - p[2]) > 2)
                ++count;
        }
    SDL_FreeSurface(s);
    return count;
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
    for (int lang = SL_LANG_ZH_CN; lang <= SL_LANG_EN; ++lang) {
        sl_i18n_set(lang);
        sl_ui_tick(&ui, ui.now + 220);
        stream_media_present();
        save_image(lang == SL_LANG_EN ? "menu-en-stream" : "menu-zh-stream");
        sl_ui_action(&ui, SL_OPEN_END_GAME, 0);
        sl_ui_tick(&ui, ui.now + 220);
        stream_media_present();
        save_image(lang == SL_LANG_EN ? "menu-en-end-game" : "menu-zh-end-game");
        sl_ui_action(&ui, SL_BACK, 0);
        sl_ui_tick(&ui, ui.now + 220);
        sl_ui_action(&ui, SL_OPEN_DISCONNECT, 0);
        sl_ui_tick(&ui, ui.now + 220);
        stream_media_present();
        save_image(lang == SL_LANG_EN ? "menu-en-disconnect" : "menu-zh-disconnect");
        sl_ui_action(&ui, SL_BACK, 0);
        sl_ui_tick(&ui, ui.now + 220);
    }
    sl_i18n_set(SL_LANG_ZH_CN);
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
    sl_system_stream_info platform = sl_system_streaming_info();
    assert(platform.system_info[0] && strstr(platform.system_info, "-203"));
    assert(!strstr(platform.system_info, "Nintendo") && !strstr(platform.system_info, "Tegra"));
    assert(platform.form_factor == SL_STREAM_FORM_COMPUTER);
    assert(!platform.maximum_decode_bitrate_kbps && !platform.maximum_burst_bitrate_kbps);
    assert(platform.decoder_info && strstr(platform.decoder_info, "FFmpeg"));
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
    assert(ui.page == SL_SETTINGS);
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
    assert(ui.page == SL_SETTINGS && ui.command.type == SL_CMD_NONE);
    key(SDLK_ESCAPE);
    ui.store.registry.hosts[0].paired = true;
    ui.store.registry.hosts[0].account = 1;
    ui.store.registry.hosts[0].games[0].id = 413150;
    strcpy(ui.store.registry.hosts[0].games[0].name, "星露谷物语");
    sl_ui_layout(&ui);
    stream_media_present();
    save_image("paired");
    {
        sl_ui_model saved = ui;
        sl_runtime_event source = {.type = SL_EVENT_HOST,
                                   .host = ui.store.registry.hosts[0],
                                   .discovery_source = SL_DISCOVERY_LAN};
        sl_ui_runtime_event(&ui, &source);
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("discovery-lan");
        SDL_Rect icon = {0};
        for (int i = 0; i < ui.layout.count; ++i)
            if (ui.layout.controls[i].action == SL_SELECT_HOST && !ui.layout.controls[i].arg) {
                const sl_control *tab = &ui.layout.controls[i];
                icon = (SDL_Rect){tab->x - 40, 166, tab->w + 80, 48};
                break;
            }
        assert(icon.w);
        uint64_t lan = region_hash(icon);
        source.discovery_source = SL_DISCOVERY_INTERNET;
        sl_ui_runtime_event(&ui, &source);
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("discovery-internet");
        uint64_t internet = region_hash(icon);
        assert(lan != internet);
        sl_runtime_event offline = {.type = SL_EVENT_HOST_OFFLINE, .host = source.host};
        sl_ui_runtime_event(&ui, &offline);
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("discovery-offline");
        uint64_t absent = region_hash(icon);
        assert(absent != lan && absent != internet);
        for (int paired = 0; paired <= 1; ++paired) {
            for (int route = SL_DISCOVERY_NONE; route <= SL_DISCOVERY_INTERNET; ++route) {
                ui = saved;
                sl_runtime_event state = {.type = SL_EVENT_HOST,
                                          .host = saved.store.registry.hosts[0],
                                          .discovery_source = route};
                sl_ui_runtime_event(&ui, &state);
                ui.store.registry.hosts[0].paired = paired;
                if (route == SL_DISCOVERY_NONE) {
                    state.type = SL_EVENT_HOST_OFFLINE;
                    sl_ui_runtime_event(&ui, &state);
                }
                if (route == SL_DISCOVERY_INTERNET && !paired)
                    continue; /* Cloud discovery requires an already-authorized identity. */
                sl_ui_layout(&ui);
                stream_media_present();
                char name[64];
                snprintf(name, sizeof(name), "status-%s-%s",
                         route == SL_DISCOVERY_LAN        ? "lan"
                         : route == SL_DISCOVERY_INTERNET ? "internet"
                                                          : "offline",
                         paired ? "paired" : "unpaired");
                save_image(name);
            }
        }
        ui = saved;
        sl_ui_runtime_event(&ui, &source);
        ui.store.registry.hosts[0].paired = false;
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("discovery-unpaired");
        ui = saved;
        source.discovery_source = SL_DISCOVERY_LAN;
        sl_ui_runtime_event(&ui, &source);
        for (int i = 1; i <= 2; ++i) {
            sl_runtime_event other = source;
            other.host.id = 0;
            other.host.client_id += i;
            snprintf(other.host.address, sizeof(other.host.address), "10.10.10.%d", 40 + i);
            snprintf(other.host.name, sizeof(other.host.name), "%s",
                     i == 1 ? "客厅电脑" : "Gaming PC");
            other.discovery_source = i == 1 ? SL_DISCOVERY_LAN : SL_DISCOVERY_INTERNET;
            sl_ui_runtime_event(&ui, &other);
            ui.store.registry.hosts[i].paired = i == 2;
            if (i == 2) {
                other.type = SL_EVENT_HOST_OFFLINE;
                sl_ui_runtime_event(&ui, &other);
            }
        }
        ui.focus = 10;
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("discovery-multiple");
        sl_runtime_event cloud = source;
        cloud.host.id = 0;
        cloud.host.client_id += 3;
        strcpy(cloud.host.name, "远程电脑");
        cloud.discovery_source = SL_DISCOVERY_INTERNET;
        sl_ui_runtime_event(&ui, &cloud);
        ui.store.registry.hosts[3].paired = true;
        ui.store.registry.selected = 3;
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("internet-paired");
        sl_ui_action(&ui, SL_OPEN_SETTINGS, 0);
        sl_ui_action(&ui, SL_OPEN_SETTINGS, 0);
        sl_ui_action(&ui, SL_OPEN_HOST_SETTINGS, 0);
        sl_ui_activate(&ui, 100);
        assert(ui.page == SL_HOME && sl_ui_adding_host(&ui));
        stream_media_present();
        save_image("add-computer");
        sl_language language = sl_i18n_language();
        sl_i18n_set(SL_LANG_EN);
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("add-computer-en");
        sl_i18n_set(language);
        sl_runtime_event availability = {.type = SL_EVENT_CLOUD_STATE, .account = 1};
        sl_ui_runtime_event(&ui, &availability);
        stream_media_present();
        save_image("add-computer-cloud-ready");
        sl_i18n_set(SL_LANG_EN);
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("add-computer-cloud-ready-en");
        sl_i18n_set(language);
        sl_ui_layout(&ui);
        sl_ui_model adding = ui;
        sl_ui_activate(&ui, 31);
        sl_ui_tick(&ui, ui.now + 220);
        stream_media_present();
        save_image("add-computer-manual");
        ui = adding;
        sl_ui_activate(&ui, 30);
        assert(ui.command.type == SL_CMD_REMOTE_PAIR && !ui.command.host.id);
        sl_runtime_event pair_code = {.type = SL_EVENT_CODE, .generation = ui.generation};
        strcpy(pair_code.text, "1234"); /* UI fixture only; never a live authorization. */
        sl_ui_runtime_event(&ui, &pair_code);
        sl_ui_tick(&ui, ui.now + 2000);
        stream_media_present();
        save_image("add-computer-code");
        ui = adding;
        ui.adding_host = false;
        ui.store.registry.selected = 1;
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("known-computer-unpaired");
        sl_ui_action(&ui, SL_START, 0);
        assert(ui.command.type == SL_CMD_STREAM &&
               ui.command.host.client_id == source.host.client_id + 1);
        pair_code.type = SL_EVENT_STREAM_AUTHORIZATION;
        pair_code.generation = ui.generation;
        sl_ui_runtime_event(&ui, &pair_code);
        sl_ui_tick(&ui, ui.now + 2000);
        stream_media_present();
        save_image("known-computer-pair-code");
        ui = adding;
        ui.adding_host = false;
        ui.store.registry.selected = 2;
        ui.store.registry.hosts[2].games[0].id = 367520;
        strcpy(ui.store.registry.hosts[2].games[0].name, "空洞骑士");
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("cached-games-offline");
        ui = saved;
        sl_ui_layout(&ui);
        stream_media_present();
    }
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
        sl_ui_model available = ui;
        SDL_Rect recent_title_box = {52, 224, 160, 60};
        uint64_t recent_title = region_hash(recent_title_box);
        SDL_Rect artwork_box = {82, SL_CARD_Y + 40, 360, 130};
        uint64_t color = region_hash(artwork_box);
        unsigned chromatic = chromatic_pixels(artwork_box);
        sl_runtime_event unavailable = {.type = SL_EVENT_HOST_OFFLINE,
                                        .host = ui.store.registry.hosts[0]};
        sl_ui_runtime_event(&ui, &unavailable);
        sl_ui_layout(&ui);
        stream_media_present();
        save_image("paired-artwork-offline");
        assert(region_hash(recent_title_box) == recent_title);
        assert(!chromatic_pixels(artwork_box));
        if (chromatic)
            assert(region_hash(artwork_box) != color);
        ui = available;
        sl_ui_layout(&ui);
        stream_media_present();
        assert(region_hash(artwork_box) == color);
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
    sl_ui_action(&ui, SL_OPEN_SETTINGS, 0);
    sl_ui_action(&ui, SL_OPEN_AV_SETTINGS, 0);
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
                sl_ui_action(&ui, SL_OPEN_SETTINGS, 0);
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
            ui.cancel_only_error = false;
            ui.page = p;
            ui.depth = 0;
            ui.leaving = false;
            ui.streaming = p == SL_STREAM || p == SL_MENU;
            ui.ending_game = p == SL_STOPPING;
            ui.debug = p == SL_STREAM;
            ui.stream_started_at = ui.now;
            ui.network_test = (sl_network_test_view){.phase = SL_TEST_RUNNING,
                                                     .target_kbps = 15000,
                                                     .previous_target_kbps = 99999,
                                                     .bandwidth_test = true,
                                                     .mean_ms = 2.5f,
                                                     .deviation_ms = 0.75f,
                                                     .recommendation = 1};
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
        ui.page = SL_HOME;
        ui.streaming = false;
        ui.depth = 0;
        ui.leaving = false;
        ui.store.quality = 0;
        ui.store.bitrate_kbps = UINT32_MAX;
        ui.store.sound = ui.update_check = true;
        ui.resolution = SL_RESOLUTION_AUTO;
        /* Keep the fixture host present while navigating all category screenshots. */
        sl_host observation = ui.store.registry.hosts[ui.store.registry.selected];
        sl_host_observe(&ui.store.registry, &observation, ui.now);
        sl_ui_action(&ui, SL_OPEN_SETTINGS, 0);
        sl_ui_tick(&ui, ui.now + 220);
        stream_media_present();
        char menu_image[64];
        const char *code = lang == SL_LANG_EN ? "en" : "zh";
        snprintf(menu_image, sizeof(menu_image), "menu-%s-settings", code);
        save_image(menu_image);
        const char *categories[] = {"video-audio", "network", "hosts", "application"};
        for (int i = 0; i < 4; ++i) {
            sl_ui_activate(&ui, 100 + i);
            sl_ui_tick(&ui, ui.now + 220);
            stream_media_present();
            snprintf(menu_image, sizeof(menu_image), "menu-%s-%s", code, categories[i]);
            save_image(menu_image);
            sl_ui_action(&ui, SL_BACK, 0);
            sl_ui_tick(&ui, ui.now + 220);
        }
        ui.page = SL_ERROR;
        ui.cancel_only_error = true;
        snprintf(ui.error, sizeof(ui.error), sl_tr(SL_T_TEST_FAILED_DETAIL), "CONTROLLED-PC",
                 61024u);
        sl_ui_layout(&ui);
        stream_media_present();
        save_image(lang == SL_LANG_EN ? "i18n-en-network-failed" : "i18n-zh-network-failed");
        ui.cancel_only_error = false;
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
    /* Full settings must win over a stale legacy UI snapshot on both launches. */
    const uint8_t saved_settings[] = {0x08, 0x03, 0x30, 0xe0, 0x5d, 0xc8,
                                      0x01, 0x01, 0xb0, 0x09, 0x07};
    sl_stream_settings full;
    assert(sl_stream_settings_init(&full, &auth));
    sl_stream_settings_receive(NULL, saved_settings, sizeof(saved_settings), &full);
    assert(sl_stream_settings_drain(&full) && sl_stream_settings_save(&full, dir));
    sl_stream_settings_destroy(&full);
    char blocked_temp[512];
    snprintf(blocked_temp, sizeof(blocked_temp), "%s/profile.tmp", dir);
    assert(mkdir(blocked_temp, 0700) == 0);
    for (int launch = 0; launch < 2; ++launch) {
        sl_runtime *rt = sl_runtime_create(&auth);
        assert(rt);
        sl_command cancel = {.type = SL_CMD_CANCEL, .generation = 100 + launch};
        assert(sl_runtime_submit(rt, &cancel, &auth));
        bool stopped = false, settings_ready = false;
        uint64_t deadline = sl_system_now() + 5000;
        while (sl_system_now() < deadline && (!stopped || !settings_ready)) {
            sl_runtime_event e;
            while (sl_runtime_poll(rt, &e)) {
                assert(e.type != SL_EVENT_FAILURE);
                if (e.type == SL_EVENT_STOPPED && e.generation == cancel.generation)
                    stopped = true;
            }
            sl_stream_preferences prefs;
            uint64_t revision;
            if (sl_runtime_stream_settings(rt, &prefs, &revision)) {
                assert(prefs.quality == 2 && prefs.bitrate_kbps == 12000 && prefs.unreliable_fec);
                settings_ready = true;
            }
            stream_media_present();
            SDL_Delay(5);
        }
        assert(stopped && settings_ready);
        sl_runtime_destroy(rt);
    }
    assert(rmdir(blocked_temp) == 0);
    /* Save a real UI edit through the worker, then read its complete file back. */
    assert(sl_special_settings_save(dir, SL_GUIDE_KEY_OFF));
    sl_runtime *settings_runtime = sl_runtime_create(&auth);
    assert(settings_runtime);
    sl_stream_preferences prefs = {0};
    uint64_t revision = 0;
    uint64_t settings_deadline = sl_system_now() + 5000;
    bool ready = false;
    while (sl_system_now() < settings_deadline && !ready) {
        ready = sl_runtime_stream_settings(settings_runtime, &prefs, &revision);
        stream_media_present();
        SDL_Delay(5);
    }
    assert(ready && prefs.unreliable_fec);
    sl_runtime_ack_stream_settings(settings_runtime, &prefs, revision);
    sl_auth_store edited = auth;
    edited.quality = 1;
    edited.bitrate_kbps = 20000;
    edited.unreliable_fec = false;
    sl_command edit = {.type = SL_CMD_SAVE,
                       .language = SL_LANG_SYSTEM,
                       .update_check = true,
                       .guide_key = SL_GUIDE_KEY_CAPTURE,
                       .resolution = SL_RESOLUTION_1080};
    assert(sl_runtime_submit(settings_runtime, &edit, &edited));
    uint64_t submitted = sl_runtime_settings_revision(settings_runtime);
    ready = false;
    settings_deadline = sl_system_now() + 5000;
    while (sl_system_now() < settings_deadline && !ready) {
        ready = sl_runtime_stream_settings(settings_runtime, &prefs, &revision) &&
                revision >= submitted;
        stream_media_present();
        SDL_Delay(5);
    }
    assert(ready && !prefs.unreliable_fec && prefs.quality == 1 && prefs.bitrate_kbps == 20000);
    sl_runtime_destroy(settings_runtime);
    assert(sl_video_settings_load(dir) == SL_RESOLUTION_1080);
    assert(sl_special_settings_load(dir) == SL_GUIDE_KEY_CAPTURE); /* The worker replaces the prior OFF preference. */
    sl_auth_store reloaded = auth;
    sl_stream_settings_preview(&reloaded, dir);
    assert(!reloaded.unreliable_fec && reloaded.quality == 1 && reloaded.bitrate_kbps == 20000);
    assert(reloaded.device_id == auth.device_id && !memcmp(reloaded.secret, auth.secret, 32));
    char settings_path[512];
    snprintf(settings_path, sizeof(settings_path), "%s/streaming_settings.bin", dir);
    FILE *settings_file = fopen(settings_path, "rb");
    assert(settings_file);
    uint8_t persisted[64];
    size_t persisted_size = fread(persisted, 1, sizeof(persisted), settings_file);
    assert(!fclose(settings_file));
    bool unknown_retained = false;
    for (size_t i = 0; i + 2 < persisted_size; ++i)
        if (persisted[i] == 0xb0 && persisted[i + 1] == 0x09 && persisted[i + 2] == 0x07)
            unknown_retained = true;
    assert(unknown_retained);
    sl_media_hooks(NULL, NULL, NULL);
    sl_artwork_destroy(artwork);
    artwork = NULL;
    sl_ui_renderer_destroy(renderer);
    stream_media_shutdown();
    const char *settings_files[] = {"profile.bin", "streaming_settings.bin", "language.conf",
                                    "update.conf", "video.conf", "special.conf"};
    for (size_t i = 0; i < sizeof(settings_files) / sizeof(settings_files[0]); ++i) {
        snprintf(blocked_temp, sizeof(blocked_temp), "%s/%s", dir, settings_files[i]);
        assert(!unlink(blocked_temp));
    }
    snprintf(blocked_temp, sizeof(blocked_temp), "%s/sdr_config.txt", dir);
    if (access(blocked_temp, F_OK) == 0) assert(!unlink(blocked_temp));
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
