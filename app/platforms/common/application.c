#include "platform/application.h"
#include "app_lifecycle.h"
#include "artwork.h"
#include "media.h"
#include "platform/events.h"
#include "platform/runtime.h"
#include "platform/shortcut.h"
#include "platform/system.h"
#include "platform/ui_renderer.h"
#include "sdl_input.h"
#include "services/i18n.h"
#include "ui/ui_events.h"
#include "ui_audio.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if NSL_DIAGNOSTICS && defined(__SWITCH__)
#include <switch.h>
#endif
#if NSL_DIAGNOSTICS
static uint64_t loop_us(void) {
    uint64_t t = SDL_GetPerformanceCounter(), f = SDL_GetPerformanceFrequency();
    return (t / f) * 1000000 + (t % f) * 1000000 / f;
}
#endif

typedef struct application {
    sl_ui_model ui;
    sl_input_router input;
    sl_ui_renderer *renderer;
    sl_runtime *runtime;
    sl_artwork *artwork;
    sl_debug_snapshot debug;
    sl_app_lifecycle lifecycle;
    sl_command replacement;
    sl_auth_store replacement_store;
} application;
static void draw(void *native, void *ctx) {
    (void)native;
    application *a = ctx;
    sl_ui_renderer_draw(a->renderer, &a->ui, &a->debug);
}
static void event(const void *native, void *ctx) {
    application *a = ctx;
    sl_sdl_input(native, &a->input);
    if (!sl_app_allow_remote(&a->lifecycle, sl_ui_remote(&a->ui)))
        sl_media_gate(false);
}
static void remote_input(const sl_input_event *input, void *context) {
    application *a = context;
    if (sl_app_allow_remote(&a->lifecycle, sl_ui_remote(&a->ui)) || input->type == SL_TOUCH_UP)
        sl_media_input(input, NULL);
}
static void runtime_events(application *a) {
    sl_runtime_event e;
    while (sl_runtime_poll(a->runtime, &e))
        sl_ui_runtime_event(&a->ui, &e);
}
/* All admission and input policy runs on the renderer/main thread. A pending
 * replacement is dispatched only after persistent cleanup facts close its owner. */
static void lifecycle_facts(application *a) {
    sl_runtime_facts f;
    if (!sl_runtime_read_facts(a->runtime, &f) || f.request_id != a->lifecycle.request_id)
        return;
    if (f.session_id && !a->lifecycle.session_id)
        sl_app_session_created(&a->lifecycle, f.request_id, f.session_id);
    if (f.failed &&
        (a->lifecycle.phase == SL_APP_STARTING || a->lifecycle.phase == SL_APP_STREAMING)) {
        sl_app_request_stop(&a->lifecycle);
        sl_media_gate(false);
        sl_media_close_video();
        sl_command stop = {.type = SL_CMD_STOP, .generation = f.request_id};
        sl_runtime_submit(a->runtime, &stop, &a->ui.store);
    }
    if (f.connected)
        sl_app_connected(&a->lifecycle, f.session_id);
    if (f.video_transition)
        sl_app_video_state(&a->lifecycle, f.session_id, f.video_transition, f.epoch, f.paused);
    if (f.presented)
        sl_app_presented(&a->lifecycle, f.session_id, f.epoch);
    if (f.requests_closed &&
        (a->lifecycle.phase == SL_APP_STARTING || a->lifecycle.phase == SL_APP_STREAMING))
        sl_app_request_stop(&a->lifecycle);
    uint64_t next = sl_app_cleanup(&a->lifecycle, f.request_id, f.session_id, f.requests_closed,
                                   f.protocol_closed, f.video_clean);
    if (next && a->replacement.generation == next &&
        !sl_runtime_submit(a->runtime, &a->replacement, &a->replacement_store))
        sl_ui_error(&a->ui, sl_tr(SL_T_BUSY));
}
static bool command(application *a, const sl_command *cmd) {
    if (cmd->type == SL_CMD_STREAM) {
        if (!sl_app_request_start(&a->lifecycle, cmd->generation))
            return false;
        if (a->lifecycle.phase != SL_APP_STARTING) {
            a->replacement = *cmd;
            a->replacement_store = a->ui.store;
            sl_media_gate(false);
            sl_media_close_video();
            sl_command stop = {.type = SL_CMD_STOP, .generation = cmd->generation};
            return sl_runtime_submit(a->runtime, &stop, &a->ui.store);
        }
    } else if (cmd->type == SL_CMD_STOP || cmd->type == SL_CMD_CANCEL || cmd->type == SL_CMD_EXIT) {
        if (cmd->type == SL_CMD_EXIT)
            sl_app_request_exit(&a->lifecycle);
        else
            sl_app_request_stop(&a->lifecycle);
        sl_media_gate(false);
        sl_media_close_video();
    }
    return sl_runtime_submit(a->runtime, cmd, &a->ui.store);
}
int sl_application_run(int argc, char **argv) {
    sl_shortcut_source(argc, argv);
    bool offline = false;
    unsigned frames = 0;
    const char *screenshot = NULL;
#if NSL_DIAGNOSTICS
    bool no_adaptive_pacing = false;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--no-adaptive-pacing"))
            no_adaptive_pacing = true;
        else if (!strcmp(argv[i], "--offline"))
            offline = true;
        else if (!strcmp(argv[i], "--frames") && i + 1 < argc)
            frames = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--screenshot") && i + 1 < argc)
            screenshot = argv[++i];
    }
#else
    (void)argc;
    (void)argv;
#endif
    if (!sl_system_init()) {
        fprintf(stderr, "Platform initialization failed\n");
        return 1;
    }
    application *a = calloc(1, sizeof(*a));
    if (!a) {
        sl_log_finish();
        sl_system_shutdown();
        return 1;
    }
    sl_app_lifecycle_init(&a->lifecycle);
    sl_i18n_load(sl_system_data_dir(), sl_system_locale());
    sl_auth_store store;
    int auth = sl_auth_load(&store, sl_system_data_dir());
    sl_ui_init(&a->ui, &store);
    sl_log_start();
    if (!offline)
        a->artwork = sl_artwork_create(sl_system_data_dir(), NULL, NULL);
    a->ui.now = a->ui.entered_at = sl_system_now();
    if (!stream_media_init(sl_log)) {
        fprintf(stderr, "Media initialization failed\n");
        sl_artwork_destroy(a->artwork);
        free(a);
        sl_log_finish();
        sl_system_shutdown();
        return 1;
    }
    a->renderer = sl_ui_renderer_create(sl_media_gfx());
    if (!a->renderer) {
        fprintf(stderr, "Font initialization failed: %s\n", SDL_GetError());
        sl_artwork_destroy(a->artwork);
        stream_media_shutdown();
        free(a);
        sl_log_finish();
        sl_system_shutdown();
        return 1;
    }
    sl_ui_renderer_set_artwork(a->renderer, a->artwork);
    sl_input_init(&a->input, &a->ui, remote_input, sl_media_neutral, a);
    sl_media_hooks(draw, event, a);
    if (auth < 0)
        sl_ui_error(&a->ui, auth == -2 ? sl_tr(SL_T_PROFILE_CORRUPT) : sl_tr(SL_T_PROFILE_FAILED));
    else if (!offline) {
        a->runtime = sl_runtime_create(&store);
        if (!a->runtime)
            sl_ui_error(&a->ui, sl_tr(SL_T_NETWORK_START_FAILED));
    }
    if (screenshot)
        sl_gfx_request_readback(sl_media_gfx());
    uint64_t last_cue = 0;
    unsigned rendered = 0;
    bool done = false;
#if NSL_DIAGNOSTICS
    if (no_adaptive_pacing)
        sl_media_adaptive_pacing(false);
    sl_loop_metrics loop_metrics = {0};
    uint64_t loop_reported = 0;
#endif
    while (!done && sl_system_running()) {
#if NSL_DIAGNOSTICS
        uint64_t loop_start = loop_us();
#endif
        sl_ui_tick(&a->ui, sl_system_now());
        if (a->runtime) {
            runtime_events(a);
            lifecycle_facts(a);
#if NSL_DIAGNOSTICS
            sl_runtime_debug(a->runtime, &a->debug);
#endif
        }
        sl_app_foreground(&a->lifecycle, sl_events_foreground());
        sl_runtime_foreground(a->runtime, sl_events_foreground());
        sl_artwork_pause(a->artwork, a->ui.streaming || a->ui.page != SL_HOME);
        sl_input_tick(&a->input, a->ui.now);
        sl_media_gate(sl_app_allow_remote(&a->lifecycle, sl_ui_remote(&a->ui)) &&
                      sl_gfx_healthy(sl_media_gfx()));
        sl_media_mute(!a->ui.store.sound);
        sl_command cmd;
        if (sl_ui_take_command(&a->ui, &cmd)) {
            if (a->runtime) {
                if (!command(a, &cmd))
                    sl_ui_error(&a->ui, sl_tr(SL_T_BUSY));
            } else if (cmd.type == SL_CMD_SAVE) {
                if (!sl_i18n_save(sl_system_data_dir(), cmd.language))
                    sl_ui_error(&a->ui, sl_tr(SL_T_SAVE_SETTINGS_FAILED));
            } else if (cmd.type == SL_CMD_CANCEL || cmd.type == SL_CMD_STOP ||
                       cmd.type == SL_CMD_END_GAME)
                sl_ui_stopped(&a->ui, false);
            else if (cmd.type != SL_CMD_EXIT && cmd.type != SL_CMD_SAVE)
                sl_ui_error(&a->ui, sl_tr(SL_T_OFFLINE_PREVIEW));
            if (cmd.type == SL_CMD_EXIT)
                done = true;
        }
#if NSL_DIAGNOSTICS
        uint64_t control_end = loop_us();
#endif
        stream_media_present();
#if NSL_DIAGNOSTICS
        uint64_t media_end = loop_us();
#endif
        sl_audio_feedback(a->ui.cue_serial != last_cue ? a->ui.cue : SL_CUE_NONE,
                          a->ui.store.sound);
        last_cue = a->ui.cue_serial;
        if (stream_media_exit_requested() || sl_events_exit_requested() ||
            !sl_gfx_healthy(sl_media_gfx()))
            done = true;
        if (frames && ++rendered >= frames)
            done = true;
#if NSL_DIAGNOSTICS
        uint64_t sleep_start = loop_us();
#endif
        SDL_Delay(1);
#if NSL_DIAGNOSTICS
        uint64_t loop_end = loop_us();
        ++loop_metrics.loops;
        loop_metrics.control_us += control_end - loop_start;
        loop_metrics.media_us += media_end - control_end;
        loop_metrics.tail_us += sleep_start - media_end;
        loop_metrics.sleep_us += loop_end - sleep_start;
        if (loop_end - loop_reported >= 1000000) {
#if defined(__SWITCH__)
            u64 ticks = 0;
            loop_metrics.cpu_result = svcGetInfo(&ticks,
                hosversionAtLeast(13, 0, 0) ? InfoType_ThreadTickCount : InfoType_ThreadTickCountDeprecated,
                CUR_THREAD_HANDLE, TickCountInfo_Total);
            loop_metrics.cpu_ticks = ticks;
            loop_metrics.cpu_wall_ticks = armGetSystemTick();
#else
            loop_metrics.cpu_result = UINT32_MAX;
#endif
            sl_media_loop_metrics(&loop_metrics);
            loop_reported = loop_end;
        }
#endif
    }
    if (NSL_DIAGNOSTICS && screenshot) {
        SDL_Surface *s = SDL_CreateRGBSurfaceWithFormat(0, 1280, 720, 32, SDL_PIXELFORMAT_RGBA32);
        if (s) {
            sl_gfx_readback(sl_media_gfx(), NULL, s->pixels, (size_t)s->pitch * s->h, s->pitch);
            SDL_SaveBMP(s, screenshot);
            SDL_FreeSurface(s);
        }
    }
    sl_app_request_exit(&a->lifecycle);
    sl_media_gate(false);
    sl_media_close_video();
    sl_runtime_request_exit(a->runtime);
    sl_artwork_request_stop(a->artwork);
    if (!sl_gfx_healthy(sl_media_gfx()))
        sl_gfx_finish(sl_media_gfx());
    while (!sl_runtime_finished(a->runtime) || !sl_artwork_finished(a->artwork) ||
           sl_gfx_poll_drain(sl_media_gfx()) == SL_GFX_BUSY) {
        sl_media_collect();
        if (!sl_gfx_healthy(sl_media_gfx()))
            sl_gfx_finish(sl_media_gfx());
        SDL_Delay(1);
    }
    sl_artwork_destroy(a->artwork);
    sl_runtime_destroy(a->runtime);
    sl_media_hooks(NULL, NULL, NULL);
    sl_ui_renderer_destroy(a->renderer);
    stream_media_shutdown();
    free(a);
    sl_log_finish();
    sl_system_shutdown();
    return auth < 0 ? 1 : 0;
}
