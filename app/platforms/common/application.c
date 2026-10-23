#include "platform/application.h"
#include "app_lifecycle.h"
#include "artwork.h"
#include "http_route.h"
#include "media.h"
#include "platform/events.h"
#include "platform/runtime.h"
#include "platform/shortcut.h"
#include "platform/system.h"
#include "platform/ui_renderer.h"
#include "sdl_input.h"
#include "services/i18n.h"
#include "services/update_config.h"
#include "stream_settings.h"
#include "ui/ui_events.h"
#include "ui_audio.h"
#include "updater.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    sl_updater *updater;
    bool http_global;
    sl_debug_snapshot debug;
    sl_app_lifecycle lifecycle;
    sl_command replacement;
    sl_auth_store replacement_store;
} application;
static bool submit_runtime(application *a, const sl_command *cmd, const sl_auth_store *store) {
    bool ok = sl_runtime_submit(a->runtime, cmd, store);
    if (ok)
        a->ui.settings_revision = sl_runtime_settings_revision(a->runtime);
    return ok;
}
static void stream_preferences(application *a) {
    sl_stream_preferences view;
    uint64_t revision;
    if (sl_runtime_stream_settings(a->runtime, &view, &revision) &&
        sl_ui_stream_preferences(&a->ui, &view, revision))
        sl_runtime_ack_stream_settings(a->runtime, &view, revision);
}
static void draw(void *native, void *ctx) {
    (void)native;
    application *a = ctx;
    sl_ui_renderer_draw(a->renderer, &a->ui, &a->debug);
}
static void event(const void *native, void *ctx) {
    application *a = ctx;
    const SDL_Event *e = native;
    /* Official BHandleEvent uses these two lifecycle events specifically.
     * Publish each edge while draining SDL, including a quick pause/resume. */
    if (e->type == SDL_APP_WILLENTERBACKGROUND)
        sl_runtime_foreground(a->runtime, false);
    else if (e->type == SDL_APP_DIDENTERFOREGROUND)
        sl_runtime_foreground(a->runtime, true);
    if (e->type == SDL_WINDOWEVENT) {
        if (e->window.event == SDL_WINDOWEVENT_FOCUS_GAINED)
            sl_runtime_player_focus(a->runtime, true);
        else if (e->window.event == SDL_WINDOWEVENT_FOCUS_LOST)
            sl_runtime_player_focus(a->runtime, false);
    }
#if __SWITCH__
    /* Native deko has no SDL window; the platform emits these edges from
     * libnx application input focus, so publish that owner fact explicitly. */
    if (e->type == SDL_APP_WILLENTERBACKGROUND)
        sl_runtime_player_focus(a->runtime, false);
    else if (e->type == SDL_APP_DIDENTERFOREGROUND)
        sl_runtime_player_focus(a->runtime, true);
#endif
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
    sl_network_test_view test;
    if (sl_runtime_network_test(a->runtime, &test))
        sl_ui_network_test(&a->ui, &test);
}
/* D-060: the NRO that was launched is replaced, and the HOME shortcut's copy
 * with it. Without a launched NRO on the SD card there is nothing to check. */
static sl_updater *start_updater(int argc, char **argv) {
#if NSL_TEST_FORCE_1080
    /* Keep the private manual-test binary intact while testing. */
    (void)argc;
    (void)argv;
    return NULL;
#elif defined(__SWITCH__)
    size_t n = argc > 0 && argv && argv[0] ? strlen(argv[0]) : 0;
    if (n <= 4 || strncmp(argv[0], "sdmc:/", 6) || strcmp(argv[0] + n - 4, ".nro"))
        return NULL;
    const char *targets[SL_UPDATE_MAX_TARGETS] = {argv[0]};
    int count = 1;
    struct stat st;
    if (!stat(SL_SHORTCUT_PATH, &st) && S_ISREG(st.st_mode))
        targets[count++] = SL_SHORTCUT_PATH;
    return sl_updater_create(NSL_SEMANTIC_VERSION, targets, count, NULL, NULL, NULL);
#else
    /* Desktop builds come from source; nothing to update in place. */
    (void)argc;
    (void)argv;
    return NULL;
#endif
}
static void update_result(application *a, bool succeeded, const char *text) {
    sl_runtime_event e = {
        .type = SL_EVENT_UPDATE_RESULT, .generation = a->ui.generation, .account = succeeded};
    snprintf(e.text, sizeof(e.text), "%s", text);
    sl_ui_runtime_event(&a->ui, &e);
}
static void update_events(application *a) {
    sl_update_status s;
    if (!sl_updater_poll(a->updater, &s))
        return;
    if (s.state == SL_UPDATE_AVAILABLE) {
#if NSL_DIAGNOSTICS
        char line[96];
        snprintf(line, sizeof(line), "update_notice available=%s page=%d", s.version, a->ui.page);
        sl_log(line);
#endif
        sl_runtime_event e = {.type = SL_EVENT_UPDATE, .generation = a->ui.generation};
        snprintf(e.text, sizeof(e.text), "%s", s.version);
        sl_ui_runtime_event(&a->ui, &e);
    } else if (s.state == SL_UPDATE_INSTALLED) {
        char text[192];
        snprintf(text, sizeof(text), sl_tr(SL_T_UPDATE_DONE), s.version);
        update_result(a, true, text);
    } else if (s.state == SL_UPDATE_FAILED) {
        update_result(a, false,
                      sl_tr(s.error == SL_UPDATE_ERROR_VERIFY  ? SL_T_UPDATE_FAILED_VERIFY
                            : s.error == SL_UPDATE_ERROR_WRITE ? SL_T_UPDATE_FAILED_WRITE
                                                               : SL_T_UPDATE_FAILED_DOWNLOAD));
    }
}
/* All admission and input policy runs on the renderer/main thread. A pending
 * replacement is dispatched only after persistent cleanup facts close its owner. */
static void lifecycle_facts(application *a) {
    sl_runtime_facts f;
    if (!sl_runtime_read_facts(a->runtime, &f) || f.request_id != a->lifecycle.request_id)
        return;
    if (f.session_id && !a->lifecycle.session_id)
        sl_app_session_created(&a->lifecycle, f.request_id, f.session_id);
    if (f.failed && !f.test_failure_pending &&
        (a->lifecycle.phase == SL_APP_STARTING || a->lifecycle.phase == SL_APP_STREAMING)) {
        sl_app_request_stop(&a->lifecycle);
        sl_media_gate(false);
        sl_media_close_video();
        sl_command stop = {.type = SL_CMD_STOP, .generation = f.request_id};
        submit_runtime(a, &stop, &a->ui.store);
    }
    if (f.connected)
        sl_app_connected(&a->lifecycle, f.session_id);
    if (f.video_transition)
        sl_app_video_state(&a->lifecycle, f.session_id, f.video_transition, f.epoch, f.paused);
    if (f.presented)
        sl_app_presented(&a->lifecycle, f.session_id, f.epoch);
    if (f.requests_closed && !f.test_failure_pending &&
        (a->lifecycle.phase == SL_APP_STARTING || a->lifecycle.phase == SL_APP_STREAMING))
        sl_app_request_stop(&a->lifecycle);
    uint64_t next = sl_app_cleanup(&a->lifecycle, f.request_id, f.session_id, f.requests_closed,
                                   f.protocol_closed, f.video_clean);
    if (next && a->replacement.generation == next &&
        !submit_runtime(a, &a->replacement, &a->replacement_store))
        sl_ui_error(&a->ui, sl_tr(SL_T_BUSY));
}
static bool command(application *a, const sl_command *cmd) {
    if (cmd->type == SL_CMD_UPDATE) {
        /* Runs on the updater worker, not the protocol runtime. */
        if (!sl_updater_install(a->updater))
            update_result(a, false, sl_tr(SL_T_UPDATE_FAILED_DOWNLOAD));
        return true;
    }
    if (cmd->type == SL_CMD_STREAM) {
        if (cmd->security_pin_retry) {
            if (a->lifecycle.phase != SL_APP_STARTING || a->lifecycle.request_id != cmd->generation)
                return false;
            return submit_runtime(a, cmd, &a->ui.store);
        }
        if (!sl_app_request_start(&a->lifecycle, cmd->generation))
            return false;
        if (a->lifecycle.phase != SL_APP_STARTING) {
            a->replacement = *cmd;
            a->replacement_store = a->ui.store;
            sl_media_gate(false);
            sl_media_close_video();
            sl_command stop = {.type = SL_CMD_STOP, .generation = cmd->generation};
            return submit_runtime(a, &stop, &a->ui.store);
        }
    } else if (cmd->type == SL_CMD_STOP || cmd->type == SL_CMD_CANCEL || cmd->type == SL_CMD_EXIT) {
        if (cmd->type == SL_CMD_EXIT)
            sl_app_request_exit(&a->lifecycle);
        else
            sl_app_request_stop(&a->lifecycle);
        sl_media_gate(false);
        sl_media_close_video();
    }
    return submit_runtime(a, cmd, &a->ui.store);
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
#if NSL_DIAGNOSTICS
        fprintf(stderr, "Platform initialization failed\n");
#endif
        return 1;
    }
    application *a = calloc(1, sizeof(*a));
    if (!a) {
        sl_log_finish();
        sl_system_shutdown();
        return 1;
    }
    /* curl 7.69/libnx TLS global setup runs on main before any app worker.
     * Per-owner references also support standalone probes and unit fixtures. */
    if (!offline) {
        a->http_global = sl_http_global_acquire();
        if (!a->http_global) {
            free(a);
            sl_system_shutdown();
            return 1;
        }
    }
    sl_app_lifecycle_init(&a->lifecycle);
    sl_i18n_load(sl_system_data_dir(), sl_system_locale());
    sl_auth_store store;
    int auth = sl_auth_load(&store, sl_system_data_dir());
    if (auth >= 0)
        sl_stream_settings_preview(&store, sl_system_data_dir());
    sl_ui_init(&a->ui, &store);
    a->ui.resolution = sl_video_settings_load(sl_system_data_dir());
    a->ui.update_check = sl_update_config_load(sl_system_data_dir());
    sl_log_start();
    if (!offline)
        a->artwork = sl_artwork_create(sl_system_data_dir(), NULL, NULL);
    if (!offline && a->ui.update_check)
        a->updater = start_updater(argc, argv);
    a->ui.now = a->ui.entered_at = sl_system_now();
    if (!stream_media_init(sl_log)) {
#if NSL_DIAGNOSTICS
        fprintf(stderr, "Media initialization failed\n");
#endif
        sl_updater_destroy(a->updater);
        sl_artwork_destroy(a->artwork);
        if (a->http_global)
            sl_http_global_release();
        free(a);
        sl_log_finish();
        sl_system_shutdown();
        return 1;
    }
    a->renderer = sl_ui_renderer_create(sl_media_gfx());
    if (!a->renderer) {
#if NSL_DIAGNOSTICS
        fprintf(stderr, "Font initialization failed: %s\n", SDL_GetError());
#endif
        sl_updater_destroy(a->updater);
        sl_artwork_destroy(a->artwork);
        stream_media_shutdown();
        if (a->http_global)
            sl_http_global_release();
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
        else
            sl_runtime_player_focus(a->runtime, sl_events_keyboard_focus());
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
#if NSL_DIAGNOSTICS
        int previous_page = a->ui.page;
#endif
        sl_ui_tick(&a->ui, sl_system_now());
#if NSL_DIAGNOSTICS
        if (previous_page != a->ui.page && a->ui.page == SL_UPDATE)
            sl_log("update_notice modal_open");
#endif
        update_events(a);
        if (a->runtime) {
            runtime_events(a);
            stream_preferences(a);
            lifecycle_facts(a);
#if NSL_DIAGNOSTICS
            sl_runtime_debug(a->runtime, &a->debug);
#endif
        }
        sl_app_foreground(&a->lifecycle, sl_events_foreground());
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
                if (!sl_i18n_save(sl_system_data_dir(), cmd.language) ||
                    !sl_update_config_save(sl_system_data_dir(), cmd.update_check) ||
                    !sl_video_settings_save(sl_system_data_dir(), cmd.resolution))
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
#if NSL_DIAGNOSTICS
        if (previous_page == SL_UPDATE && a->ui.page != SL_UPDATE) {
            char line[80];
            snprintf(line, sizeof(line), "update_notice modal_closed page=%d", a->ui.page);
            sl_log(line);
        }
#endif
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
            loop_metrics.cpu_result =
                svcGetInfo(&ticks,
                           hosversionAtLeast(13, 0, 0) ? InfoType_ThreadTickCount
                                                       : InfoType_ThreadTickCountDeprecated,
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
    sl_updater_request_stop(a->updater);
    if (!sl_gfx_healthy(sl_media_gfx()))
        sl_gfx_finish(sl_media_gfx());
    while (!sl_runtime_finished(a->runtime) || !sl_artwork_finished(a->artwork) ||
           !sl_updater_finished(a->updater) || sl_gfx_poll_drain(sl_media_gfx()) == SL_GFX_BUSY) {
        sl_media_collect();
        if (!sl_gfx_healthy(sl_media_gfx()))
            sl_gfx_finish(sl_media_gfx());
        SDL_Delay(1);
    }
    sl_artwork_destroy(a->artwork);
    sl_updater_destroy(a->updater);
    sl_runtime_destroy(a->runtime);
    sl_log(sl_system_dns_finish() ? "cleanup: DNS scopes=0 sockets=0"
                                 : "cleanup: DNS unmatched scopes released");
    sl_media_hooks(NULL, NULL, NULL);
    sl_ui_renderer_destroy(a->renderer);
    stream_media_shutdown();
    if (a->http_global)
        sl_http_global_release();
    free(a);
    sl_log_finish();
    sl_system_shutdown();
    return auth < 0 ? 1 : 0;
}
