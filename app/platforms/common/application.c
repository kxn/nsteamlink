#include "platform/application.h"
#include "media.h"
#include "platform/runtime.h"
#include "platform/system.h"
#include "platform/ui_renderer.h"
#include "sdl_input.h"
#include "ui/ui_events.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct application {
    sl_ui_model ui;
    sl_input_router input;
    sl_ui_renderer *renderer;
    sl_runtime *runtime;
    sl_debug_snapshot debug;
} application;
static void draw(void *native, void *ctx) {
    (void)native;
    application *a = ctx;
    sl_ui_renderer_draw(a->renderer, &a->ui, &a->debug);
}
static void event(const void *native, void *ctx) {
    application *a = ctx;
    sl_sdl_input(native, &a->input);
}
static void runtime_events(application *a) {
    sl_runtime_event e;
    while (sl_runtime_poll(a->runtime, &e))
        sl_ui_runtime_event(&a->ui, &e);
}
int sl_application_run(int argc, char **argv) {
    bool offline = false;
    unsigned frames = 0;
    const char *screenshot = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--offline"))
            offline = true;
        else if (!strcmp(argv[i], "--frames") && i + 1 < argc)
            frames = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--screenshot") && i + 1 < argc)
            screenshot = argv[++i];
    }
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
    sl_auth_store store;
    int auth = sl_auth_load(&store, sl_system_data_dir());
    sl_ui_init(&a->ui, &store);
    sl_log_start();
    a->ui.now = a->ui.entered_at = sl_system_now();
    if (!stream_media_init(sl_log)) {
        fprintf(stderr, "Media initialization failed\n");
        free(a);
        sl_log_finish();
        sl_system_shutdown();
        return 1;
    }
    a->renderer = sl_ui_renderer_create(sl_media_renderer());
    if (!a->renderer) {
        fprintf(stderr, "Font initialization failed: %s\n", SDL_GetError());
        stream_media_shutdown();
        free(a);
        sl_log_finish();
        sl_system_shutdown();
        return 1;
    }
    sl_input_init(&a->input, &a->ui, sl_media_input, sl_media_neutral, NULL);
    sl_media_hooks(draw, event, a);
    if (auth < 0)
        sl_ui_error(&a->ui,
                    auth == -2 ? "配对记录损坏，请保留原文件后修复" : "无法读取或保存配对记录");
    else if (!offline) {
        a->runtime = sl_runtime_create(&store);
        if (!a->runtime)
            sl_ui_error(&a->ui, "无法启动网络服务");
    }
    unsigned rendered = 0;
    bool done = false;
    while (!done && sl_system_running()) {
        sl_ui_tick(&a->ui, sl_system_now());
        if (a->runtime) {
            runtime_events(a);
            sl_runtime_debug(a->runtime, &a->debug);
        }
        sl_input_tick(&a->input, a->ui.now);
        sl_media_gate(sl_ui_remote(&a->ui));
        sl_media_mute(!a->ui.store.sound);
        sl_command cmd;
        if (sl_ui_take_command(&a->ui, &cmd)) {
            if (a->runtime) {
                if (!sl_runtime_submit(a->runtime, &cmd, &a->ui.store))
                    sl_ui_error(&a->ui, "操作正在进行，请稍后重试");
            } else if (cmd.type == SL_CMD_CANCEL || cmd.type == SL_CMD_STOP)
                sl_ui_stopped(&a->ui, false);
            else if (cmd.type != SL_CMD_EXIT && cmd.type != SL_CMD_SAVE)
                sl_ui_error(&a->ui, "离线预览未连接网络");
            if (cmd.type == SL_CMD_EXIT)
                done = true;
        }
        stream_media_present();
        if (stream_media_exit_requested())
            done = true;
        if (frames && ++rendered >= frames)
            done = true;
        SDL_Delay(1);
    }
    if (screenshot) {
        SDL_Surface *s = SDL_CreateRGBSurfaceWithFormat(0, 1280, 720, 32, SDL_PIXELFORMAT_ARGB8888);
        if (s) {
            SDL_RenderReadPixels(sl_media_renderer(), NULL, s->format->format, s->pixels, s->pitch);
            SDL_SaveBMP(s, screenshot);
            SDL_FreeSurface(s);
        }
    }
    sl_media_gate(false);
    sl_runtime_destroy(a->runtime);
    sl_media_hooks(NULL, NULL, NULL);
    sl_ui_renderer_destroy(a->renderer);
    stream_media_shutdown();
    free(a);
    sl_log_finish();
    sl_system_shutdown();
    return auth < 0 ? 1 : 0;
}
