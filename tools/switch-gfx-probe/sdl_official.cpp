// Based on devkitPro's graphics/sdl2/sdl2-simple example.
// Diagnostic changes: stage file, nxlink log socket, and bounded auto-exit.
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <switch.h>
#include <SDL.h>

#define STAGE_DIR  "sdmc:/switch/nsteamlink"
#define STAGE_PATH STAGE_DIR "/gfx_probe_stage.txt"
#define PROBE_NAME "switch-gfx-sdl-official"
#define AUTO_FRAMES 180

static int s_log_fd = -1;

static void ensure_stage_dir(void)
{
    if (mkdir(STAGE_DIR, 0777) != 0 && errno != EEXIST)
        return;
}

static void write_stage(const char *stage)
{
    ensure_stage_dir();
    FILE *fp = fopen(STAGE_PATH, "w");
    if (fp) {
        fprintf(fp, "%s:%s\n", PROBE_NAME, stage);
        fclose(fp);
    }
    if (s_log_fd >= 0)
        dprintf(s_log_fd, "%s: %s\n", PROBE_NAME, stage);
}

static void logline(const char *fmt, ...)
{
    if (s_log_fd < 0)
        return;

    va_list ap;
    va_start(ap, fmt);
    dprintf(s_log_fd, "%s: ", PROBE_NAME);
    vdprintf(s_log_fd, fmt, ap);
    dprintf(s_log_fd, "\n");
    va_end(ap);
}

static void init_log(void)
{
    write_stage("socket:init:start");
    if (R_FAILED(socketInitializeDefault())) {
        write_stage("socket:init:failed");
        return;
    }
    write_stage("socket:init:done");
    write_stage("nxlink:connect:start");
    s_log_fd = nxlinkConnectToHost(false, false);
    write_stage(s_log_fd >= 0 ? "nxlink:connect:done" : "nxlink:connect:failed");
}

static void close_log(void)
{
    if (s_log_fd >= 0) {
        int fd = s_log_fd;
        s_log_fd = -1;
        close(fd);
    }
    socketExit();
}

static void draw_rects(SDL_Renderer *renderer, int x, int y)
{
    SDL_SetRenderDrawColor(renderer, 255, 0, 0, 255);
    SDL_Rect r = {x, y, 64, 64};
    SDL_RenderFillRect(renderer, &r);

    SDL_SetRenderDrawColor(renderer, 0, 255, 0, 255);
    SDL_Rect g = {x + 64, y, 64, 64};
    SDL_RenderFillRect(renderer, &g);

    SDL_SetRenderDrawColor(renderer, 0, 0, 255, 255);
    SDL_Rect b = {x + 128, y, 64, 64};
    SDL_RenderFillRect(renderer, &b);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    write_stage("main:entered");
    init_log();

    SDL_Event event;
    SDL_Window *window;
    SDL_Renderer *renderer;
    int done = 0, x = 0, w = 1920, h = 1080;
    int frames = 0;

    write_stage("sdl:init:start");
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_JOYSTICK) < 0) {
        logline("SDL_Init: %s", SDL_GetError());
        write_stage("sdl:init:failed");
        close_log();
        return -1;
    }
    write_stage("sdl:init:done");

    write_stage("sdl:window:start");
    window = SDL_CreateWindow("sdl2_gles2", 0, 0, 1920, 1080, 0);
    if (!window) {
        logline("SDL_CreateWindow: %s", SDL_GetError());
        write_stage("sdl:window:failed");
        SDL_Quit();
        close_log();
        return -1;
    }
    write_stage("sdl:window:done");

    write_stage("sdl:renderer:start");
    renderer = SDL_CreateRenderer(window, 0, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer) {
        logline("SDL_CreateRenderer: %s", SDL_GetError());
        write_stage("sdl:renderer:failed");
        SDL_Quit();
        close_log();
        return -1;
    }
    write_stage("sdl:renderer:done");

    for (int i = 0; i < 2; i++) {
        if (SDL_JoystickOpen(i) == NULL) {
            logline("SDL_JoystickOpen: %s", SDL_GetError());
            write_stage("sdl:joystick:failed");
            SDL_Quit();
            close_log();
            return -1;
        }
    }
    write_stage("sdl:joystick:done");

    write_stage("loop:sdl-owned:start");
    while (!done) {
        while (SDL_PollEvent(&event)) {
            switch (event.type) {
                case SDL_JOYAXISMOTION:
                    logline("Joystick %d axis %d value: %d",
                            event.jaxis.which,
                            event.jaxis.axis, event.jaxis.value);
                    break;

                case SDL_JOYBUTTONDOWN:
                    logline("Joystick %d button %d down",
                            event.jbutton.which, event.jbutton.button);
                    if (event.jbutton.which == 0) {
                        if (event.jbutton.button == 0) {
                            if (w == 1920) {
                                SDL_SetWindowSize(window, 1280, 720);
                            } else {
                                SDL_SetWindowSize(window, 1920, 1080);
                            }
                        } else if (event.jbutton.button == 10) {
                            done = 1;
                        }
                    }
                    break;

                case SDL_QUIT:
                    done = 1;
                    break;

                default:
                    break;
            }
        }

        SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
        SDL_RenderClear(renderer);

        SDL_SetRenderDrawColor(renderer, 111, 111, 111, 255);
        SDL_GetWindowSize(window, &w, &h);
        SDL_Rect f = {0, 0, w, h};
        SDL_RenderFillRect(renderer, &f);

        draw_rects(renderer, x, 0);
        draw_rects(renderer, x, h - 64);

        SDL_RenderPresent(renderer);

        x++;
        if (x > w - 192)
            x = 0;

        frames++;
        if (frames >= AUTO_FRAMES)
            done = 1;
    }
    write_stage("loop:sdl-owned:done");

    write_stage("sdl:destroy-renderer:start");
    SDL_DestroyRenderer(renderer);
    write_stage("sdl:destroy-renderer:done");
    write_stage("sdl:destroy-window:start");
    SDL_DestroyWindow(window);
    write_stage("sdl:destroy-window:done");
    write_stage("sdl:quit:start");
    SDL_Quit();
    write_stage("sdl:quit:done");

    write_stage("result:ok");
    close_log();
    return 0;
}
