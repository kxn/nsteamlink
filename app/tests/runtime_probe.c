/* Desktop runner for the same automatic UI driver used by the private NRO. */
#include "platform/application.h"
#include "runtime_fixture.h"
#include <SDL.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int virtual_pad = -1;
int __real_SDL_Init(Uint32);
int __wrap_SDL_Init(Uint32 flags) {
    int result = __real_SDL_Init(flags);
    if (!result && virtual_pad < 0 && SDL_WasInit(SDL_INIT_GAMECONTROLLER))
        virtual_pad = SDL_JoystickAttachVirtual(SDL_JOYSTICK_TYPE_GAMECONTROLLER, 6, 15, 0);
    return result;
}
void __real_SDL_Quit(void);
void __wrap_SDL_Quit(void) {
    if (virtual_pad >= 0) {
        SDL_JoystickDetachVirtual(virtual_pad);
        virtual_pad = -1;
    }
    __real_SDL_Quit();
}
int sl_live_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = vprintf(format, args);
    va_end(args);
    fflush(stdout);
    return n;
}
int main(int argc, char **argv) {
    if (argc != 3 &&
        !(argc == 4 && (!strcmp(argv[3], "--sdr-only") || !strcmp(argv[3], "--cloud-reconnect")))) {
        fprintf(
            stderr,
            "Usage: nsl-runtime-probe PRIVATE_PROFILE LAN_HOST [--sdr-only|--cloud-reconnect]\n");
        return 2;
    }
    if (argc == 4 && !strcmp(argv[3], "--cloud-reconnect"))
        sl_runtime_fixture_cloud_reconnect();
    sl_auth_store store = {0};
    if ((argc != 3 && argc != 4) || sl_auth_load(&store, argv[1]) ||
        !sl_runtime_fixture_prepare(argv[1], &store, argv[2],
                                    argc == 4 && !strcmp(argv[3], "--sdr-only"))) {
        fprintf(stderr, "Pass an isolated, paired test profile directory and LAN host IPv4\n");
        return 2;
    }
    int result = sl_application_run(1, argv);
    return result ? result : sl_runtime_fixture_result();
}
