#include "platform/rumble.h"
#include "platform/runtime.h"
#include <SDL.h>
#include <switch.h>

/* devkitPro SDL 2.28.5-4 maps instance IDs 0..7 to Npad slots; slot 0
 * additionally reads Handheld. Wrap only the app's GameControllerRumble calls,
 * bypassing that backend's invalid amplitudes/uninitialized slot-0 handle.
 * All calls and expiry run on the media thread, never the receive thread. */
typedef struct rumble_slot {
    HidVibrationDeviceHandle handles[2];
    HidNpadIdType id;
    u32 style;
    int count;
    bool active;
    uint64_t expires;
} rumble_slot;
static rumble_slot slots[8];
static uint64_t last_error;

static int failure(Result rc) {
    uint64_t now = SDL_GetTicks64();
    if (!last_error || now - last_error >= 2000) {
        char line[96];
        SDL_snprintf(line, sizeof(line), "rumble: libnx output failed rc=%08x", (unsigned)rc);
        sl_log(line);
        last_error = now ? now : 1;
    }
    return SDL_SetError("Switch rumble failed: %08x", (unsigned)rc);
}
static int stop(rumble_slot *s) {
    if (s->active) {
        const HidVibrationValue zero[2] = {{0, 160, 0, 320}, {0, 160, 0, 320}};
        Result rc = hidSendVibrationValues(s->handles, zero, s->count);
        if (R_FAILED(rc)) {
            s->expires = SDL_GetTicks64() + 100;
            return failure(rc);
        }
    }
    s->active = false;
    s->expires = 0;
    return 0;
}
static u32 location(int index, HidNpadIdType *id) {
    *id = (HidNpadIdType)(HidNpadIdType_No1 + index);
    /* Same sources as SDL's padInitializeDefault, but vibration must target
     * Handheld explicitly instead of silently sending to No1. */
    if (index == 0 && (hidGetNpadStyleSet(HidNpadIdType_Handheld) & HidNpadStyleTag_NpadHandheld))
        *id = HidNpadIdType_Handheld;
    return hidGetNpadStyleSet(*id);
}
int __wrap_SDL_GameControllerRumble(SDL_GameController *controller, Uint16 low, Uint16 high,
                                    Uint32 duration_ms) {
    SDL_Joystick *joy = SDL_GameControllerGetJoystick(controller);
    int index = joy ? SDL_JoystickInstanceID(joy) : -1;
    if (index < 0 || index >= 8)
        return SDL_SetError("Unknown Switch rumble controller");
    rumble_slot *s = &slots[index];
    HidNpadIdType id;
    u32 style = location(index, &id);
    if (s->id != id || s->style != style) {
        if (stop(s) < 0)
            return -1;
        s->count = 0;
        s->id = id;
        s->style = style;
    }
    if (!low && !high) {
        return stop(s);
    }
    if (!s->count) {
        int count = (style & (HidNpadStyleTag_NpadHandheld | HidNpadStyleTag_NpadJoyDual |
                              HidNpadStyleTag_NpadFullKey))
                        ? 2
                    : (style & (HidNpadStyleTag_NpadJoyLeft | HidNpadStyleTag_NpadJoyRight)) ? 1
                                                                                             : 0;
        if (!count)
            return SDL_SetError("Controller has no supported vibration device");
        Result rc = hidInitializeVibrationDevices(s->handles, count, id, (HidNpadStyleTag)style);
        if (R_FAILED(rc))
            return failure(rc);
        s->count = count;
    }
    /* SDL inputs are intensities, not Hz. libnx amplitudes are normalized.
     * Paired Joy-Cons: SDL HIDAPI routes low to left and high to right.
     * Pro Controller / a single Joy-Con retain both bands on each actuator. */
    float lo = low / 65535.0f, hi = high / 65535.0f;
    HidVibrationValue values[2] = {{lo, 160, hi, 320}, {lo, 160, hi, 320}};
    if (style & (HidNpadStyleTag_NpadHandheld | HidNpadStyleTag_NpadJoyDual)) {
        values[0].amp_high = 0;
        values[1].amp_low = 0;
    }
    Result rc = hidSendVibrationValues(s->handles, values, s->count);
    if (R_FAILED(rc))
        return failure(rc);
    s->active = true;
    /* SDL duration=0 means no expiry; an explicit zero still stops it. */
    s->expires = duration_ms ? SDL_GetTicks64() + duration_ms : 0;
    return 0;
}
void sl_rumble_tick(bool session_active) {
    uint64_t now = SDL_GetTicks64();
    for (int i = 0; i < 8; ++i) {
        rumble_slot *s = &slots[i];
        if (!s->active)
            continue;
        HidNpadIdType id;
        u32 style = location(i, &id);
        if (!session_active || (s->expires && now >= s->expires) || id != s->id ||
            style != s->style || !SDL_JoystickFromInstanceID(i)) {
            if (stop(s) == 0)
                s->count = 0;
        }
    }
}
