#include "platform/rumble.h"
#include <SDL.h>
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <switch.h>
int __wrap_SDL_GameControllerRumble(SDL_GameController *, Uint16, Uint16, Uint32);
static uint64_t now;
static u32 styles[33];
static HidVibrationValue last[2];
static int count, sends, initializes;
static HidNpadIdType destination;
static Result send_error, init_error;
static bool connected = true;
Uint64 SDL_GetTicks64(void) {
    return now;
}
SDL_Joystick *SDL_GameControllerGetJoystick(SDL_GameController *c) {
    return (SDL_Joystick *)c;
}
SDL_JoystickID SDL_JoystickInstanceID(SDL_Joystick *j) {
    return (int)(uintptr_t)j - 1;
}
SDL_Joystick *SDL_JoystickFromInstanceID(SDL_JoystickID id) {
    return connected ? (SDL_Joystick *)(uintptr_t)(id + 1) : NULL;
}
void sl_log(const char *s) {
    (void)s;
}
u32 hidGetNpadStyleSet(HidNpadIdType id) {
    return styles[id];
}
Result hidInitializeVibrationDevices(HidVibrationDeviceHandle *h, int n, HidNpadIdType id,
                                     HidNpadStyleTag s) {
    (void)s;
    ++initializes;
    destination = id;
    for (int i = 0; i < n; ++i)
        h[i].type_value = id * 2 + i;
    return init_error;
}
Result hidSendVibrationValues(const HidVibrationDeviceHandle *h, const HidVibrationValue *v,
                              int n) {
    (void)h;
    ++sends;
    count = n;
    memcpy(last, v, sizeof(*v) * n);
    for (int i = 0; i < n; ++i) {
        assert(v[i].amp_low >= 0 && v[i].amp_low <= 1);
        assert(v[i].amp_high >= 0 && v[i].amp_high <= 1);
        assert(v[i].freq_low == 160 && v[i].freq_high == 320);
    }
    return send_error;
}
static int rumble(unsigned lo, unsigned hi, unsigned ms) {
    return __wrap_SDL_GameControllerRumble((SDL_GameController *)1, lo, hi, ms);
}
int main(void) {
    styles[32] = HidNpadStyleTag_NpadHandheld;
    assert(rumble(65535, 32768, 100) == 0);
    assert(destination == HidNpadIdType_Handheld && count == 2);
    assert(last[0].amp_low == 1 && last[0].amp_high == 0);
    assert(last[1].amp_low == 0 && fabsf(last[1].amp_high - .5f) < .00002f);
    now = 99;
    sl_rumble_tick(true);
    assert(sends == 1);
    now = 100;
    sl_rumble_tick(true);
    assert(sends == 2 && last[0].amp_low == 0 && last[1].amp_high == 0);
    assert(rumble(0, 65535, 10) == 0 && last[1].amp_high == 1);
    now = 105;
    assert(rumble(0, 65535, 100) == 0);
    now = 111;
    sl_rumble_tick(true);
    assert(last[1].amp_high == 1); /* replacement extends expiry */
    assert(rumble(0, 0, 0) == 0 && last[1].amp_high == 0);
    assert(rumble(65535, 65535, 0) == 0);
    now = 100000;
    sl_rumble_tick(true);
    assert(last[0].amp_low == 1); /* duration 0 is sustained */
    sl_rumble_tick(false);
    assert(last[0].amp_low == 0);
    assert(rumble(1, 0, 100) == 0 && last[0].amp_low > 0);
    styles[32] = 0;
    styles[0] = HidNpadStyleTag_NpadJoyDual;
    sl_rumble_tick(true);
    assert(last[0].amp_low == 0); /* docking stops old handles */
    assert(rumble(0, 65535, 100) == 0 && destination == HidNpadIdType_No1 && count == 2);
    connected = false;
    sl_rumble_tick(true);
    assert(last[1].amp_high == 0);
    connected = true;
    styles[0] = HidNpadStyleTag_NpadJoyLeft;
    assert(rumble(0, 65535, 100) == 0 && count == 1 && last[0].amp_high == 1);
    sl_rumble_tick(false);
    styles[0] = HidNpadStyleTag_NpadFullKey;
    assert(rumble(65535, 65535, 100) == 0 && count == 2);
    assert(last[0].amp_low == 1 && last[0].amp_high == 1 && last[1].amp_low == 1);
    send_error = 123;
    assert(rumble(10, 20, 100) == -1);
    assert(rumble(0, 0, 0) == -1); /* explicit stop propagates failure */
    send_error = 0;
    now += 101;
    sl_rumble_tick(true); /* failed stop is retried, not forgotten */
    assert(last[0].amp_low == 0 && last[1].amp_high == 0);
    sl_rumble_tick(false);
    init_error = 456;
    int before = initializes;
    assert(rumble(1, 2, 3) == -1 && initializes == before + 1);
    init_error = 0;
    assert(rumble(1, 2, 3) == 0);
    sl_rumble_tick(false);
    assert(__wrap_SDL_GameControllerRumble(NULL, 1, 2, 3) == -1);
    styles[0] = 0;
    assert(rumble(1, 2, 3) == -1);
    puts("PASS native rumble mapping, intensity, expiry, replacement, cleanup and failures");
}
