#include "events_backend.h"
#include <switch.h>
static bool foreground = true, quit;
#if NSL_GFX_DEKO
static HidTouchScreenState previous;
static SDL_Event touch_events[32];
static unsigned touch_count, touch_cursor;
static void touch_event(Uint32 type, const HidTouchState *now, const HidTouchState *old) {
    SDL_Event *e = &touch_events[touch_count++];
    *e = (SDL_Event){.type = type};
    e->tfinger.fingerId = now->finger_id;
    e->tfinger.x = now->x / 1280.f;
    e->tfinger.y = now->y / 720.f;
    e->tfinger.pressure = type == SDL_FINGERUP ? 0.f : 1.f;
    if (old) {
        e->tfinger.dx = ((float)now->x - old->x) / 1280.f;
        e->tfinger.dy = ((float)now->y - old->y) / 720.f;
    }
}
#endif
static bool touch_polled;
void sl_events_init(void) {
    foreground = true;
    quit = touch_polled = false;
#if NSL_GFX_DEKO
    previous = (HidTouchScreenState){0};
    touch_count = touch_cursor = 0;
#endif
    hidInitializeTouchScreen();
}
bool sl_events_foreground(void) {
    return appletGetFocusState() == AppletFocusState_InFocus;
}
bool sl_events_exit_requested(void) {
    return quit;
}
bool sl_events_next(SDL_Event *event) {
    bool focused = sl_events_foreground();
    if (foreground != focused) {
        foreground = focused;
        *event =
            (SDL_Event){.type = focused ? SDL_APP_DIDENTERFOREGROUND : SDL_APP_WILLENTERBACKGROUND};
        return true;
    }
    if (SDL_PollEvent(event)) {
        if (event->type == SDL_QUIT)
            quit = true;
        return true;
    }
#if NSL_GFX_DEKO
    /* SDL's Switch touch source belongs to SDL video, which is not initialized
     * for deko. Synthesize the same normalized finger events from libnx. */
    if (touch_cursor < touch_count) {
        *event = touch_events[touch_cursor++];
        return true;
    }
    if (!touch_polled) {
        touch_polled = true;
        touch_count = touch_cursor = 0;
        HidTouchScreenState state = {0};
        if (foreground && hidGetTouchScreenStates(&state, 1) <= 0)
            state.count = 0;
        if (state.count < 0)
            state.count = 0;
        if (state.count > 16)
            state.count = 16;
        for (int i = 0; i < previous.count; ++i) {
            int j = 0;
            while (j < state.count && previous.touches[i].finger_id != state.touches[j].finger_id)
                ++j;
            if (j == state.count)
                touch_event(SDL_FINGERUP, &previous.touches[i], NULL);
        }
        for (int i = 0; i < state.count; ++i) {
            int j = 0;
            while (j < previous.count &&
                   state.touches[i].finger_id != previous.touches[j].finger_id)
                ++j;
            if (j == previous.count)
                touch_event(SDL_FINGERDOWN, &state.touches[i], NULL);
            else if (state.touches[i].x != previous.touches[j].x ||
                     state.touches[i].y != previous.touches[j].y)
                touch_event(SDL_FINGERMOTION, &state.touches[i], &previous.touches[j]);
        }
        previous = state;
        if (touch_count) {
            *event = touch_events[touch_cursor++];
            return true;
        }
    }
#endif
    touch_polled = false;
    return false;
}
