#include "events_backend.h"
#include "platform/system.h"
#include <switch.h>
#if NSL_DIAGNOSTICS
#include "diagnostic_log.h"
#include <stdio.h>
static bool capture_test_active;
static unsigned capture_test_messages;
static unsigned capture_notifications, capture_notifications_reported;
#endif
static bool foreground = true, quit;
static AppletHookCookie capture_hook;
static bool capture_hooked, capture_redirected, capture_restore, capture_allowed;
static bool capture_pending, capture_failed;
static Result capture_error;

static void capture_message(AppletHookType hook, void *context) {
    (void)context;
    /* Called by the EXISTING appletMainLoop, never consumes messages itself.
     * No SDL/session/network/log work is allowed in this callback. */
    if (hook == AppletHookType_OnCaptureButtonShortPressed && capture_allowed)
        capture_pending = true; /* Coalesce; never build a backlog of presses. */
#if NSL_DIAGNOSTICS
    if (hook == AppletHookType_OnCaptureButtonShortPressed && capture_notifications != UINT32_MAX)
        ++capture_notifications;
    if (hook == AppletHookType_OnCaptureButtonShortPressed && capture_test_active &&
        capture_test_messages != UINT32_MAX)
        ++capture_test_messages;
#endif
    if (hook == AppletHookType_OnFocusState || hook == AppletHookType_OnExitRequest)
        capture_pending = false;
}
static bool capture_policy(bool allowed) {
    bool requested = allowed;
    allowed = allowed && !capture_failed && !quit && sl_events_foreground();
    capture_allowed = allowed;
    if (!allowed)
        capture_pending = false;
    if (!capture_hooked)
        return !requested;
    if (capture_redirected == allowed && !(!allowed && capture_restore))
        return !requested || allowed;
    Result rc = appletSetRequiresCaptureButtonShortPressedMessage(allowed);
#if NSL_DIAGNOSTICS
    char line[160];
    snprintf(line, sizeof(line), "{\"capture_route\":\"ipc\",\"enable\":%s,\"rc\":%u}",
             allowed ? "true" : "false", (unsigned)rc);
    sl_log(line); /* State transitions only; never emitted from the applet hook. */
#endif
    if (R_SUCCEEDED(rc)) {
        capture_redirected = allowed;
        capture_restore = allowed;
        return !requested || allowed;
    }
    capture_error = rc;
    capture_allowed = capture_pending = false;
    if (!capture_failed)
        sl_system_log("Capture Guide unavailable; restoring system screenshots");
    capture_failed = true;
    /* Failed enable has not changed applet state. Only a successful enable
     * creates a restoration obligation; unsupported optional APIs stay optional. */
    return false;
}
bool sl_events_capture_guide(bool allowed) {
#if NSL_DIAGNOSTICS
    if (capture_test_active)
        return !allowed; /* Explicit offline selftest owns notification IPC until completion. */
#endif
    return capture_policy(allowed);
}
bool sl_events_take_capture_guide(void) {
#if NSL_DIAGNOSTICS
    if (capture_test_active)
        return false; /* Platform selftest must never create a host Guide event. */
    if (capture_notifications != capture_notifications_reported) {
        char line[192];
        snprintf(line, sizeof(line), "{\"capture_route\":\"notification\",\"count\":%u,\"allowed\":%s,\"pending\":%s}",
                 capture_notifications, capture_allowed ? "true" : "false",
                 capture_pending ? "true" : "false");
        sl_log(line); /* Coalesced by the existing main owner. */
        capture_notifications_reported = capture_notifications;
    }
#endif
    bool pending = capture_pending && capture_allowed && sl_events_foreground() && !quit;
    capture_pending = false;
    return pending;
}
#if NSL_DIAGNOSTICS
bool sl_events_capture_probe_begin(void) {
    if (capture_test_active)
        return false;
    capture_test_active = true;
    capture_test_messages = 0;
    if (capture_policy(true))
        return true;
    capture_policy(false);
    capture_test_active = false;
    return false;
}
unsigned sl_events_capture_probe_messages(void) {
    return capture_test_messages;
}
bool sl_events_capture_probe_end(void) {
    bool restored = capture_policy(false);
    capture_test_active = false;
    capture_pending = false;
    return restored;
}
/* The API generates a SYSTEM Capture-short action, not a physical button.
 * Keep its result distinct from real-device screenshot/host-overlay evidence. */
bool sl_events_capture_selftest_tick(uint64_t now) {
    static unsigned stage;
    static uint64_t deadline;
    Result rc = 0;
    const char *error = NULL;
    if (!stage) {
        capture_test_active = true;
        capture_test_messages = 0;
        if (!hosversionAtLeast(6, 0, 0))
            error = "unsupported_firmware";
        else if (!sl_events_foreground())
            error = "not_in_focus";
        else if (!capture_policy(true)) {
            rc = capture_error;
            error = "enable_failed";
        } else {
            rc = appletPerformSystemButtonPressingIfInFocus(AppletSystemButtonType_CaptureButtonShortPressing);
            if (R_FAILED(rc))
                error = "trigger_on_failed";
            else {
                sl_log("{\"test\":\"capture_guide\",\"stage\":\"trigger_on\",\"rc\":0}");
                stage = 1;
                deadline = now + 1500;
            }
        }
    } else if (stage == 1 && capture_test_messages) {
        if (!capture_policy(false)) {
            rc = capture_error;
            error = "restore_failed";
        } else {
            capture_test_messages = 0;
            rc = appletPerformSystemButtonPressingIfInFocus(AppletSystemButtonType_CaptureButtonShortPressing);
            if (R_FAILED(rc))
                error = "trigger_off_failed";
            else {
                sl_log("{\"test\":\"capture_guide\",\"stage\":\"hook_on_restore_trigger_off\",\"rc\":0}");
                stage = 2;
                deadline = now + 1500;
            }
        }
    } else if (stage == 1 && now >= deadline)
        error = "hook_timeout";
    else if (stage == 2 && capture_test_messages)
        error = "hook_after_restore";
    else if (stage == 2 && now >= deadline && sl_events_foreground()) {
        sl_log("{\"test\":\"capture_guide\",\"stage\":\"complete\",\"api_hook\":true,\"off_hook_absent\":true,\"physical_key_verified\":false,\"album_verified\":false,\"host_overlay_verified\":false}");
        capture_test_active = false;
        capture_pending = false;
        stage = 0;
        return true;
    }
    if (!error && !sl_events_foreground())
        error = "focus_lost";
    if (error) {
        char line[256];
        snprintf(line, sizeof(line), "{\"test\":\"capture_guide\",\"stage\":\"error\",\"error\":\"%s\",\"rc\":%u}", error, (unsigned)rc);
        sl_log(line);
        capture_policy(false); /* Normal teardown retries a failed restore. */
        capture_test_active = false;
        capture_pending = false;
        stage = 0;
        return true;
    }
    return false;
}
#endif
void sl_events_shutdown(void) {
    if (!capture_hooked)
        return;
    capture_allowed = capture_pending = false;
    /* A failed restore must not silently return dirty applet state to hbmenu.
     * Bounded retries; failure terminates instead of returning to the loader. */
    for (unsigned attempt = 0; capture_restore && attempt < 3; ++attempt) {
        Result rc = appletSetRequiresCaptureButtonShortPressedMessage(false);
        if (R_SUCCEEDED(rc))
            capture_redirected = capture_restore = false;
        else
            capture_error = rc;
    }
    if (capture_restore)
        diagAbortWithResult(capture_error);
    appletUnhook(&capture_hook);
    capture_hooked = false;
    capture_failed = false;
}
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
    if (capture_hooked)
        sl_events_shutdown();
    foreground = true;
    quit = touch_polled = false;
    capture_pending = capture_allowed = capture_redirected = capture_restore = false;
    capture_failed = false;
    capture_error = 0;
#if NSL_DIAGNOSTICS
    capture_test_active = false;
    capture_test_messages = 0;
    capture_notifications = capture_notifications_reported = 0;
#endif
    if (hosversionAtLeast(3, 0, 0)) {
        appletHook(&capture_hook, capture_message, NULL);
        capture_hooked = true;
    }
#if NSL_GFX_DEKO
    previous = (HidTouchScreenState){0};
    touch_count = touch_cursor = 0;
#endif
    hidInitializeTouchScreen();
}
bool sl_events_foreground(void) {
    return appletGetFocusState() == AppletFocusState_InFocus;
}
bool sl_events_keyboard_focus(void) {
    /* deko owns no SDL window; libnx application input focus is this backend's
     * equivalent fact, separate from Remote Play's pause state. */
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
