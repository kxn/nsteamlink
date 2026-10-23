/* Real Switch event backend with fake libnx service terminals; no device/IPC. */
#include "events_backend.h"
#include <switch.h>
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static AppletHookFn hook;
static void *hook_context;
static unsigned hooks, unhooks, enables, disables, logs;
static bool supported = true, fail_enable, system_redirected;
static unsigned fail_disable;
static AppletFocusState focus = AppletFocusState_InFocus;
static jmp_buf fatal;
static bool expect_fatal;
static bool selftest_complete;
extern bool sl_events_capture_selftest_tick(uint64_t);
extern bool sl_events_capture_probe_begin(void);
extern unsigned sl_events_capture_probe_messages(void);
extern bool sl_events_capture_probe_end(void);
void appletHook(AppletHookCookie *cookie, AppletHookFn fn, void *context) {
    (void)cookie;
    assert(!hook);
    hook = fn; hook_context = context; ++hooks;
}
void appletUnhook(AppletHookCookie *cookie) {
    (void)cookie;
    assert(hook && !system_redirected);
    hook = NULL; ++unhooks;
}
Result appletSetRequiresCaptureButtonShortPressedMessage(bool value) {
    if (value) {
        ++enables;
        if (fail_enable) return 123;
    } else {
        ++disables;
        if (fail_disable) { --fail_disable; return 456; }
    }
    system_redirected = value;
    return 0;
}
AppletFocusState appletGetFocusState(void) { return focus; }
bool hosversionAtLeast(unsigned a, unsigned b, unsigned c) {
    assert((a == 3 || a == 6) && !b && !c);
    return supported;
}
Result appletPerformSystemButtonPressingIfInFocus(AppletSystemButtonType type) {
    assert(type == AppletSystemButtonType_CaptureButtonShortPressing);
    if (system_redirected)
        hook(AppletHookType_OnCaptureButtonShortPressed, hook_context);
    return 0;
}
void sl_log(const char *text) {
    if (strstr(text, "\"stage\":\"complete\""))
        selftest_complete = true;
}
void hidInitializeTouchScreen(void) { }
void sl_system_log(const char *text) { assert(text); ++logs; }
_Noreturn void diagAbortWithResult(Result result) {
    assert(expect_fatal && result == 456 && system_redirected && hook);
    longjmp(fatal, 1);
}
static void press(void) { assert(hook); hook(AppletHookType_OnCaptureButtonShortPressed, hook_context); }
int main(void) {
    sl_events_shutdown(); /* Cleanup before initialization is safe. */
    supported = false;
    sl_events_init();
    assert(!hooks && !sl_events_capture_guide(true) && sl_events_capture_guide(false));
    sl_events_shutdown();
    assert(!enables && !disables); /* Unsupported optional API never causes an abort. */
    supported = true;
    sl_events_init();
    assert(hooks == 1 && !system_redirected);
    press(); assert(!sl_events_take_capture_guide());
    assert(sl_events_capture_guide(true) && system_redirected);
    press(); press(); assert(sl_events_take_capture_guide() && !sl_events_take_capture_guide());
    press();
    assert(sl_events_capture_guide(false) && !system_redirected && !sl_events_take_capture_guide());
    assert(sl_events_capture_guide(true));
    press(); focus = AppletFocusState_OutOfFocus;
    hook(AppletHookType_OnFocusState, hook_context);
    assert(!sl_events_take_capture_guide() && !sl_events_capture_guide(true) && !system_redirected);
    focus = AppletFocusState_InFocus;
    assert(sl_events_capture_guide(true));
    sl_events_shutdown(); sl_events_shutdown();
    assert(!system_redirected && unhooks == hooks);
    /* Failed enable leaves normal screenshots untouched; no off IPC/fatal needed. */
    fail_enable = true;
    sl_events_init();
    unsigned off_before = disables;
    assert(!sl_events_capture_guide(true) && !system_redirected);
    assert(!sl_events_capture_guide(true) && logs == 1);
    sl_events_shutdown();
    assert(disables == off_before && hooks == unhooks);
    fail_enable = false;
    sl_events_init();
    assert(sl_events_capture_guide(true));
    fail_disable = 1;
    assert(!sl_events_capture_guide(false) && system_redirected);
    press(); assert(!sl_events_take_capture_guide());
    sl_events_shutdown(); /* Retry restores screenshots before unhooking. */
    assert(!system_redirected && hooks == unhooks);
    sl_events_init(); assert(sl_events_capture_guide(true));
    fail_disable = 3;
    expect_fatal = true;
    if (!setjmp(fatal)) {
        sl_events_shutdown();
        abort();
    }
    expect_fatal = false;
    assert(hooks == unhooks + 1); /* Never claim cleanup succeeded after failed restore. */
    sl_events_shutdown(); /* Recover the terminal fixture after the expected abort. */
    assert(!system_redirected && hooks == unhooks);
    sl_events_init();
    assert(!sl_events_capture_selftest_tick(10) && system_redirected);
    assert(sl_events_capture_guide(false) && system_redirected); /* Ordinary offline gate cannot undo the diagnostic step. */
    assert(!sl_events_take_capture_guide()); /* No Guide controller event during this API-only test. */
    assert(!sl_events_capture_selftest_tick(11) && !system_redirected);
    assert(sl_events_capture_selftest_tick(1511) && selftest_complete);
    sl_events_shutdown();
    assert(!system_redirected && hooks == unhooks);
    /* The virtual-HID trial owns the route while the normal offline main loop
     * keeps its product gate OFF. Its messages must never reach host input. */
    sl_events_init();
    assert(sl_events_capture_probe_begin() && system_redirected);
    assert(!sl_events_capture_probe_begin());
    assert(sl_events_capture_guide(false) && system_redirected);
    press();
    assert(sl_events_capture_probe_messages() == 1 && !sl_events_take_capture_guide());
    press();
    assert(sl_events_capture_probe_messages() == 2 && !sl_events_take_capture_guide());
    press();
    assert(sl_events_capture_probe_messages() == 3); /* Keep a later trial observable. */
    assert(sl_events_capture_probe_end() && !system_redirected);
    assert(!sl_events_take_capture_guide());
    sl_events_shutdown();
    assert(hooks == unhooks);
    fail_enable = true;
    sl_events_init();
    assert(!sl_events_capture_probe_begin() && !system_redirected);
    assert(sl_events_capture_guide(false));
    sl_events_shutdown();
    fail_enable = false;
    assert(hooks == unhooks);
    puts("PASS Capture notification OFF/focus/unsupported/IPC failure and paired cleanup");
}
