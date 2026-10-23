/* Real diagnostic state machine with fake libnx terminals. No hardware claim. */
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "../platforms/switch/system_buttons_probe.c"

static unsigned fail_op, op, begin_calls, home_down_calls, capture_down_calls, messages;
static unsigned end_failures, detach_failures, cleanup_phase, query_calls;
static bool query_supported, initially_blocked, blocked, active_sys, active_dbg;
static bool active_work, active_device, active_event, capture_route, capture_pending;
static bool states_available, ignore_first_capture, lose_focus, expect_fatal;
static bool complete, summary_home, summary_first, summary_second;
static bool evidence_boundary;
static u64 device_buttons, serial;
static AppletFocusState focus;
static jmp_buf abort_jump;

static Result operation(void) { return ++op == fail_op ? 123 : 0; }
void sl_log(const char *s) {
    assert(strlen(s) < 224); /* Persistent diagnostic queue must preserve JSON. */
    puts(s);
    if (strstr(s, "\"stage\":\"evidence_boundary\"")) {
        assert(strstr(s, "\"physical_key_verified\":false"));
        assert(strstr(s, "\"album_verified\":false"));
        evidence_boundary = true;
    }
    if (strstr(s, "\"stage\":\"complete\"")) {
        complete = true;
        summary_home = strstr(s, "\"home_virtual_read\":true") != NULL;
        summary_first = strstr(s, "\"capture_first_hook\":true") != NULL;
        summary_second = strstr(s, "\"capture_second_hook\":true") != NULL;
        assert(evidence_boundary);
    }
}
Result hidsysInitialize(void) {
    Result rc = operation(); active_sys = R_SUCCEEDED(rc); return rc;
}
void hidsysExit(void) {
    assert(active_sys && !active_event);
    active_sys = false;
    cleanup_phase = 4;
}
Result hidsysActivateHomeButton(void) { assert(active_sys); return operation(); }
Result hidsysAcquireHomeButtonEventHandle(Event *e, bool autoclear) {
    assert(active_sys && !autoclear);
    Result rc = operation();
    if (R_SUCCEEDED(rc)) { e->handle = 1; active_event = true; }
    return rc;
}
Result eventWait(Event *e, u64 timeout) { assert(e->handle && timeout == 0); return 0; }
void eventClose(Event *e) {
    assert(active_event && active_sys && e->handle);
    active_event = false; e->handle = 0; cleanup_phase = 3;
}
void *hidGetSharedmemAddr(void) { return states_available ? (void *)1 : NULL; }
size_t hidGetHomeButtonStates(HidHomeButtonState *s, size_t n) {
    assert(active_sys && n == 17);
    if (!states_available) return 0;
    s[0] = (HidHomeButtonState){++serial, device_buttons & HiddbgNpadButton_Home};
    return 1;
}
AppletFocusState appletGetFocusState(void) { return focus; }
unsigned appletGetAppletType(void) { return 0; }
unsigned hosversionGet(void) { return 0x140000; }
Result appletIsHomeButtonShortPressedBlocked(bool *out) {
    ++query_calls;
    if (!query_supported) return 456;
    *out = blocked;
    return 0;
}
Result appletBeginBlockingHomeButton(s64 value) {
    assert(value == 0 && !initially_blocked);
    ++begin_calls;
    Result rc = operation();
    if (R_SUCCEEDED(rc)) blocked = true;
    return rc;
}
Result appletEndBlockingHomeButton(void) {
    assert(blocked && !initially_blocked && !active_dbg && !active_sys && !active_event);
    if (end_failures) { --end_failures; return 789; }
    blocked = false; cleanup_phase = 6; return 0;
}
Result hiddbgInitialize(void) {
    Result rc = operation(); active_dbg = R_SUCCEEDED(rc); return rc;
}
void hiddbgExit(void) { assert(active_dbg && !active_work); active_dbg = false; cleanup_phase = 5; }
Result hiddbgAttachHdlsWorkBuffer(HiddbgHdlsSessionId *id, void *mem, size_t size) {
    assert(active_dbg && ((uintptr_t)mem % 0x1000) == 0 && size == 0x1000);
    Result rc = operation();
    if (R_SUCCEEDED(rc)) { active_work = true; id->id = 44; }
    return rc;
}
Result hiddbgReleaseHdlsWorkBuffer(HiddbgHdlsSessionId id) {
    assert(active_work && active_dbg && id.id == 44);
    active_device = active_work = false; device_buttons = 0;
    cleanup_phase = 2; return 0;
}
Result hiddbgAttachHdlsVirtualDevice(HiddbgHdlsHandle *h, const HiddbgHdlsDeviceInfo *d) {
    assert(active_work && d->deviceType == HidDeviceType_FullKey3 &&
           d->npadInterfaceType == HidNpadInterfaceType_Bluetooth);
    Result rc = operation();
    if (R_SUCCEEDED(rc)) { active_device = true; h->handle = 55; }
    return rc;
}
Result hiddbgDetachHdlsVirtualDevice(HiddbgHdlsHandle h) {
    assert(h.handle == 55 && active_device && !device_buttons && cleanup_phase == 0);
    if (detach_failures) { --detach_failures; return 789; }
    active_device = false; cleanup_phase = 1; return 0;
}
Result hiddbgSetHdlsState(HiddbgHdlsHandle h, const HiddbgHdlsState *s) {
    assert(active_device && h.handle == 55 && s->battery_level == 4 && s->flags == 1);
    Result rc = operation();
    if (R_FAILED(rc)) return rc;
    device_buttons = s->buttons;
    if (s->buttons & HiddbgNpadButton_Home) {
        /* Safety gate under test: no injection with an unverified block/read. */
        assert(blocked && query_supported && states_available && active_sys);
        ++home_down_calls;
        if (lose_focus) focus = AppletFocusState_OutOfFocus;
    }
    if (s->buttons & HiddbgNpadButton_Capture) {
        assert(capture_route);
        ++capture_down_calls;
        if (!ignore_first_capture || capture_down_calls != 1) capture_pending = true;
    }
    return 0;
}
bool sl_events_capture_probe_begin(void) { assert(!capture_route); capture_route = true; messages = 0; return true; }
unsigned sl_events_capture_probe_messages(void) { assert(capture_route); return messages; }
bool sl_events_capture_probe_end(void) {
    assert(capture_route && !active_device && !active_work);
    capture_route = false; capture_pending = false; return true;
}
_Noreturn void diagAbortWithResult(Result rc) {
    assert(expect_fatal && rc == 789 && !active_sys && !active_dbg && !active_work && !active_event);
    longjmp(abort_jump, 1);
}
static void reset(void) {
    memset(&probe, 0, sizeof(probe));
    fail_op = op = begin_calls = home_down_calls = capture_down_calls = messages = 0;
    end_failures = detach_failures = cleanup_phase = query_calls = 0;
    query_supported = states_available = true;
    initially_blocked = blocked = active_sys = active_dbg = active_work = false;
    active_device = active_event = capture_route = capture_pending = false;
    ignore_first_capture = lose_focus = expect_fatal = complete = evidence_boundary = false;
    summary_home = summary_first = summary_second = false;
    device_buttons = serial = 0;
    focus = AppletFocusState_InFocus;
}
static void run(void) {
    bool finished = false;
    for (uint64_t now = 0; now < 10000 && !finished; now += 20) {
        /* Stand-in for the existing main loop's next applet dispatch. */
        if (capture_pending) { if (messages < 2) ++messages; capture_pending = false; }
        finished = sl_system_buttons_probe_tick(now);
    }
    assert(finished && complete);
    assert(!active_sys && !active_dbg && !active_work && !active_device && !active_event);
    assert(!capture_route && !device_buttons && blocked == initially_blocked);
    sl_system_buttons_probe_cleanup(); /* Idempotent after normal completion. */
}
int main(void) {
    sl_system_buttons_probe_cleanup(); /* Early application init failure. */
    reset(); run();
    assert(home_down_calls == 1 && capture_down_calls == 2 && summary_home && summary_first && summary_second);
    assert(cleanup_phase == 6 && query_calls == 3);
    reset(); query_supported = false; run();
    assert(begin_calls == 1 && home_down_calls == 0 && !summary_home && summary_first && summary_second);
    reset(); states_available = false; run();
    assert(home_down_calls == 0 && !summary_home && summary_first && summary_second);
    reset(); initially_blocked = blocked = true; run();
    assert(!begin_calls && !home_down_calls && blocked && summary_first && summary_second);
    reset(); ignore_first_capture = true; run();
    assert(!summary_first && summary_second); /* A second hook cannot rewrite first-shot evidence. */
    reset(); lose_focus = true; run();
    assert(home_down_calls == 1 && !device_buttons && !summary_home && !capture_down_calls);
    /* Fail each acquisition/input IPC once: only acquired state is unwound. */
    for (unsigned n = 1; n <= 15; ++n) { reset(); fail_op = n; run(); }
    /* Exit midway through an injected down always sends neutral and cleans up. */
    reset();
    for (uint64_t now = 0; probe.phase != HOME_DOWN; now += 20)
        assert(!sl_system_buttons_probe_tick(now));
    sl_system_buttons_probe_cleanup();
    assert(complete && !blocked && !active_device && !device_buttons);
    reset(); end_failures = 3; expect_fatal = true;
    if (!setjmp(abort_jump)) { run(); assert(false); }
    assert(complete && !active_dbg && !active_sys);
    reset(); detach_failures = 3; expect_fatal = true;
    if (!setjmp(abort_jump)) { run(); assert(false); }
    puts("PASS diagnostic HOME safety gates, Capture first/second evidence, acquisition failure and cleanup");
    return 0;
}
