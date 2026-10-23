#include "system_buttons_probe.h"
#include "diagnostic_log.h"
#include "platform/events.h"
#include <switch.h>
#include <stdalign.h>
#include <stdio.h>

/* Matches switchbrew's hid/hdls example: page-aligned 0x1000 work memory,
 * dedicated FullKey device, neutral -> detach -> release -> hiddbgExit.
 * No appletGetMessage, workers, sleeps, host sessions, or long-HOME blocking. */
enum phase {
    START, HID_INIT, HID_ACTIVATE, HID_EVENT, HOME_BASELINE, HOME_BLOCK, HOME_VERIFY,
    DEBUG_INIT, WORK_ATTACH, DEVICE_ATTACH, DEVICE_NEUTRAL, HOME_START,
    HOME_DOWN, HOME_RELEASED, CAPTURE_BEGIN, CAPTURE_DOWN, CAPTURE_RELEASED,
    CAPTURE_WAIT, CLEANUP, DONE
};
static struct {
    enum phase phase;
    bool started, hidsys, home_active, event_open, hiddbg, work, device, blocking;
    bool baseline_known, baseline_blocked, block_confirmed, focus_ok;
    bool home_available, home_down, home_up, home_verified;
    bool logged_down, logged_up;
    bool capture_owned, capture_first, capture_second, cleanup_ok;
    uint64_t due, sample, last_buttons;
    unsigned trial, capture_before;
    unsigned event_signals;
    Event event;
    HiddbgHdlsSessionId session;
    HiddbgHdlsHandle handle;
} probe;
static alignas(0x1000) unsigned char workmem[0x1000];

static void result(const char *stage, Result rc) {
    char line[192];
    snprintf(line, sizeof(line), "{\"test\":\"system_buttons\",\"stage\":\"%s\",\"rc\":%u}",
             stage, (unsigned)rc);
    sl_log(line);
}
static void flag(const char *stage, bool value) {
    char line[192];
    snprintf(line, sizeof(line), "{\"test\":\"system_buttons\",\"stage\":\"%s\",\"value\":%s}",
             stage, value ? "true" : "false");
    sl_log(line);
}
static Result set_buttons(u64 buttons) {
    HiddbgHdlsState state = {0};
    state.battery_level = 4;
    state.flags = 1; /* IsPowered, per libnx HiddbgHdlsState documentation. */
    state.buttons = buttons;
    return hiddbgSetHdlsState(probe.handle, &state);
}
static void sample_home(void) {
    if (!probe.home_active || !hidGetSharedmemAddr())
        return;
    HidHomeButtonState states[17];
    size_t count = hidGetHomeButtonStates(states, 17);
    /* libnx returns newest first. Traverse forward in sampling order so a
     * press/release both present in one ring read are retained. */
    for (size_t n = count; n; --n) {
        const HidHomeButtonState *s = &states[n - 1];
        if (s->sampling_number <= probe.sample)
            continue;
        probe.home_available = true;
        probe.sample = s->sampling_number;
        probe.last_buttons = s->buttons;
        if (probe.phase != HOME_DOWN && probe.phase != HOME_RELEASED)
            continue;
        if (s->buttons)
            probe.home_down = true;
        if (probe.home_down && !s->buttons && probe.phase == HOME_RELEASED)
            probe.home_up = true;
        char line[208];
        /* At most two transition records: no high-rate sharedmem log stream. */
        if ((s->buttons && !probe.logged_down) || (probe.home_up && !probe.logged_up)) {
            snprintf(line, sizeof(line),
                     "{\"test\":\"system_buttons\",\"stage\":\"home_sample\",\"sample\":%llu,\"buttons\":%llu}",
                     (unsigned long long)s->sampling_number, (unsigned long long)s->buttons);
            sl_log(line);
            if (s->buttons) probe.logged_down = true;
            if (probe.home_up) probe.logged_up = true;
        }
    }
}
void sl_system_buttons_probe_cleanup(void) {
    if (!probe.started || probe.phase == DONE)
        return;
    Result fatal = 0;
    probe.cleanup_ok = true;
    if (probe.device) {
        Result rc = set_buttons(0);
        result("cleanup_neutral", rc);
        Result detach = 0;
        for (unsigned n = 0; n < 3; ++n) {
            detach = hiddbgDetachHdlsVirtualDevice(probe.handle);
            result("cleanup_detach", detach);
            if (R_SUCCEEDED(detach)) break;
        }
        if (R_FAILED(detach)) { probe.cleanup_ok = false; fatal = detach; }
        probe.device = false;
    }
    if (probe.work) {
        Result rc = hiddbgReleaseHdlsWorkBuffer(probe.session);
        result("cleanup_workbuffer", rc);
        /* libnx closes its transfer-memory handle even when IPC fails. */
        if (R_FAILED(rc)) { probe.cleanup_ok = false; fatal = rc; }
        probe.work = false;
    }
    if (probe.capture_owned) {
        bool restored = false;
        for (unsigned n = 0; n < 3 && !restored; ++n)
            restored = sl_events_capture_probe_end();
        flag("cleanup_capture_restored", restored);
        if (!restored) probe.cleanup_ok = false;
        /* events shutdown owns its successful-enable restoration obligation. */
        probe.capture_owned = false;
    }
    if (probe.event_open) {
        eventClose(&probe.event);
        probe.event_open = false;
        flag("cleanup_event_closed", true);
    }
    if (probe.hidsys) {
        hidsysExit();
        probe.hidsys = false;
        flag("cleanup_hidsys_closed", true);
    }
    if (probe.hiddbg) {
        hiddbgExit();
        probe.hiddbg = false;
        flag("cleanup_hiddbg_closed", true);
    }
    if (probe.blocking) {
        Result rc = 0;
        for (unsigned n = 0; n < 3; ++n) {
            rc = appletEndBlockingHomeButton();
            result("cleanup_home_end", rc);
            if (R_SUCCEEDED(rc)) break;
        }
        if (R_FAILED(rc)) { probe.cleanup_ok = false; fatal = rc; }
        probe.blocking = false;
        bool blocked = true;
        rc = appletIsHomeButtonShortPressedBlocked(&blocked);
        result("cleanup_home_query", rc);
        flag("home_restore_query_verified", R_SUCCEEDED(rc) && !blocked);
        /* Getter rejection is a query capability limit, not failed End IPC. */
        if (R_SUCCEEDED(rc) && blocked) {
            probe.cleanup_ok = false;
            if (R_SUCCEEDED(fatal))
                fatal = MAKERESULT(Module_Libnx, LibnxError_BadInput);
        }
    }
    flag("home_event_observed", probe.event_signals != 0);
    sl_log("{\"test\":\"system_buttons\",\"stage\":\"evidence_boundary\",\"physical_key_verified\":false,\"album_verified\":false,\"host_overlay_verified\":false}");
    char line[224];
    snprintf(line, sizeof(line),
             "{\"test\":\"system_buttons\",\"stage\":\"complete\",\"home_virtual_read\":%s,\"focus_preserved\":%s,\"capture_first_hook\":%s,\"capture_second_hook\":%s,\"cleanup_ok\":%s}",
             probe.home_verified ? "true" : "false", probe.focus_ok ? "true" : "false",
             probe.capture_first ? "true" : "false", probe.capture_second ? "true" : "false",
             probe.cleanup_ok ? "true" : "false");
    sl_log(line);
    probe.phase = DONE;
    /* Only successfully acquired system state with failed bounded cleanup can
     * block loader return. Optional API denial never reaches this path. */
    if (R_FAILED(fatal))
        diagAbortWithResult(fatal);
}
bool sl_system_buttons_probe_tick(uint64_t now) {
    Result rc;
    if (probe.phase == DONE)
        return true;
    if (!probe.started) {
        probe.started = true;
        char line[144];
        snprintf(line, sizeof(line),
                 "{\"test\":\"system_buttons\",\"stage\":\"environment\",\"applet_type\":%u,\"hos_version\":%u}",
                 (unsigned)appletGetAppletType(), (unsigned)hosversionGet());
        sl_log(line);
        probe.focus_ok = appletGetFocusState() == AppletFocusState_InFocus;
        flag("focus_initial", probe.focus_ok);
    }
    if (appletGetFocusState() != AppletFocusState_InFocus) {
        probe.focus_ok = false;
        probe.phase = CLEANUP;
    }
    if (probe.event_open && R_SUCCEEDED(eventWait(&probe.event, 0)))
        ++probe.event_signals;
    sample_home();
    switch (probe.phase) {
    case START:
        probe.phase = HID_INIT;
        break;
    case HID_INIT:
        rc = hidsysInitialize();
        result("hidsys_init", rc);
        probe.hidsys = R_SUCCEEDED(rc);
        probe.phase = probe.hidsys ? HID_ACTIVATE : HOME_BASELINE;
        break;
    case HID_ACTIVATE:
        rc = hidsysActivateHomeButton();
        result("hidsys_activate_home", rc);
        probe.home_active = R_SUCCEEDED(rc);
        probe.phase = HID_EVENT;
        break;
    case HID_EVENT:
        rc = hidsysAcquireHomeButtonEventHandle(&probe.event, true);
        result("hidsys_home_event", rc);
        probe.event_open = R_SUCCEEDED(rc);
        probe.phase = HOME_BASELINE;
        break;
    case HOME_BASELINE:
        rc = appletIsHomeButtonShortPressedBlocked(&probe.baseline_blocked);
        result("home_block_baseline", rc);
        probe.baseline_known = R_SUCCEEDED(rc);
        flag("home_baseline_blocked", probe.baseline_known && probe.baseline_blocked);
        probe.phase = probe.baseline_known && probe.baseline_blocked ? DEBUG_INIT : HOME_BLOCK;
        break;
    case HOME_BLOCK:
        rc = appletBeginBlockingHomeButton(0);
        result("home_block_begin", rc);
        probe.blocking = R_SUCCEEDED(rc);
        probe.phase = HOME_VERIFY;
        break;
    case HOME_VERIFY: {
        bool blocked = false;
        rc = appletIsHomeButtonShortPressedBlocked(&blocked);
        result("home_block_query", rc);
        probe.block_confirmed = probe.blocking && probe.baseline_known &&
                                !probe.baseline_blocked && R_SUCCEEDED(rc) && blocked;
        flag("home_block_confirmed", probe.block_confirmed);
        probe.phase = DEBUG_INIT;
        break;
    }
    case DEBUG_INIT:
        rc = hiddbgInitialize();
        result("hiddbg_init", rc);
        probe.hiddbg = R_SUCCEEDED(rc);
        probe.phase = probe.hiddbg ? WORK_ATTACH : CLEANUP;
        break;
    case WORK_ATTACH:
        rc = hiddbgAttachHdlsWorkBuffer(&probe.session, workmem, sizeof(workmem));
        result("hdls_workbuffer", rc);
        probe.work = R_SUCCEEDED(rc);
        probe.phase = probe.work ? DEVICE_ATTACH : CLEANUP;
        break;
    case DEVICE_ATTACH: {
        HiddbgHdlsDeviceInfo device = {0};
        device.deviceType = HidDeviceType_FullKey3;
        device.npadInterfaceType = HidNpadInterfaceType_Bluetooth;
        rc = hiddbgAttachHdlsVirtualDevice(&probe.handle, &device);
        result("hdls_device", rc);
        probe.device = R_SUCCEEDED(rc);
        probe.phase = probe.device ? DEVICE_NEUTRAL : CLEANUP;
        break;
    }
    case DEVICE_NEUTRAL:
        rc = set_buttons(0);
        result("hdls_neutral", rc);
        probe.due = now + 150;
        probe.phase = R_SUCCEEDED(rc) ? HOME_START : CLEANUP;
        break;
    case HOME_START:
        if (now < probe.due) break;
        flag("home_raw_samples_available", probe.home_available);
        {
            char line[192];
            snprintf(line, sizeof(line),
                     "{\"test\":\"system_buttons\",\"stage\":\"home_raw_baseline\",\"sample\":%llu,\"buttons\":%llu}",
                     (unsigned long long)probe.sample, (unsigned long long)probe.last_buttons);
            sl_log(line); /* Shared-memory baseline, not a physical press claim. */
        }
        if (!probe.block_confirmed || !probe.home_available || probe.last_buttons) {
            flag("home_injection_skipped", true);
            probe.phase = CAPTURE_BEGIN;
            break;
        }
        rc = set_buttons(HiddbgNpadButton_Home);
        result("hdls_home_down", rc);
        probe.due = now + 120;
        probe.phase = R_SUCCEEDED(rc) ? HOME_DOWN : CLEANUP;
        break;
    case HOME_DOWN:
        if (now < probe.due) break;
        rc = set_buttons(0);
        result("hdls_home_up", rc);
        probe.due = now + 600;
        probe.phase = R_SUCCEEDED(rc) ? HOME_RELEASED : CLEANUP;
        break;
    case HOME_RELEASED:
        if (now < probe.due) break;
        probe.home_verified = probe.home_down && probe.home_up && probe.focus_ok;
        flag("home_virtual_read_verified", probe.home_verified);
        probe.phase = CAPTURE_BEGIN;
        break;
    case CAPTURE_BEGIN:
        probe.capture_owned = sl_events_capture_probe_begin();
        flag("capture_route_begin", probe.capture_owned);
        probe.trial = 1;
        probe.phase = probe.capture_owned ? CAPTURE_DOWN : CLEANUP;
        break;
    case CAPTURE_DOWN:
        probe.capture_before = sl_events_capture_probe_messages();
        rc = set_buttons(HiddbgNpadButton_Capture);
        result(probe.trial == 1 ? "hdls_capture_first_down" : "hdls_capture_second_down", rc);
        probe.due = now + 80;
        probe.phase = R_SUCCEEDED(rc) ? CAPTURE_RELEASED : CLEANUP;
        break;
    case CAPTURE_RELEASED:
        if (now < probe.due) break;
        rc = set_buttons(0);
        result(probe.trial == 1 ? "hdls_capture_first_up" : "hdls_capture_second_up", rc);
        probe.due = now + 1000;
        probe.phase = R_SUCCEEDED(rc) ? CAPTURE_WAIT : CLEANUP;
        break;
    case CAPTURE_WAIT: {
        if (now < probe.due) break;
        unsigned count = sl_events_capture_probe_messages();
        bool received = count > probe.capture_before;
        char line[208];
        snprintf(line, sizeof(line),
                 "{\"test\":\"system_buttons\",\"stage\":\"capture_hook\",\"trial\":%u,\"before\":%u,\"after\":%u,\"received\":%s}",
                 probe.trial, probe.capture_before, count, received ? "true" : "false");
        sl_log(line);
        if (probe.trial == 1) {
            probe.capture_first = received;
            probe.trial = 2;
            probe.phase = CAPTURE_DOWN;
        } else {
            probe.capture_second = received;
            probe.phase = CLEANUP;
        }
        break;
    }
    case CLEANUP:
        sl_system_buttons_probe_cleanup();
        break;
    case DONE:
        break;
    }
    return probe.phase == DONE;
}
