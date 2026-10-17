/* Diagnostic-only linker wrappers around the real production application.
 * No test control endpoint, network mode, or driver is linked into nsteamlink.
 * UI/SDL actions and snapshots run on the existing main thread; SNS observations
 * are copied by its existing owner through atomics. No additional workers. */
#include "runtime_fixture.h"
#include "media.h"
#include "platform/runtime.h"
#include "platform/system.h"
#include "sns_backend.h"
#include <SDL.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>

int sl_live_printf(const char *, ...);
static char private_directory[192];
static uint32_t private_host;
static uint64_t began, sampled, phase_at, submitted_before, acked_before;
static uint32_t frames_before;
static uint64_t wire_before, wire_pressed, submitted_pressed, acked_pressed, sent_before,
    sent_pressed, giveups_before;
static uint64_t reported;
static unsigned phase, failure;
static sl_runtime *runtime;
static atomic_uint filtered_tx, filtered_rx, sns_flags, reliability_revision;
static atomic_uint_fast64_t observed_submitted, observed_acked, observed_sent, observed_giveups;
static atomic_uint observed_pending, observed_inflight;
static atomic_uint_fast64_t wire_report;
static atomic_size_t report_length;
int __real_IHS_HIDDeviceStartInputReports(IHS_HIDDevice *, size_t);
int __wrap_IHS_HIDDeviceStartInputReports(IHS_HIDDevice *device, size_t length) {
    int result = __real_IHS_HIDDeviceStartInputReports(device, length);
    if (!result)
        atomic_store(&report_length, length);
    sl_live_printf("RUNTIME_FIXTURE_START_INPUT length=%zu result=%d\n", length, result);
    return result;
}
bool __real_IHS_HIDSDLGetLastSubmittedReport(IHS_Session *, IHS_HIDSDLLastSubmitted *);
bool __wrap_IHS_HIDSDLGetLastSubmittedReport(IHS_Session *session, IHS_HIDSDLLastSubmitted *out) {
    bool result = __real_IHS_HIDSDLGetLastSubmittedReport(session, out);
    if (result && out)
        atomic_store(&wire_report, (out->seq << 16) | out->buttons);
    return result;
}
static atomic_uint traced_events;
static atomic_uint flush_calls, flush_queued, input_enabled, handled_events, gate_enabled,
    gate_closes;
/* Diagnostics only; preserve the original calls and their return values. */
bool IHS_SessionInputEnabled(IHS_Session *);
bool __real_IHS_HIDFlushSDLGameControllers(IHS_Session *);
bool __wrap_IHS_HIDFlushSDLGameControllers(IHS_Session *session) {
    atomic_fetch_add(&flush_calls, 1);
    atomic_store(&input_enabled, IHS_SessionInputEnabled(session));
    bool result = __real_IHS_HIDFlushSDLGameControllers(session);
    if (result)
        atomic_fetch_add(&flush_queued, 1);
    return result;
}
bool __real_IHS_HIDHandleSDLEvent(IHS_Session *, const SDL_Event *);
bool __wrap_IHS_HIDHandleSDLEvent(IHS_Session *session, const SDL_Event *e) {
    bool result = __real_IHS_HIDHandleSDLEvent(session, e);
    if (result)
        atomic_fetch_add(&handled_events, 1);
    if ((e->type == SDL_CONTROLLERBUTTONDOWN || e->type == SDL_CONTROLLERBUTTONUP) &&
        atomic_fetch_add(&traced_events, 1) < 4)
        sl_live_printf(
            "RUNTIME_FIXTURE_HID_EVENT time=%llu code=%u value=%u accepted=%d gate=%u enabled=%d\n",
            (unsigned long long)sl_system_now(), e->cbutton.button, e->cbutton.state, result,
            atomic_load(&gate_enabled), IHS_SessionInputEnabled(session));
    return result;
}
void __real_sl_media_gate(bool);
void __wrap_sl_media_gate(bool enabled) {
    if (atomic_exchange(&gate_enabled, enabled) && !enabled)
        atomic_fetch_add(&gate_closes, 1);
    __real_sl_media_gate(enabled);
}
void __real_IHS_SessionGetReliabilityStats(IHS_Session *, IHS_SessionReliabilityStats *);
void __wrap_IHS_SessionGetReliabilityStats(IHS_Session *session, IHS_SessionReliabilityStats *out) {
    __real_IHS_SessionGetReliabilityStats(session, out);
    if (!out)
        return;
    /* The runtime owner already samples these counters. The raw media snapshot
     * deliberately does not contain them; publish only this copied observation. */
    atomic_fetch_add(&reliability_revision, 1);
    atomic_store(&observed_submitted, out->hidSubmitted);
    atomic_store(&observed_acked, out->hidAcknowledged);
    atomic_store(&observed_sent, out->hidSent);
    atomic_store(&observed_giveups, out->reliableGiveUps);
    atomic_store(&observed_pending, out->hidPending);
    atomic_store(&observed_inflight, out->hidInFlight);
    atomic_fetch_add(&reliability_revision, 1);
}
static bool menu_keys_released, force_sdr;
static SDL_JoystickID controller_id = -1;

bool sl_runtime_fixture_prepare(const char *directory, const sl_auth_store *store,
                                const char *lan_host, bool sdr_only) {
    if (!directory || strlen(directory) >= sizeof(private_directory) || !store ||
        store->registry.selected < 0 || store->registry.selected >= store->registry.count)
        return false;
    const sl_host *h = &store->registry.hosts[store->registry.selected];
    struct in_addr address;
    if (!h->paired || !lan_host || !inet_aton(lan_host, &address))
        return false;
    private_host = ntohl(address.s_addr);
    if (!private_host || private_host == UINT32_MAX)
        return false;
    strcpy(private_directory, directory);
    force_sdr = sdr_only;
    began = sl_system_now();
    return true;
}
const char *__wrap_sl_system_data_dir(void) {
    return private_directory;
}
/* Never let the updater replace a private NRO containing test credentials. */
bool __wrap_sl_update_config_load(const char *directory) {
    (void)directory;
    return false;
}

bool __real_sl_system_running(void);
bool __wrap_sl_system_running(void) {
    if (failure)
        return false;
    if (!__real_sl_system_running()) {
        if (!failure && phase != 8)
            failure = 1;
        return false;
    }
    if (began && sl_system_now() - began >= 90000) {
        if (!failure)
            failure = 2;
        sl_live_printf("RUNTIME_FIXTURE_TIMEOUT phase=%u\n", phase);
        return false;
    }
    return true;
}
sl_runtime *__real_sl_runtime_create(const sl_auth_store *);
sl_runtime *__wrap_sl_runtime_create(const sl_auth_store *store) {
    runtime = __real_sl_runtime_create(store);
    return runtime;
}
sl_sns *__real_sl_sns_create(const IHS_ClientConfig *, const sl_remote_material *, bool, char *,
                             size_t);
sl_sns *__wrap_sl_sns_create(const IHS_ClientConfig *config, const sl_remote_material *material,
                             bool share_ip, char *error, size_t size) {
    /* Explicit diagnostic topology only. The production application always
     * retains its automatic ICE/SDR configuration. */
    return __real_sl_sns_create(config, material, force_sdr ? false : share_ip, error, size);
}
void __real_sl_sns_update(sl_sns *, uint64_t);
void __wrap_sl_sns_update(sl_sns *sns, uint64_t now) {
    __real_sl_sns_update(sns, now);
    sl_sns_stats s = {0};
    sl_sns_get_stats(sns, &s);
    /* Latched positive observations survive normal stop/destroy. */
    if (sl_sns_get_state(sns) == SL_SNS_CONNECTED)
        atomic_fetch_or(&sns_flags, 1u | (s.authenticated ? 2u : 0) | (s.relayed ? 4u : 0));
}
static void key(SDL_Keycode code, bool down) {
    SDL_Event e = {0};
    e.type = down ? SDL_KEYDOWN : SDL_KEYUP;
    e.key.state = down ? SDL_PRESSED : SDL_RELEASED;
    e.key.keysym.sym = code;
    if (SDL_PushEvent(&e) < 0)
        failure = 3;
}
static void tap(SDL_Keycode code) {
    key(code, true);
    key(code, false);
}
static void button(bool down) {
    SDL_Event e = {0};
    e.type = down ? SDL_CONTROLLERBUTTONDOWN : SDL_CONTROLLERBUTTONUP;
    e.cbutton.which = controller_id;
    e.cbutton.button = SDL_CONTROLLER_BUTTON_DPAD_RIGHT;
    e.cbutton.state = down ? SDL_PRESSED : SDL_RELEASED;
    if (SDL_PushEvent(&e) < 0)
        failure = 4;
}
static void click(int x, int y) {
    SDL_Event e = {0};
    e.type = SDL_MOUSEBUTTONDOWN;
    e.button.button = SDL_BUTTON_LEFT;
    e.button.state = SDL_PRESSED;
    e.button.x = x;
    e.button.y = y;
    if (SDL_PushEvent(&e) < 0)
        failure = 5;
    e.type = SDL_MOUSEBUTTONUP;
    e.button.state = SDL_RELEASED;
    if (SDL_PushEvent(&e) < 0)
        failure = 5;
}
static void enter(unsigned next, uint64_t now) {
    phase = next;
    phase_at = now;
    sl_live_printf("RUNTIME_FIXTURE_STAGE=%u\n", phase);
}
void __real_sl_ui_tick(sl_ui_model *, uint64_t);
void __wrap_sl_ui_tick(sl_ui_model *ui, uint64_t now) {
    __real_sl_ui_tick(ui, now);
    if (now - sampled < 50 || failure)
        return;
    sampled = now;
    stream_media_snapshot s = {0};
    stream_media_get_snapshot(&s);
    unsigned revision = atomic_load(&reliability_revision);
    if (revision & 1)
        return;
    s.reliability.hidSubmitted = atomic_load(&observed_submitted);
    s.reliability.hidAcknowledged = atomic_load(&observed_acked);
    s.reliability.hidSent = atomic_load(&observed_sent);
    s.reliability.reliableGiveUps = atomic_load(&observed_giveups);
    s.reliability.hidPending = atomic_load(&observed_pending);
    s.reliability.hidInFlight = atomic_load(&observed_inflight);
    if (revision != atomic_load(&reliability_revision))
        return;
    sl_runtime_facts f = {0};
    bool facts = sl_runtime_read_facts(runtime, &f);
    uint64_t packed_wire = atomic_load(&wire_report), wire_seq = packed_wire >> 16;
    uint16_t wire_buttons = (uint16_t)packed_wire;
    bool pressed = (wire_buttons & (1u << SDL_CONTROLLER_BUTTON_DPAD_RIGHT)) != 0;
    if ((phase == 2 || phase == 3) && s.reliability.reliableGiveUps > giveups_before) {
        failure = 8;
        sl_live_printf("RUNTIME_FIXTURE_ERROR reliable_giveup=1\n");
        return;
    }
    if (ui->page == SL_ERROR || s.render_failed) {
        failure = 6;
        sl_live_printf("RUNTIME_FIXTURE_ERROR page=%u render=%d\n", ui->page, s.render_failed);
        return;
    }
    switch (phase) {
    case 0: {
        int i = ui->store.registry.selected;
        sl_host *h = i >= 0 && i < ui->store.registry.count ? &ui->store.registry.hosts[i] : NULL;
        if (ui->page == SL_HOME && h && h->paired && sl_host_online(h, now)) {
            tap(SDLK_y);
            enter(1, now);
        }
        break;
    }
    case 1:
        if (now - reported >= 2000) {
            reported = now;
            sl_live_printf("RUNTIME_FIXTURE_READY_WAIT length=%zu sub=%llu displayed=%u\n",
                           atomic_load(&report_length),
                           (unsigned long long)s.reliability.hidSubmitted, s.displayed_frames);
        }
        if (ui->page == SL_STREAM && s.displayed_frames >= 60 &&
            (atomic_load(&sns_flags) & 3) == 3 && atomic_load(&report_length) &&
            s.reliability.hidSubmitted && !s.reliability.hidPending && !s.reliability.hidInFlight) {
            for (int i = 0; i < SDL_NumJoysticks(); ++i)
                if (SDL_IsGameController(i)) {
                    controller_id = SDL_JoystickGetDeviceInstanceID(i);
                    break;
                }
            if (controller_id < 0) {
                failure = 7;
                break;
            }
            submitted_before = s.reliability.hidSubmitted;
            sent_before = s.reliability.hidSent;
            giveups_before = s.reliability.reliableGiveUps;
            acked_before = s.reliability.hidAcknowledged;
            frames_before = s.displayed_frames;
            wire_before = wire_seq;
            sl_live_printf("RUNTIME_FIXTURE_MEDIA decoded=%u displayed=%u hardware=%d audio=%u "
                           "audio_errors=%u sns=%u\n",
                           s.decoded_frames, s.displayed_frames, s.render.hardware, s.audio_frames,
                           s.audio_decode_errors, atomic_load(&sns_flags));
            button(true);
            enter(2, now);
        }
        break;
    case 2:
        if (wire_seq > wire_before && pressed && s.reliability.hidSubmitted > submitted_before &&
            s.reliability.hidSent > sent_before && s.reliability.hidAcknowledged > acked_before &&
            !s.reliability.hidPending && !s.reliability.hidInFlight) {
            sl_live_printf("RUNTIME_FIXTURE_PRESS_ACK seq=%llu buttons=%u\n",
                           (unsigned long long)wire_seq, wire_buttons);
            wire_pressed = wire_seq;
            submitted_pressed = s.reliability.hidSubmitted;
            sent_pressed = s.reliability.hidSent;
            acked_pressed = s.reliability.hidAcknowledged;
            button(false);
            enter(3, now);
        }
        /* Bounded diagnostics while holding the synthetic press. */
        if (phase == 2 && now - reported >= 1000) {
            reported = now;
            sl_live_printf("RUNTIME_FIXTURE_PRESS_WAIT seq=%llu buttons=%u sub=%llu gate=%u "
                           "flush=%u queued=%u enabled=%u\n",
                           (unsigned long long)wire_seq, wire_buttons,
                           (unsigned long long)s.reliability.hidSubmitted,
                           atomic_load(&gate_enabled), atomic_load(&flush_calls),
                           atomic_load(&flush_queued), atomic_load(&input_enabled));
        }
        break;
    case 3:
        if (now - reported >= 1000) {
            reported = now;
            sl_live_printf("RUNTIME_FIXTURE_INPUT_WAIT sub=%llu ack=%llu pending=%u flight=%u "
                           "gate=%u closes=%u flush=%u queued=%u enabled=%u events=%u page=%u\n",
                           (unsigned long long)s.reliability.hidSubmitted,
                           (unsigned long long)s.reliability.hidAcknowledged,
                           s.reliability.hidPending, s.reliability.hidInFlight,
                           atomic_load(&gate_enabled), atomic_load(&gate_closes),
                           atomic_load(&flush_calls), atomic_load(&flush_queued),
                           atomic_load(&input_enabled), atomic_load(&handled_events), ui->page);
        }
        if (wire_seq > wire_pressed && !pressed && s.reliability.hidSubmitted > submitted_pressed &&
            s.reliability.hidSent > sent_pressed && s.reliability.hidAcknowledged > acked_pressed &&
            !s.reliability.hidPending && !s.reliability.hidInFlight &&
            s.displayed_frames >= frames_before + 30 && s.audio_frames >= 30 &&
            !s.audio_decode_errors) {
            sl_live_printf("RUNTIME_FIXTURE_INPUT submitted_delta=%llu ack_delta=%llu "
                           "new_frames=%u release_seq=%llu buttons=%u\n",
                           (unsigned long long)(s.reliability.hidSubmitted - submitted_before),
                           (unsigned long long)(s.reliability.hidAcknowledged - acked_before),
                           s.displayed_frames - frames_before, (unsigned long long)wire_seq,
                           wire_buttons);
            key(SDLK_MINUS, true);
            key(SDLK_EQUALS, true);
            enter(4, now);
        }
        break;
    case 4:
        if (now - phase_at >= 1000 && !menu_keys_released) {
            key(SDLK_MINUS, false);
            key(SDLK_EQUALS, false);
            menu_keys_released = true;
        }
        if (menu_keys_released && ui->page == SL_MENU) {
            /* Hit the actual current Disconnect row, rather than bypassing
             * layout/input_router with a direct model action. */
            for (int i = 0; i < ui->layout.count; ++i) {
                const sl_control *c = &ui->layout.controls[i];
                if (c->action == SL_OPEN_DISCONNECT) {
                    click(c->x + c->w / 2, c->y + c->h / 2);
                    enter(5, now);
                    break;
                }
            }
        }
        break;
    case 5:
        if (ui->page == SL_DISCONNECT) {
            tap(SDLK_RETURN);
            enter(6, now);
        }
        break;
    case 6:
        if (ui->page == SL_HOME && facts && f.requests_closed && f.protocol_closed &&
            f.video_clean) {
            sl_live_printf(
                "RUNTIME_FIXTURE_STOP requests_closed=1 protocol_closed=1 video_clean=1\n");
            tap(SDLK_ESCAPE);
            enter(7, now);
        }
        break;
    case 7:
        if (ui->page == SL_EXIT) {
            tap(SDLK_RETURN);
            enter(8, now);
        }
        break;
    }
}
int sl_runtime_fixture_result(void) {
    unsigned flags = atomic_load(&sns_flags), tx = atomic_load(&filtered_tx),
             rx = atomic_load(&filtered_rx);
    bool passed = !failure && phase == 8 && (flags & 3) == 3 && (!force_sdr || (flags & 4)) && tx;
    sl_live_printf(
        "RUNTIME_FIXTURE_RESULT=%d phase=%u failure=%u sns=%u filtered_tx=%u filtered_rx=%u\n",
        passed ? 0 : 1, phase, failure, flags, tx, rx);
    return passed ? 0 : 1;
}
/* Process-local LAN isolation. Consume at most one rejected datagram per call,
 * preserving nonblocking progress. CM TCP, public UDP, nxlink and loopback are
 * unaffected. No global firewall or host state is changed. */
static bool blocked(const struct sockaddr *sa) {
    if (!private_host || !sa || sa->sa_family != AF_INET)
        return false;
    uint32_t ip = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
    return ip == private_host || ip == UINT32_MAX || ip == ((private_host & 0xffffff00u) | 255u);
}
ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_sendto(int fd, const void *p, size_t n, int flags, const struct sockaddr *sa,
                      socklen_t len) {
    if (blocked(sa)) {
        atomic_fetch_add(&filtered_tx, 1);
        return n;
    }
    return __real_sendto(fd, p, n, flags, sa, len);
}
ssize_t __real_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t __wrap_recvfrom(int fd, void *p, size_t n, int flags, struct sockaddr *sa, socklen_t *len) {
    ssize_t result = __real_recvfrom(fd, p, n, flags, sa, len);
    if (result >= 0 && blocked(sa)) {
        atomic_fetch_add(&filtered_rx, 1);
        errno = EAGAIN;
        return -1;
    }
    return result;
}

ssize_t __real_sendmsg(int, const struct msghdr *, int);
ssize_t __wrap_sendmsg(int fd, const struct msghdr *msg, int flags) {
    if (blocked(msg->msg_name)) {
        size_t total = 0;
        size_t vectors = msg->msg_iovlen > 0 ? (size_t)msg->msg_iovlen : 0;
        for (size_t i = 0; i < vectors; ++i)
            total += msg->msg_iov[i].iov_len;
        atomic_fetch_add(&filtered_tx, 1);
        return total;
    }
    return __real_sendmsg(fd, msg, flags);
}
ssize_t __real_recvmsg(int, struct msghdr *, int);
ssize_t __wrap_recvmsg(int fd, struct msghdr *msg, int flags) {
    ssize_t result = __real_recvmsg(fd, msg, flags);
    if (result >= 0 && blocked(msg->msg_name)) {
        atomic_fetch_add(&filtered_rx, 1);
        errno = EAGAIN;
        return -1;
    }
    return result;
}
