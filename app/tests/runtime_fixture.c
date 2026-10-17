/* Diagnostic-only linker wrappers around the real production application.
 * No test control endpoint, network mode, or driver is linked into nsteamlink.
 * UI/SDL actions and snapshots run on the existing main thread; SNS observations
 * are copied by its existing owner through atomics. No additional workers. */
#include "runtime_fixture.h"
#include "media.h"
#include "platform/runtime.h"
#include "platform/system.h"
#include "remote_connection.h"
#include "sns_backend.h"
#include <SDL.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>

int sl_live_printf(const char *, ...);
static char private_directory[192];
static uint32_t private_host;
static uint64_t began, sampled, phase_at, submitted_before, acked_before;
static bool cloud_mode, cloud_ui_offline, cloud_initial, cloud_initial_bridge;
static bool loss_soak, soak_completed;
static bool abrupt_fault, fault_completed;
static atomic_bool fault_armed, fault_injected, fault_invalid, fault_terminal;
static atomic_uint fault_e2e, fault_new_pop, fault_generation;
static atomic_uint_fast64_t fault_started;
static uint64_t fault_window, fault_e2e_at, fault_frame_at;
static unsigned fault_seen_e2e, fault_frames;
static atomic_bool loss_active;
static atomic_uint loss_packets[2], loss_dropped[2]; /* RX, TX. */
static uint64_t soak_started, soak_last_frame;
static uint32_t soak_previous_frame;
static atomic_uint cloud_directory_rounds, cloud_tls_failures, cloud_tls_unique, cloud_tls_success;
static atomic_uint_fast64_t cloud_retry_delay;
static _Thread_local bool cloud_update_context;
static atomic_bool cloud_armed, cloud_ready;
static atomic_uint cloud_connections, cloud_disconnects, cloud_drops;
static sl_remote_connection *cloud_connection;
static _Thread_local bool cloud_receive_context;
static uint64_t cloud_resume_at;
static bool cloud_was_ready;
void sl_runtime_fixture_cloud_reconnect(void) {
    cloud_mode = true;
}
void sl_runtime_fixture_loss_soak(void) {
    loss_soak = true;
}
void sl_runtime_fixture_abrupt_fault(void) {
    abrupt_fault = true;
}
void sl_runtime_fixture_cloud_initial_failure(bool bridge_mode) {
    cloud_mode = cloud_initial = true;
    cloud_initial_bridge = bridge_mode;
}
static bool initial_delay_valid(void) {
    uint64_t delay = atomic_load(&cloud_retry_delay);
    return cloud_initial_bridge ? delay < 1000 : delay >= 10000 && delay <= 30500;
}
/* Desktop-only initial-connect fixture. The first directory and TLS handshakes
 * are real; only their CM completion results are replaced. No WS request is sent
 * on the failed batch. The production provider rotates/exhausts its own list. */
#ifndef __SWITCH__
static uint64_t cloud_tls_last_failed;
static char cloud_failed_urls[32][192];
CURLMcode __real_curl_multi_add_handle(CURLM *, CURL *);
CURLMcode __wrap_curl_multi_add_handle(CURLM *multi, CURL *easy) {
    char *url = NULL;
    if (cloud_initial && cloud_update_context &&
        curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &url) == CURLE_OK && url &&
        strstr(url, "/ISteamDirectory/")) {
        ++cloud_directory_rounds;
        if (cloud_directory_rounds == 2 && cloud_tls_last_failed) {
            cloud_retry_delay = sl_system_now() - cloud_tls_last_failed;
            sl_live_printf("CLOUD_FIXTURE_INITIAL_RETRY delay_ms=%llu failed=%u unique=%u\n",
                           (unsigned long long)cloud_retry_delay, cloud_tls_failures,
                           cloud_tls_unique);
        }
    }
    return __real_curl_multi_add_handle(multi, easy);
}
CURLMsg *__real_curl_multi_info_read(CURLM *, int *);
CURLMsg *__wrap_curl_multi_info_read(CURLM *multi, int *remaining) {
    CURLMsg *message = __real_curl_multi_info_read(multi, remaining);
    char *url = NULL;
    if (cloud_initial && cloud_update_context && cloud_directory_rounds == 1 && message &&
        message->msg == CURLMSG_DONE &&
        curl_easy_getinfo(message->easy_handle, CURLINFO_EFFECTIVE_URL, &url) == CURLE_OK && url &&
        strstr(url, "/remoteplay/")) {
        bool known = false;
        for (unsigned i = 0; i < cloud_tls_unique; ++i)
            if (!strcmp(url, cloud_failed_urls[i]))
                known = true;
        if (!known && cloud_tls_unique < 32 && strlen(url) < sizeof(cloud_failed_urls[0]))
            strcpy(cloud_failed_urls[cloud_tls_unique++], url);
        ++cloud_tls_failures;
        cloud_tls_last_failed = sl_system_now();
        CURLcode original = message->data.result;
        if (original == CURLE_OK)
            ++cloud_tls_success;
        message->data.result = CURLE_COULDNT_CONNECT;
        sl_live_printf("CLOUD_FIXTURE_INITIAL_TLS_FAILURE attempt=%u unique=%u original=%d\n",
                       cloud_tls_failures, cloud_tls_unique, original);
    }
    return message;
}
#endif
CURLcode __real_curl_easy_recv(CURL *, void *, size_t, size_t *);
CURLcode __wrap_curl_easy_recv(CURL *easy, void *data, size_t size, size_t *received) {
    if (cloud_mode && cloud_receive_context && atomic_exchange(&cloud_armed, false)) {
        *received = 0;
        cloud_resume_at = sl_system_now() + 20000;
        atomic_fetch_add(&cloud_drops, 1);
        sl_live_printf("CLOUD_FIXTURE_RECV_ERROR=1 hold_ms=20000\n");
        return CURLE_RECV_ERROR;
    }
    return __real_curl_easy_recv(easy, data, size, received);
}
void __real_sl_remote_connection_update(sl_remote_connection *, uint64_t);
void __wrap_sl_remote_connection_update(sl_remote_connection *connection, uint64_t now) {
    if (cloud_mode && connection == cloud_connection && now < cloud_resume_at)
        return;
    if (cloud_initial && !cloud_connection) {
        cloud_connection = connection;
        sl_remote_connection_set_bridge_mode(connection, cloud_initial_bridge);
        sl_live_printf("CLOUD_FIXTURE_INITIAL_MODE bridge=%d\n", cloud_initial_bridge);
    }
    cloud_update_context = cloud_mode && (!cloud_connection || connection == cloud_connection);
    cloud_receive_context = cloud_mode && !cloud_initial && connection == cloud_connection;
    __real_sl_remote_connection_update(connection, now);
    cloud_receive_context = cloud_update_context = false;
    if (!cloud_mode)
        return;
    bool ready = sl_remote_ready(sl_remote_connection_protocol(connection));
    if (!cloud_connection && ready)
        cloud_connection = connection;
    if (connection != cloud_connection)
        return;
    if (ready != cloud_was_ready) {
        atomic_fetch_add(ready ? &cloud_connections : &cloud_disconnects, 1);
        cloud_was_ready = ready;
    }
    atomic_store(&cloud_ready, ready);
}
static uint32_t frames_before;
static uint64_t wire_before, wire_pressed, submitted_pressed, acked_pressed, sent_before,
    sent_pressed, giveups_before;
static uint64_t reported;
static unsigned phase, failure, press_attempts;
static uint64_t press_attempt_at;
static sl_runtime *runtime;
static atomic_uint filtered_tx, filtered_rx, sns_flags, reliability_revision;
static atomic_uint_fast64_t observed_submitted, observed_acked, observed_sent, observed_giveups;
static atomic_uint observed_pending, observed_inflight;
static atomic_uint_fast64_t wire_report;
static atomic_size_t report_length;
static atomic_uintptr_t observed_device;
static atomic_int observed_controller = -1;
static atomic_uint device_creations, device_closes;
IHS_HIDDevice *__real_IHS_HIDDeviceSDLCreate(IHS_HIDProvider *, SDL_GameController *, bool);
IHS_HIDDevice *__wrap_IHS_HIDDeviceSDLCreate(IHS_HIDProvider *provider,
                                             SDL_GameController *controller, bool managed) {
    IHS_HIDDevice *device = __real_IHS_HIDDeviceSDLCreate(provider, controller, managed);
    int id = SDL_JoystickInstanceID(SDL_GameControllerGetJoystick(controller));
    atomic_store(&observed_controller, id);
    atomic_store(&observed_device, (uintptr_t)device);
    if (atomic_fetch_add(&device_creations, 1) < 8)
        sl_live_printf("RUNTIME_FIXTURE_DEVICE_CREATED id=%d managed=%d ok=%d\n", id, managed,
                       device != NULL);
    return device;
}
void __real_IHS_HIDManagedDeviceClose(IHS_HIDManagedDevice *);
void __wrap_IHS_HIDManagedDeviceClose(IHS_HIDManagedDevice *managed) {
    if (atomic_fetch_add(&device_closes, 1) < 8)
        sl_live_printf("RUNTIME_FIXTURE_DEVICE_CLOSE observed=%u\n", atomic_load(&device_closes));
    __real_IHS_HIDManagedDeviceClose(managed);
}
int __real_IHS_HIDDeviceStartInputReports(IHS_HIDDevice *, size_t);
int __wrap_IHS_HIDDeviceStartInputReports(IHS_HIDDevice *device, size_t length) {
    int result = __real_IHS_HIDDeviceStartInputReports(device, length);
    if (!result)
        atomic_store(&report_length, length);
    sl_live_printf("RUNTIME_FIXTURE_START_INPUT length=%zu result=%d last_device=%d id=%d\n",
                   length, result, atomic_load(&observed_device) == (uintptr_t)device,
                   atomic_load(&observed_controller));
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
        sl_live_printf("RUNTIME_FIXTURE_HID_EVENT time=%llu id=%d code=%u value=%u accepted=%d "
                       "gate=%u enabled=%d\n",
                       (unsigned long long)sl_system_now(), e->cbutton.which, e->cbutton.button,
                       e->cbutton.state, result, atomic_load(&gate_enabled),
                       IHS_SessionInputEnabled(session));
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
    if (began && sl_system_now() - began >= (loss_soak ? 240000 : cloud_initial ? 180000 : 90000)) {
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
    if (!abrupt_fault)
        return;
    unsigned values[5] = {0};
    if (atomic_exchange(&fault_armed, false)) {
        if (!sl_sns_test_relay_loss(sns, 1, values)) {
            atomic_store(&fault_invalid, true);
            return;
        }
        atomic_store(&fault_started, now);
        atomic_store(&fault_injected, true);
        sl_live_printf("RUNTIME_FIXTURE_FAULT_INJECTED generation=%u\n", values[0]);
    }
    if (atomic_load(&fault_injected) && sl_sns_test_relay_loss(sns, -1, values)) {
        atomic_store(&fault_generation, values[0]);
        atomic_store(&fault_e2e, values[3]);
        atomic_store(&fault_new_pop, values[4]);
    }
    if (s.terminal_source && !atomic_exchange(&fault_terminal, true)) {
        sl_live_printf(
            "RUNTIME_FIXTURE_FAULT_TERMINAL source=%d detail=%d sdk_state=%d reason=%d\n",
            s.terminal_source, s.terminal_detail, s.terminal_sdk_state, s.terminal_end_reason);
        sl_sdr_loss_snapshot end;
        if (sl_sns_loss_snapshot(sns, &end))
            sl_live_printf("RUNTIME_FIXTURE_FAULT_CLOSE type20=%u type21=%u cm=%u relay_mode=%u "
                           "primary=%u local_ack=%u revision=%u\n",
                           end.relay_closed, end.relay_no_connection, end.cm_closed,
                           end.close_relay_mode, end.primary_pop, end.local_acked,
                           end.local_revision);
    }
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
    if ((phase == 2 || phase == 3 || phase == 30) &&
        s.reliability.reliableGiveUps > giveups_before) {
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
            if (cloud_initial) {
                if (!atomic_load(&cloud_ready))
                    break;
                if (cloud_directory_rounds != 2 || cloud_tls_failures < 2 ||
                    cloud_tls_unique != cloud_tls_failures || !cloud_tls_success ||
                    !initial_delay_valid() || atomic_load(&cloud_connections) != 1 ||
                    atomic_load(&cloud_disconnects)) {
                    failure = 9;
                    sl_live_printf("CLOUD_FIXTURE_INITIAL_INVALID=1\n");
                    break;
                }
                sl_live_printf(
                    "CLOUD_FIXTURE_INITIAL_RECOVERED=1 failed=%u unique=%u retry_ms=%llu\n",
                    cloud_tls_failures, cloud_tls_unique, (unsigned long long)cloud_retry_delay);
                tap(SDLK_ESCAPE);
                enter(7, now);
            } else if (cloud_mode) {
                atomic_store(&cloud_armed, true);
                enter(20, now);
            } else {
                tap(SDLK_y);
                enter(1, now);
            }
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
            sl_live_printf("RUNTIME_FIXTURE_DEVICE_SELECTED id=%d total=%d\n", controller_id,
                           SDL_NumJoysticks());
            button(true);
            press_attempts = 1;
            press_attempt_at = now;
            enter(2, now);
        }
        break;
    case 2:
        /* A host may reopen the SDL device after its first full report. These
         * are bounded driver events, never a substitute for the wire/ACK gate. */
        if (wire_seq == wire_before && now - press_attempt_at >= 1000 && press_attempts < 3) {
            button(true);
            press_attempt_at = now;
            sl_live_printf("RUNTIME_FIXTURE_RETRY_PRESS attempt=%u\n", ++press_attempts);
        }
        if (wire_seq == wire_before && now - phase_at >= 15000) {
            failure = 11;
            sl_live_printf("RUNTIME_FIXTURE_INPUT_UNAVAILABLE=1 attempts=%u\n", press_attempts);
            break;
        }
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
            if (abrupt_fault) {
                soak_previous_frame = s.displayed_frames;
                fault_frame_at = now;
                atomic_store(&fault_armed, true);
                enter(31, now);
                break;
            }
            if (loss_soak) {
                frames_before = soak_previous_frame = s.displayed_frames;
                soak_started = soak_last_frame = now;
                atomic_store(&loss_active, true);
                sl_live_printf("RUNTIME_FIXTURE_LOSS_BEGIN duration_ms=180000 per_10000=100 "
                               "seed=1373051537\n");
                enter(30, now);
                break;
            }
            key(SDLK_MINUS, true);
            key(SDLK_EQUALS, true);
            enter(4, now);
        }
        break;
    case 31: {
        unsigned e2e = atomic_load(&fault_e2e);
        bool usable = atomic_load(&fault_new_pop) && e2e;
        if (atomic_load(&fault_invalid) || now - phase_at > 35000) {
            failure = 12;
            sl_live_printf("RUNTIME_FIXTURE_FAULT_TIMEOUT=1\n");
            break;
        }
        if (s.displayed_frames != soak_previous_frame) {
            soak_previous_frame = s.displayed_frames;
            fault_frame_at = now;
        }
        if (!usable) {
            fault_window = 0;
        } else if (!fault_window) {
            fault_window = fault_e2e_at = now;
            fault_seen_e2e = e2e;
            fault_frames = s.displayed_frames;
        } else if (e2e != fault_seen_e2e) {
            fault_seen_e2e = e2e;
            fault_e2e_at = now;
        }
        if (atomic_load(&fault_injected) && now - reported >= 1000) {
            reported = now;
            sl_live_printf("RUNTIME_FIXTURE_FAULT_SAMPLE elapsed=%llu generation=%u new_pop=%u "
                           "e2e=%u displayed=%u frame_age=%llu\n",
                           (unsigned long long)(now - atomic_load(&fault_started)),
                           atomic_load(&fault_generation), atomic_load(&fault_new_pop), e2e,
                           s.displayed_frames, (unsigned long long)(now - fault_frame_at));
        }
        if (fault_window && now - fault_window >= 5000 && now - fault_e2e_at <= 1000 &&
            now - fault_frame_at <= 1000 && s.displayed_frames - fault_frames >= 30) {
            fault_completed = true;
            sl_live_printf("RUNTIME_FIXTURE_FAULT_RECOVERED=1 new_frames=%u\n",
                           s.displayed_frames - fault_frames);
            key(SDLK_MINUS, true);
            key(SDLK_EQUALS, true);
            enter(4, now);
        }
        break;
    }
    case 30:
        if (s.displayed_frames != soak_previous_frame) {
            soak_previous_frame = s.displayed_frames;
            soak_last_frame = now;
        }
        if (ui->page != SL_STREAM || now - soak_last_frame > 5000) {
            failure = 10;
            sl_live_printf("RUNTIME_FIXTURE_LOSS_STALLED page=%u age_ms=%llu\n", ui->page,
                           (unsigned long long)(now - soak_last_frame));
            break;
        }
        if (now - reported >= 5000) {
            reported = now;
            sl_live_printf("RUNTIME_FIXTURE_LOSS_SAMPLE elapsed_ms=%llu new_frames=%u audio=%u "
                           "errors=%u packets_rx=%u tx=%u dropped_rx=%u tx=%u\n",
                           (unsigned long long)(now - soak_started),
                           s.displayed_frames - frames_before, s.audio_frames,
                           s.audio_decode_errors, atomic_load(&loss_packets[0]),
                           atomic_load(&loss_packets[1]), atomic_load(&loss_dropped[0]),
                           atomic_load(&loss_dropped[1]));
        }
        if (now - soak_started >= 180000 && now - soak_last_frame <= 1000 &&
            s.displayed_frames - frames_before >= 3000 && s.audio_frames >= 1000 &&
            atomic_load(&loss_dropped[0]) && atomic_load(&loss_dropped[1])) {
            soak_completed = true;
            atomic_store(&loss_active, false);
            sl_live_printf(
                "RUNTIME_FIXTURE_LOSS_HELD elapsed_ms=%llu new_frames=%u fresh_ms=%llu\n",
                (unsigned long long)(now - soak_started), s.displayed_frames - frames_before,
                (unsigned long long)(now - soak_last_frame));
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
    case 20: {
        int i = ui->store.registry.selected;
        sl_host *h = i >= 0 && i < ui->store.registry.count ? &ui->store.registry.hosts[i] : NULL;
        if (atomic_load(&cloud_drops) && !atomic_load(&cloud_ready) && !sl_host_online(h, now)) {
            cloud_ui_offline = true;
            sl_live_printf("CLOUD_FIXTURE_UI_OFFLINE delay_ms=%llu\n",
                           (unsigned long long)(now - phase_at));
            enter(21, now);
        }
        break;
    }
    case 21: {
        int i = ui->store.registry.selected;
        sl_host *h = i >= 0 && i < ui->store.registry.count ? &ui->store.registry.hosts[i] : NULL;
        if (cloud_ui_offline && atomic_load(&cloud_connections) >= 2 && atomic_load(&cloud_ready) &&
            sl_host_online(h, now)) {
            sl_live_printf("CLOUD_FIXTURE_UI_RESTORED connections=%u disconnects=%u\n",
                           atomic_load(&cloud_connections), atomic_load(&cloud_disconnects));
            tap(SDLK_ESCAPE);
            enter(7, now);
        }
        break;
    }
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
    bool path = cloud_initial ? !flags && cloud_directory_rounds == 2 && cloud_tls_failures >= 2 &&
                                    cloud_tls_unique == cloud_tls_failures && cloud_tls_success &&
                                    initial_delay_valid() && atomic_load(&cloud_connections) == 1 &&
                                    !atomic_load(&cloud_disconnects) && !atomic_load(&cloud_drops)
                : cloud_mode
                    ? !flags && cloud_ui_offline && atomic_load(&cloud_connections) >= 2 &&
                          atomic_load(&cloud_disconnects) == 1 && atomic_load(&cloud_drops) == 1
                    : (flags & 3) == 3 && (!force_sdr || (flags & 4));
    bool passed = !failure && phase == 8 && path && tx && (!loss_soak || soak_completed) &&
                  (!abrupt_fault || fault_completed);
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
/* Fixed-seed pseudorandom 1% public IPv4 UDP loss after input acceptance.
 * No socket, timer, worker, delayed queue, or global firewall is introduced. */
static bool impaired(const struct sockaddr *sa, bool tx) {
    if (!atomic_load(&loss_active) || !sa || sa->sa_family != AF_INET)
        return false;
    uint32_t ip = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
    if ((ip >> 24) == 0 || (ip >> 24) == 10 || (ip >> 24) == 127 || (ip >> 16) == 0xa9fe ||
        (ip >> 20) == 0xac1 || (ip >> 16) == 0xc0a8 || ip >= 0xe0000000)
        return false;
    uint32_t x = (atomic_fetch_add(&loss_packets[tx], 1) + 1) ^ (UINT32_C(0x51d71a91) + tx);
    x ^= x >> 16;
    x *= UINT32_C(0x7feb352d);
    x ^= x >> 15;
    x *= UINT32_C(0x846ca68b);
    x ^= x >> 16;
    if (x % 10000 >= 100)
        return false;
    atomic_fetch_add(&loss_dropped[tx], 1);
    return true;
}
ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_sendto(int fd, const void *p, size_t n, int flags, const struct sockaddr *sa,
                      socklen_t len) {
    if (blocked(sa)) {
        atomic_fetch_add(&filtered_tx, 1);
        return n;
    }
    if (impaired(sa, true))
        return n;
    return __real_sendto(fd, p, n, flags, sa, len);
}
ssize_t __real_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t __wrap_recvfrom(int fd, void *p, size_t n, int flags, struct sockaddr *sa, socklen_t *len) {
    ssize_t result = __real_recvfrom(fd, p, n, flags, sa, len);
    bool lan = result >= 0 && blocked(sa);
    if (result >= 0 && (lan || impaired(sa, false))) {
        if (lan)
            atomic_fetch_add(&filtered_rx, 1);
        errno = EAGAIN;
        return -1;
    }
    return result;
}

ssize_t __real_sendmsg(int, const struct msghdr *, int);
ssize_t __wrap_sendmsg(int fd, const struct msghdr *msg, int flags) {
    bool lan = blocked(msg->msg_name);
    if (lan || impaired(msg->msg_name, true)) {
        size_t total = 0;
        size_t vectors = msg->msg_iovlen > 0 ? (size_t)msg->msg_iovlen : 0;
        for (size_t i = 0; i < vectors; ++i)
            total += msg->msg_iov[i].iov_len;
        if (lan)
            atomic_fetch_add(&filtered_tx, 1);
        return total;
    }
    return __real_sendmsg(fd, msg, flags);
}
ssize_t __real_recvmsg(int, struct msghdr *, int);
ssize_t __wrap_recvmsg(int fd, struct msghdr *msg, int flags) {
    ssize_t result = __real_recvmsg(fd, msg, flags);
    bool lan = result >= 0 && blocked(msg->msg_name);
    if (result >= 0 && (lan || impaired(msg->msg_name, false))) {
        if (lan)
            atomic_fetch_add(&filtered_rx, 1);
        errno = EAGAIN;
        return -1;
    }
    return result;
}
