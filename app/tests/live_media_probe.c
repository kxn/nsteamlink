/* Real-host smoke probe, never a synthetic peer or a new protocol policy.
 * Observers forward every production call unchanged. No packet logging, file
 * I/O, allocation or waiting is added to the network/decoder observers. */
#include "build_identity.h"
#include "ihs_udp.h"
#include "media.h"
#include "platform/events.h"
#include "platform/runtime.h"
#include "platform/system.h"
#include "services/i18n.h"
#include "services/video_settings.h"
#include "session/channels/ch_data.h"
#include "session/session_pri.h"
#include "session/unreliable.h"
#include "stream_settings.h"
#include <SDL.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>

static atomic_uint_fast64_t ordinary, fec, fec_parity_enabled, fec_parity_shards;
static atomic_uint_fast64_t fec_complete, complete, recovery, feedback, send_fail;
static _Atomic(IHS_UDPSocket *) ordinary_socket;
static _Thread_local bool ordinary_rx;
static uint64_t run_id;

void __real_IHS_SessionUnreliableReceived(IHS_Session *, IHS_SessionPacket *);
void __wrap_IHS_SessionUnreliableReceived(IHS_Session *s, IHS_SessionPacket *p) {
    bool previous = ordinary_rx;
    ordinary_rx = !s->networkTest.mode && p->header.channelId >= 3;
    if (ordinary_rx) {
        atomic_store_explicit(&ordinary_socket, s->base.socket, memory_order_relaxed);
        if (p->header.type == IHS_SessionPacketTypeUnreliableFEC) {
            atomic_fetch_add_explicit(&fec, 1, memory_order_relaxed);
            const uint8_t *b = IHS_BufferPointer(&p->body);
            if (b && p->body.size >= 8) {
                uint32_t length =
                    b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
                unsigned width = b[4] | (unsigned)b[5] << 8;
                unsigned parity = b[6] | (unsigned)b[7] << 8;
                /* These are observed metadata, not receiver admission or a
                 * claim that a group actually needed RS reconstruction. */
                if (parity && width && length) {
                    atomic_fetch_add_explicit(&fec_parity_enabled, 1, memory_order_relaxed);
                    uint64_t k = ((uint64_t)length + width - 1) / width;
                    if ((uint16_t)p->header.fragmentId >= k)
                        atomic_fetch_add_explicit(&fec_parity_shards, 1, memory_order_relaxed);
                }
            }
        } else if (p->header.type == IHS_SessionPacketTypeUnreliable ||
                   p->header.type == IHS_SessionPacketTypeUnreliableFrag)
            atomic_fetch_add_explicit(&ordinary, 1, memory_order_relaxed);
    }
    __real_IHS_SessionUnreliableReceived(s, p);
    ordinary_rx = previous;
}
bool __real_IHS_FECReceiverAdd(IHS_FECReceiver *, const IHS_SessionPacket *, IHS_SessionFrame *);
bool __wrap_IHS_FECReceiverAdd(IHS_FECReceiver *r, const IHS_SessionPacket *p,
                               IHS_SessionFrame *f) {
    bool ready = __real_IHS_FECReceiverAdd(r, p, f);
    if (ready && ordinary_rx)
        atomic_fetch_add_explicit(&fec_complete, 1, memory_order_relaxed);
    return ready;
}
void __real_IHS_SessionChannelDataReceiveReliableFrame(IHS_SessionChannel *, IHS_SessionFrame *);
void __wrap_IHS_SessionChannelDataReceiveReliableFrame(IHS_SessionChannel *c, IHS_SessionFrame *f) {
    if (c->id >= 3 && !c->session->networkTest.mode)
        atomic_fetch_add_explicit(&complete, 1, memory_order_relaxed);
    __real_IHS_SessionChannelDataReceiveReliableFrame(c, f);
}
void __real_IHS_SessionChannelDataLost(IHS_SessionChannel *);
void __wrap_IHS_SessionChannelDataLost(IHS_SessionChannel *c) {
    if (c->id >= 3 && !c->session->networkTest.mode)
        atomic_fetch_add_explicit(&recovery, 1, memory_order_relaxed);
    __real_IHS_SessionChannelDataLost(c);
}
bool __real_IHS_UDPSocketSend(IHS_UDPSocket *, const IHS_UDPPacket *);
bool __wrap_IHS_UDPSocketSend(IHS_UDPSocket *s, const IHS_UDPPacket *p) {
    const uint8_t *b = IHS_BufferPointer(&p->buffer);
    bool watched = s == atomic_load_explicit(&ordinary_socket, memory_order_relaxed) && b &&
                   p->buffer.size >= 13 && b[4] >= 3 && (b[0] & 127) == 10;
    bool sent = __real_IHS_UDPSocketSend(s, p);
    if (watched)
        atomic_fetch_add_explicit(sent ? &feedback : &send_fail, 1, memory_order_relaxed);
    return sent;
}

/* Main-thread records only. Switch's platform transport is bounded/nonblocking;
 * desktop uses stdout for offline contract checks. Missing records fail closed. */
static void record(const char *tag, const char *format, ...) {
    char line[224];
    int n = snprintf(line, sizeof(line), "LIVE_%s run=%" PRIu64 " ", tag, run_id);
    if (n < 0 || (size_t)n >= sizeof(line))
        return;
    va_list args;
    va_start(args, format);
    int written = vsnprintf(line + n, sizeof(line) - n, format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= sizeof(line) - n)
        return;
#ifdef __SWITCH__
    sl_system_log(line);
#else
    puts(line);
    fflush(stdout);
#endif
}
static void counters(void) {
    record("WIRE",
           "ordinary=%" PRIuFAST64 " fec=%" PRIuFAST64 " parity_enabled=%" PRIuFAST64
           " parity_shards=%" PRIuFAST64 " fec_complete=%" PRIuFAST64,
           atomic_load(&ordinary), atomic_load(&fec), atomic_load(&fec_parity_enabled),
           atomic_load(&fec_parity_shards), atomic_load(&fec_complete));
    record("FLOW",
           "complete=%" PRIuFAST64 " recovery=%" PRIuFAST64 " feedback_sent=%" PRIuFAST64
           " feedback_failed=%" PRIuFAST64,
           atomic_load(&complete), atomic_load(&recovery), atomic_load(&feedback),
           atomic_load(&send_fail));
}
int main(int argc, char **argv) {
    /* Numeric address prevents a diagnostic argument from starting an unrelated
     * DNS workflow. Existing paired host identity must also match discovery. */
    struct in_addr ip;
    if (argc != 3 || inet_pton(AF_INET, argv[1], &ip) != 1)
        return 2;
    char *end;
    unsigned long seconds = strtoul(argv[2], &end, 10);
    if (*end || seconds < 5 || seconds > 120)
        return 2;
    if (!sl_system_init())
        return 1;
    run_id = sl_system_now();
    record("BEGIN", "build=%s host=%s seconds=%lu", NSL_GIT_COMMIT, argv[1], seconds);
    const char *failure = "profile_missing";
    sl_runtime *runtime = NULL;
    bool media = false, log = false, submitted = false, passed = false;
    uint64_t play_ms = 0, last_present_at = 0, gap_ms = 0, tail_ms = 0;
    uint32_t seen_presented = 0;
    stream_media_snapshot last = {0};
    char path[512];
    snprintf(path, sizeof(path), "%s/profile.bin", sl_system_data_dir());
    struct stat st;
    sl_auth_store store;
    /* sl_auth_load may create an identity on a fresh installation. Refuse that
     * in this probe: never use an unpaired synthetic desktop identity. */
    if (stat(path, &st) || !S_ISREG(st.st_mode))
        goto cleanup;
    failure = "profile_invalid";
    if (sl_auth_load(&store, sl_system_data_dir()) != 0)
        goto cleanup;
    sl_stream_settings_preview(&store, sl_system_data_dir());
    record("SETTINGS", "stored_fec=%u sound=%u", store.unreliable_fec, store.sound);
    sl_i18n_load(sl_system_data_dir(), sl_system_locale());
    failure = "log_start";
    log = sl_log_start();
    if (!log)
        goto cleanup;
    failure = "media_init";
    media = stream_media_init(sl_log);
    if (!media)
        goto cleanup;
    failure = "runtime_create";
    runtime = sl_runtime_create(&store);
    if (!runtime)
        goto cleanup;
    sl_runtime_player_focus(runtime, sl_events_keyboard_focus());
    sl_media_mute(!store.sound);
    uint64_t began = sl_system_now(), first = 0, sampled = 0;
    uint64_t test_confirmed = 0;
    failure = "host_not_discovered";
    while (sl_system_running() && sl_system_now() - began < 180000) {
        uint64_t now = sl_system_now();
        sl_runtime_event event;
        while (sl_runtime_poll(runtime, &event)) {
            if (event.type == SL_EVENT_HOST && !submitted && !strcmp(event.host.address, argv[1])) {
                sl_host *host = sl_host_observe(&store.registry, &event.host, now);
                if (!host || !host->paired) {
                    failure = "host_not_paired";
                    goto cleanup;
                }
                sl_command cmd = {.type = SL_CMD_STREAM,
                                  .generation = 1,
                                  .host = *host,
                                  .quality = store.quality,
                                  .bitrate_kbps = store.bitrate_kbps,
                                  .unreliable_fec = store.unreliable_fec,
                                  .resolution = sl_video_settings_load(sl_system_data_dir())};
                failure = "stream_submit";
                if (!sl_runtime_submit(runtime, &cmd, &store))
                    goto cleanup;
                submitted = true;
                failure = "first_frame_timeout";
                record("SUBMITTED", "existing_identity=1");
            } else if (event.type == SL_EVENT_PIN || event.type == SL_EVENT_CODE ||
                       event.type == SL_EVENT_STREAM_AUTHORIZATION) {
                failure = "authorization_required";
                goto cleanup; /* Do not answer an authorization prompt. */
            } else if (event.type == SL_EVENT_FAILURE) {
                failure = "runtime_failure";
                goto cleanup;
            } else if (event.type == SL_EVENT_STOPPED && submitted) {
                failure = "host_stopped";
                goto cleanup;
            }
        }
        sl_network_test_view test;
        if (sl_runtime_network_test(runtime, &test) && test.phase == SL_TEST_FAILED) {
            failure = "network_test_failed";
            goto cleanup;
        }
        if (sl_runtime_network_test(runtime, &test) && test.phase == SL_TEST_RESULT &&
            test.generation != test_confirmed) {
            /* Explicit automation of Continue without accepting a preset.
             * Keep the ordinary client's test, stats save and continuation;
             * never infer that the recommendation enables FEC automatically. */
            sl_command cmd = {.type = SL_CMD_TEST_CONFIRM,
                              .generation = test.generation,
                              .accept_recommendation = false};
            if (!sl_runtime_submit(runtime, &cmd, &store)) {
                failure = "network_test_continue";
                goto cleanup;
            }
            test_confirmed = test.generation;
            record("NETTEST", "decision=continue_keep_settings");
        }
        sl_runtime_foreground(runtime, sl_events_foreground());
        sl_runtime_player_focus(runtime, sl_events_keyboard_focus());
        sl_media_gate(false); /* Passive playback probe; no remote input. */
        stream_media_present();
        stream_media_get_snapshot(&last);
        if (last.displayed_frames && last.displayed_frames != seen_presented) {
            uint64_t gap = last_present_at ? now - last_present_at : 0;
            if (gap > gap_ms)
                gap_ms = gap;
            last_present_at = now;
            seen_presented = last.displayed_frames;
        }
        tail_ms = last_present_at ? now - last_present_at : 0;
        if (last.render_failed || !sl_gfx_healthy(sl_media_gfx())) {
            failure = "render_failure";
            goto cleanup;
        }
        if (last.first_frame_displayed && !first) {
            first = now;
            record("FIRST", "elapsed_ms=%" PRIu64, now - began);
        }
        if (now - sampled >= 1000) {
            counters();
            record("MEDIA", "elapsed_ms=%" PRIu64 " decoded=%u presented=%u audio=%u hardware=%u",
                   now - began, last.decoded_frames, last.displayed_frames, last.audio_frames,
                   last.render.hardware);
            sampled = now;
        }
        if (first && now - first >= seconds * 1000) {
            play_ms = now - first;
            if (tail_ms > gap_ms)
                gap_ms = tail_ms;
            /* Smoke acceptance only, never a protocol deadline/drop rule.
             * Do not pass a session that showed one frame then froze. */
            passed = last.decoded_frames > 0 && last.displayed_frames > 1 &&
                     atomic_load(&complete) > 0 && tail_ms <= 2000;
            failure = passed ? "none" : tail_ms > 2000 ? "playback_stalled" : "media_missing";
            break;
        }
        if ((!submitted && now - began > 15000) || (!first && now - began > 120000))
            break;
        if (stream_media_exit_requested() || sl_events_exit_requested()) {
            failure = "local_exit";
            break;
        }
        SDL_Delay(1);
    }
cleanup:
    if (media) {
        sl_media_gate(false);
        sl_media_close_video();
    }
    sl_runtime_request_exit(runtime);
    while (!sl_runtime_finished(runtime) ||
           (media && sl_gfx_poll_drain(sl_media_gfx()) == SL_GFX_BUSY)) {
        if (media) {
            sl_media_collect();
            if (!sl_gfx_healthy(sl_media_gfx()))
                sl_gfx_finish(sl_media_gfx());
        }
        SDL_Delay(1);
    }
    sl_runtime_destroy(runtime); /* joins client/session workers before IHS_Quit */
    if (media)
        stream_media_shutdown();
    if (log)
        sl_log_finish();
    counters();
    record("RESULT",
           "decoded=%u presented=%u audio=%u hardware=%u play_ms=%" PRIu64 " gap_ms=%" PRIu64
           " tail_ms=%" PRIu64,
           last.decoded_frames, last.displayed_frames, last.audio_frames, last.render.hardware,
           play_ms, gap_ms, tail_ms);
    record("FINAL", "result=%s reason=%s workers=joined media=destroyed", passed ? "PASS" : "FAIL",
           failure);
    sl_system_shutdown(); /* FINAL precedes closing its nonblocking log socket. */
    return passed ? 0 : 1;
}
