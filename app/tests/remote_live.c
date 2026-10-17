/* Default: read-only anonymous CreateSession. Explicit --pair/--status use an
 * isolated private profile. --sns-test explicitly requests a host network test
 * and checks the independent custom-signaling backend, without launching a game. */
#include "remote_connection.h"
#include "services/auth_store.h"
#ifdef NSL_HAVE_SNS
#include "sns_backend.h"
#include <ihslib/session.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>
#ifdef NSL_LIVE_EXTERNAL_LOG
int sl_live_printf(const char *, ...);
#define printf sl_live_printf
#define puts(text) sl_live_printf("%s\n", text)
#define fprintf(stream, ...) sl_live_printf(__VA_ARGS__)
#define fflush(stream) ((void)0)
#endif
#ifndef NSL_REMOTE_LIVE_ENTRY
#define NSL_REMOTE_LIVE_ENTRY main
#endif
typedef struct live {
    sl_auth_store store;
    const char *profile;
    bool ready, failed, paired, status;
    unsigned codes;
    uint64_t peer_id;
#ifdef NSL_HAVE_SNS
    sl_sns *sns;
    IHS_Session *session;
    IHS_SessionInfo session_info;
    atomic_bool session_connected;
    atomic_uint video_frames;
    bool desktop_stream;
    bool relay_only;
#endif
} live;
static void connected(bool ready, void *ctx) {
    ((live *)ctx)->ready = ready;
    printf("CLOUD_CONNECTED=%d\n", ready);
    fflush(stdout);
}
static void diagnostic(const char *message, void *ctx) {
    (void)ctx;
    fprintf(stderr, "%lld %s\n", (long long)time(NULL), message);
}
static void pin(const char *code, void *ctx) {
    live *l = ctx;
    ++l->codes;
    /* Explicit interactive test only. Never dump identity, key or certificate. */
    printf("PAIR_CODE=%s\n", code);
    fflush(stdout);
}
static bool save(const sl_remote_peer *peer, void *ctx) {
    live *l = ctx;
    sl_host *h = NULL;
    for (int i = 0; i < l->store.registry.count; ++i)
        if (l->store.registry.hosts[i].client_id == peer->client_id)
            h = &l->store.registry.hosts[i];
    if (!h) {
        if (l->store.registry.count == SL_HOST_LIMIT)
            return false;
        h = &l->store.registry.hosts[l->store.registry.count++];
        *h = (sl_host){.id = l->store.registry.next_id++, .client_id = peer->client_id};
        snprintf(h->name, sizeof(h->name), "Steam");
        l->store.registry.selected = (int)(h - l->store.registry.hosts);
    }
    h->paired = h->has_secret = true;
    h->account = peer->steam_id;
    memcpy(h->secret, peer->secret, 32);
    return sl_auth_save(&l->store, l->profile);
}
static void paired(const sl_remote_peer *peer, void *ctx) {
    (void)peer;
    ((live *)ctx)->paired = true;
    puts("PAIRED=1");
    fflush(stdout);
}
static void failed(IHS_AuthorizationResult result, void *ctx) {
    ((live *)ctx)->failed = true;
    printf("PAIR_FAILED=%d\n", result);
    fflush(stdout);
}
static void host(const sl_remote_host *h, void *ctx) {
    live *l = ctx;
    l->status = true;
    l->peer_id = h->info.clientId;
    puts("CLOUD_STATUS=1");
    fflush(stdout);
}
#ifdef NSL_HAVE_SNS
static void stream_result(IHS_StreamingResult result, const sl_remote_material *m, void *ctx) {
    live *l = ctx;
    printf("NETWORK_TEST_RESULT=%d\n", result);
    if (result != IHS_StreamingSuccess || !m) {
        l->failed = true;
        return;
    }
    IHS_ClientConfig config = {.deviceId = l->store.device_id,
        .secretKey = l->store.secret, .deviceName = l->store.device_name};
    char error[1024];
    printf("SNS_MATERIAL transport=%d key_bytes=%zu cert_bytes=%zu\n", m->transport,
        m->key_size, m->cert ? strlen(m->cert) : 0);
    l->sns = sl_sns_create(&config, m, !l->relay_only, error, sizeof(error));
    l->session_info = (IHS_SessionInfo){.steamId = m->steam_id, .sessionKeyLen = m->key_size};
    IHS_IPAddressFromString(&l->session_info.address.ip, "127.0.0.1");
    if (m->key_size <= sizeof(l->session_info.sessionKey))
        memcpy(l->session_info.sessionKey, m->key, m->key_size);
    else
        l->failed = true;
    printf("SNS_INITIALIZED=%d\n", l->sns != NULL);
    if (!l->sns) {
        /* SDK error text can contain identity/certificate data. */
        l->failed = true;
        char path[1024];
        snprintf(path, sizeof(path), "%s/sns-error.private", l->profile);
        FILE *file = fopen(path, "wb");
        if (file) {
            fwrite(error, 1, strlen(error), file);
            fclose(file);
        }
    }
    memset(error, 0, sizeof(error));
    fflush(stdout);
}
static void session_connected(IHS_Session *session, void *ctx) {
    (void)session;
    atomic_store(&((live *)ctx)->session_connected, true);
}
static void session_disconnected(IHS_Session *session, void *ctx) {
    (void)session; atomic_store(&((live *)ctx)->session_connected,false);
}
static void configuring(IHS_Session *session, IHS_SessionConfig *config, void *ctx) {
    (void)session;
    (void)ctx;
    *config = (IHS_SessionConfig){.maxWidth = 1280, .maxHeight = 720, .maxFps = 30,
        .maxBitrateKbps = 5000};
}
static int video_start(IHS_Session *session, const IHS_StreamVideoConfig *config, void *ctx) {
    (void)session;
    (void)config;
    (void)ctx;
    return 0;
}
static IHS_StreamVideoSubmitResult video_submit(IHS_Session *session, uint16_t id,
    IHS_Buffer *data, IHS_StreamVideoFrameFlag flags, void *ctx) {
    (void)session;
    (void)id;
    (void)data;
    (void)flags;
    atomic_fetch_add(&((live *)ctx)->video_frames, 1);
    /* Probe counts encrypted/encoded pipeline delivery; no pixels or video
     * bytes are written to disk or rendered. This does not prove decoding. */
    return IHS_StreamVideoSubmitOK;
}
static void video_stop(IHS_Session *session, void *ctx) { (void)session; (void)ctx; }
static const IHS_StreamSessionCallbacks session_cb = {
    .connected = session_connected, .disconnected = session_disconnected, .configuring = configuring};
static const IHS_StreamVideoCallbacks video_cb = {
    .start = video_start, .submit = video_submit, .stop = video_stop};
#endif
static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
int NSL_REMOTE_LIVE_ENTRY(int argc, char **argv) {
    uint8_t secret[32] = {0};
    IHS_ClientConfig config = {
        .deviceId = 1, .secretKey = secret, .deviceName = "NSteamLink probe"};
    bool pairing = argc == 3 && !strcmp(argv[1], "--pair");
    bool status = argc == 3 && !strcmp(argv[1], "--status");
    bool idle = argc == 2 && !strcmp(argv[1], "--idle");
    bool sns_test = false;
    bool desktop_stream = false;
    bool sdr_session = false;
    bool relay_only = false, fault_test = false, warm_fault = false, pause_test = false;
    int terminal_test = 0;
#ifdef NSL_HAVE_SNS
    sns_test = argc == 3 && !strcmp(argv[1], "--sns-test");
    desktop_stream = argc == 3 && !strcmp(argv[1], "--sns-desktop");
    sdr_session = argc == 3 && !strcmp(argv[1], "--sdr-session");
    if (argc == 3 && (!strcmp(argv[1], "--sdr-close-test") || !strcmp(argv[1], "--sdr-no-connection-test"))) {
        terminal_test = !strcmp(argv[1], "--sdr-close-test") ? 1 : 2;
        sns_test = relay_only = true;
    }
    if (argc == 3 && !strcmp(argv[1], "--sdr-fault-test"))
        fault_test = sns_test = relay_only = true;
    if (argc == 3 && !strcmp(argv[1], "--sdr-fault-desktop"))
        fault_test = desktop_stream = relay_only = true;
    if (argc == 3 && !strcmp(argv[1], "--sdr-warm-fault-desktop"))
        warm_fault = fault_test = desktop_stream = relay_only = true;
    if (argc == 3 && !strcmp(argv[1], "--sdr-pause-desktop"))
        pause_test = desktop_stream = relay_only = true;
    if (argc == 3 && !strcmp(argv[1], "--sdr-only-test"))
        sns_test = relay_only = true;
    if (argc == 3 && !strcmp(argv[1], "--sdr-only-desktop"))
        desktop_stream = relay_only = true;
#endif
    if (argc != 1 && !pairing && !status && !idle && !sns_test && !desktop_stream && !sdr_session) {
        fprintf(stderr, "usage: %s [--idle | --pair|--status|--sns-test|--sns-desktop|--sdr-session|--sdr-only-test|--sdr-only-desktop|--sdr-fault-test|--sdr-fault-desktop|--sdr-warm-fault-desktop|--sdr-pause-desktop PRIVATE_PROFILE_DIRECTORY]\n",
                argv[0]);
        return 2;
    }
    live l = {.profile = argc == 3 ? argv[2] : NULL};
#ifdef NSL_HAVE_SNS
    l.desktop_stream = desktop_stream;
    l.relay_only = relay_only;
    atomic_init(&l.session_connected, false);
    atomic_init(&l.video_frames, 0);
#endif
#ifndef __SWITCH__
    umask(0077);
#endif
    if (l.profile) {
        if (sl_auth_load(&l.store, l.profile) < 0)
            return 1;
        config = (IHS_ClientConfig){.deviceId = l.store.device_id,
                                    .secretKey = l.store.secret,
                                    .deviceName = l.store.device_name};
    }
    sl_remote_callbacks cb = {.diagnostic = diagnostic,
                              .connected = connected,
                              .pair_code = pin,
                              .save_key = save,
                              .paired = paired,
                              .pair_failed = failed,
                              .host = host};
#ifdef NSL_HAVE_SNS
    cb.stream_result = stream_result;
#endif
    IHS_Init();
    sl_remote_connection *c = sl_remote_connection_create(&config, &cb, &l);
    if (!c) {
        IHS_Quit();
        return 1;
    }
    sl_remote *protocol = sl_remote_connection_protocol(c);
    if (l.profile) {
        sl_remote_peer peers[SL_REMOTE_PEERS];
        size_t count = 0;
        for (int i = 0; i < l.store.registry.count; ++i) {
            sl_host *h = &l.store.registry.hosts[i];
            if (!h->paired || !h->client_id || !h->account)
                continue;
            peers[count] = (sl_remote_peer){.client_id = h->client_id, .steam_id = h->account};
            memcpy(peers[count++].secret, h->has_secret ? h->secret : l.store.secret, 32);
        }
        sl_remote_watch(protocol, peers, count);
        memset(peers, 0, sizeof(peers));
    }
    uint64_t deadline = now_ms() + (pairing ? 1800000 : idle ? 90000 : 60000);
    bool started = false, success = false;
    uint64_t connected_at = 0;
    uint64_t sns_connected_at = 0;
    bool desktop_success = false;
    bool sdr_success = false, fault_success = false, injected = false;
    unsigned fault_generation = 0;
    uint64_t fault_at = 0, recovered_at = 0;
    unsigned observed_e2e = 0, recovery_generation = 0;
    uint64_t e2e_received_at = 0;
    bool reported_e2e = false;
    unsigned observed_frames = 0, recovery_frames = 0;
    bool ihs_was_connected = false;
    uint64_t pause_at = 0, resume_at = 0;
    unsigned resume_frames = 0;
    uint64_t video_received_at = 0, snapshot_at = 0;
    unsigned terminal_stage = 0;
    uint64_t terminal_at = 0;
    while (!l.failed && now_ms() < deadline) {
        sl_remote_connection_update(c, now_ms());
        if (l.ready && !connected_at)
            connected_at = now_ms();
        if (idle && connected_at && !l.ready) {
            l.failed = true;
            break;
        }
        if (l.ready && pairing && !started) {
            started = true;
            if (!sl_remote_pair(protocol))
                break;
        }
#ifdef NSL_HAVE_SNS
        if ((sns_test || desktop_stream || sdr_session) && l.ready && l.status && !started) {
            started = true;
            IHS_StreamingRequest request = {.streamingEnable = {.video = true},
                .maxResolution = {1280, 720}, .audioChannelCount = 2,
                .streamDesktop = desktop_stream};
            sl_remote_stream_options options = {.network_test = !desktop_stream, .sns = true};
            if (!sl_remote_stream_ex(protocol, l.peer_id, &request, &options))
                break;
        }
        if (l.sns) {
            sl_sns_update(l.sns, now_ms());
            sl_sns_state state = sl_sns_get_state(l.sns);
            if (state == SL_SNS_CONNECTED && !sns_connected_at) {
                sns_connected_at = now_ms();
                puts("SNS_CONNECTED=1");
                printf("SNS_MESSAGE_MTU=%d\n", sl_sns_set_mtu(l.sns, 1300));
                sl_sns_stats stats;
                sl_sns_get_stats(l.sns, &stats);
                printf("SNS_PEER_AUTHENTICATED=%d SNS_ROUTE_RELAYED=%d\n",
                    stats.authenticated, stats.relayed);
                if (relay_only && !stats.relayed)
                    l.failed = true;
                if (desktop_stream) {
                    l.session = IHS_SessionCreate(&config, &l.session_info);
                    IHS_SessionSetSessionCallbacks(l.session, &session_cb, &l);
                    IHS_SessionSetVideoCallbacks(l.session, &video_cb, &l);
                    if (!IHS_SessionSetDatagramTransport(l.session, sl_sns_datagram_transport(), l.sns) ||
                        !IHS_SessionConnect(l.session))
                        l.failed = true;
                }
                if (sdr_session && !sl_sns_start_relay_probe(l.sns))
                    l.failed = true;
                fflush(stdout);
            }
            bool ihs_connected=atomic_load(&l.session_connected);
            if (ihs_connected) ihs_was_connected=true;
            if (desktop_stream && ihs_was_connected && !ihs_connected) {
                puts("IHS_DISCONNECTED=1");
                l.failed=true;
                break;
            }
            unsigned frames = atomic_load(&l.video_frames);
            if (frames != observed_frames) {
                observed_frames = frames;
                video_received_at = now_ms();
            }
            if (pause_test && ihs_connected && frames>=30 && !pause_at) {
                IHS_SessionSetPaused(l.session,true); pause_at=now_ms();
                puts("IHS_PAUSE_REQUESTED=1"); fflush(stdout);
            }
            if (pause_at && !resume_at && now_ms()-pause_at>=2000) {
                IHS_SessionSetPaused(l.session,false); resume_at=now_ms(); resume_frames=frames;
                puts("IHS_RESUME_REQUESTED=1"); fflush(stdout);
            }
            if (fault_test && sns_connected_at && now_ms()-sns_connected_at >= (warm_fault ? 15000u : 3000u) &&
                (!desktop_stream || (atomic_load(&l.session_connected) && frames >= 30))) {
                unsigned fault[5] = {};
                if (!injected && sl_sns_test_relay_loss(l.sns, 1, fault)) {
                    injected = true; fault_at = now_ms(); fault_generation = fault[0];
                    printf("SDR_PRIMARY_LOSS_INJECTED=1 generation=%u\n", fault_generation);
                    fflush(stdout);
                } else if (injected && sl_sns_test_relay_loss(l.sns, -1, fault)) {
                    if (fault[0] != fault_generation && fault[3] && fault[4] && fault[1]+fault[2]) {
                        if (!recovered_at || recovery_generation != fault[0]) {
                            recovery_generation = fault[0];
                            recovered_at = now_ms();
                            observed_e2e = fault[3];
                            e2e_received_at = recovered_at;
                            recovery_frames = frames;
                        } else if (observed_e2e != fault[3]) {
                            observed_e2e = fault[3];
                            e2e_received_at = now_ms();
                        }
                        if (!reported_e2e) {
                            reported_e2e = true;
                            printf("SDR_BACKUP_E2E_OBSERVED=1 milliseconds=%llu\n",
                                (unsigned long long)(recovered_at-fault_at));
                            fflush(stdout);
                        }
                        /* A single reply can precede another stall. Require
                         * a fresh reply at the end of the five-second hold. */
                        fault_success = now_ms()-recovered_at >= 5000 &&
                            now_ms()-e2e_received_at <= 1000 &&
                            (!desktop_stream || (frames-recovery_frames >= 30 &&
                                now_ms()-video_received_at <= 1000));
                        if (fault_success) {
                            printf("SDR_BACKUP_RECOVERED=1 post_fault_e2e=1 held_ms=%llu fresh_e2e_ms=%llu dropped_tx=%u dropped_rx=%u\n",
                                (unsigned long long)(now_ms()-recovered_at),
                                (unsigned long long)(now_ms()-e2e_received_at), fault[1], fault[2]);
                            if (desktop_stream)
                                printf("SDR_MEDIA_RECOVERED=1 encoded_frames_after_switch=%u fresh_frame_ms=%llu\n",
                                    frames-recovery_frames, (unsigned long long)(now_ms()-video_received_at));
                            fflush(stdout);
                        }
                    } else {
                        recovered_at = 0;
                        observed_e2e = 0;
                        e2e_received_at = 0;
                    }
                }
                if (injected && now_ms()-fault_at > 30000 && !fault_success) {
                    printf("SDR_RECOVERY_TIMEOUT=1 generation=%u dropped_tx=%u dropped_rx=%u e2e_observations=%u different_pop=%u\n",
                        fault[0], fault[1], fault[2], fault[3], fault[4]);
                    l.failed = true;
                }
            }
            if (injected && now_ms()-snapshot_at >= 1000) {
                snapshot_at=now_ms();
                sl_sdr_loss_snapshot s;
                if (sl_sns_loss_snapshot(l.sns,&s)) {
                    printf("SDR_LOSS_SAMPLE time=%u gen=%u pop=%u backup=%u drop=%u/%u root=%u session=%u recv_age=%u/%u request_age=%u pending=%u front=%u/%u\n",
                        s.elapsed,s.generation,s.primary_pop,s.backup_pop,s.dropped_tx,s.dropped_rx,
                        s.root_failures,s.session_failures,s.root_received_age,s.session_received_age,
                        s.root_request_age,s.root_pending,s.front_samples,s.front_oldest_age);
                    printf("SDR_LOSS_FEEDBACK time=%u backup_fail=%u/%u backup_age=%u old_fail=%u old_age=%u e2e=%u/%u revisions=%u/%u/%u forward_ack=%u\n",
                        s.elapsed,s.backup_root_failures,s.backup_session_failures,s.backup_received_age,
                        s.previous_root_failures,s.previous_received_age,s.e2e_count,s.e2e_received_age,
                        s.local_revision,s.peer_revision,s.pending_revision_ack,s.forward_ack);
                    printf("SDR_LOSS_ROUTING time=%u target=%u/%u peer_first=%u/%u e2e_request_age=%u pending=%u failures=%u\n",
                        s.elapsed,s.target_pop,s.target_revision,s.peer_first_local,s.peer_first_remote,
                        s.e2e_request_age,s.e2e_pending,s.e2e_failures);
                    fflush(stdout);
                }
            }
            if (sdr_session) {
                unsigned stats[5];
                sl_sns_relay_probe_stats(l.sns, stats);
                sdr_success = stats[3] > 0;
            }
            if (terminal_test && sns_connected_at && state == SL_SNS_CONNECTED &&
                now_ms()-sns_connected_at >= 1000 && now_ms()-terminal_at >= 200 && terminal_stage < 4) {
                int packet_case = terminal_stage < 3 ? 3+terminal_stage : terminal_test;
                if (!sl_sns_test_terminal(l.sns, packet_case)) l.failed = true;
                ++terminal_stage; terminal_at = now_ms();
                printf("SDR_TERMINAL_FIXTURE_CASE=%d ok=%d\n", packet_case, !l.failed);
                fflush(stdout);
            }
            if (state == SL_SNS_FAILED || state == SL_SNS_CLOSED) {
                if (terminal_test && terminal_stage == 4 &&
                    sl_sns_end_reason(l.sns) == (terminal_test == 1 ? 1042 : 5010)) {
                    printf("SDR_TERMINAL_EXPECTED=1 reason=%d invalid_cases_ignored=3\n", sl_sns_end_reason(l.sns));
                    success = !l.failed;
                    break;
                }
                printf("SNS_TERMINAL_STATE=%d reason=%d\n", state, sl_sns_end_reason(l.sns));
                l.failed = true;
                break;
            }
        }
        desktop_success = atomic_load(&l.session_connected) && atomic_load(&l.video_frames) >= 30 &&
            (!pause_test || (resume_at && atomic_load(&l.video_frames)-resume_frames>=30));
        if (pause_test && desktop_success)
            printf("IHS_PAUSE_RESUME_OK=1 fresh_frames=%u\n",atomic_load(&l.video_frames)-resume_frames);
#endif
        success = pairing  ? l.paired && l.status
                  : status ? l.status
                  : terminal_test ? false
                  : fault_test ? fault_success && !l.failed
                  : sns_test ? sns_connected_at && now_ms() - sns_connected_at >= 5000
                  : desktop_stream ? desktop_success
                  : sdr_session ? sdr_success
                  : idle   ? connected_at && now_ms() - connected_at >= 65000
                           : l.ready;
        if (success)
            break;
        usleep(10000);
    }
#ifdef NSL_HAVE_SNS
    if (l.session) {
        printf("IHS_CONNECTED=%d VIDEO_FRAMES=%u\n", atomic_load(&l.session_connected),
            atomic_load(&l.video_frames));
        IHS_SessionInterrupt(l.session);
        IHS_SessionThreadedJoin(l.session);
        IHS_SessionDestroy(l.session);
    }
    if (l.sns) {
        sl_sns_stats stats;
        sl_sns_get_stats(l.sns, &stats);
        printf("SNS_TERMINAL_SOURCE=%d detail=%d\n", stats.terminal_source, stats.terminal_detail);
        printf("SNS_DATAGRAMS_SENT=%llu RECEIVED=%llu\n",
            (unsigned long long)stats.datagrams_sent, (unsigned long long)stats.datagrams_received);
        if (sdr_session) {
            unsigned relay[5];
            sl_sns_relay_probe_stats(l.sns, relay);
            printf("SDR_PINGS_SENT=%u REPLIES=%u SESSION_REQUESTS=%u ESTABLISHED=%u REJECTED=%u\n",
                relay[0], relay[1], relay[2], relay[3], relay[4]);
        }
        if (relay_only) {
            unsigned debug[16];
            sl_sns_sdr_debug(l.sns, debug);
            printf("SDR_TRANSPORT_COUNTERS=");
            for (unsigned i = 0; i < 16; ++i)
                printf("%s%u", i ? "," : "", debug[i]);
            puts("");
        }
    }
    if (fault_test && l.sns) { unsigned final[5]; sl_sns_test_relay_loss(l.sns, 0, final); }
    sl_sns_destroy(l.sns);
#endif
    sl_remote_cancel(protocol);
    /* Flush cancellation/confirmation already queued; bounded owner-thread drain. */
    for (unsigned i = 0; i < 20; ++i) {
        sl_remote_connection_update(c, now_ms());
        usleep(10000);
    }
    sl_remote_connection_destroy(c);
    IHS_Quit();
    memset(&l.store, 0, sizeof(l.store));
    puts(success ? "PASS anonymous cloud test" : "FAIL anonymous cloud test");
    return success ? 0 : 1;
}
